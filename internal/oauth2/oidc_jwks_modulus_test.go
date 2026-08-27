package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"testing"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// jwksModulusCapBits is the ceiling written out rather than read from
// vjwt.MaxRSAModulusBits.
//
// A boundary test that takes its boundary from the constant under test moves
// with that constant: lower the cap a bit and the "exactly at the cap" case
// lowers itself to match and still passes, so the pair asserts only that the
// code agrees with itself. Spelling the number here is what lets these cases
// fail. TestJWKSModulusCapIsTheSharedBound holds the literal and the constant
// together, so a deliberate change to the house rule fails one obvious test
// instead of quietly rewriting what the boundary means.
const jwksModulusCapBits = 4096

// modulusOfBits renders a base64url modulus whose big.Int is exactly bits long.
//
// No RSA key is generated. That is not a shortcut past a stronger test: nothing
// on this path treats the modulus as a modulus. rsaPublicKeyFromJWK
// base64url-decodes it, calls BitLen on the result, and range-checks that
// number; the bound under test is a bound on that number alone. A real key
// would prove the same thing about BitLen while costing seconds to minutes to
// generate, and it could not state the boundary at all -- rsa.GenerateKey
// produces the size it is asked for, so "one bit over the cap" is not a key it
// can be asked for. A value of 2^bits - 1 is exactly what the check sees.
func modulusOfBits(bits int) string {
	one := big.NewInt(1)
	n := new(big.Int).Sub(new(big.Int).Lsh(one, uint(bits)), one)
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// exponent65537 is the public exponent every entry below carries, so the
// exponent check is never what refuses a key and the modulus bound is the only
// thing under test.
func exponent65537() string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())
}

// The two JWK importers have to be reading one number. If they are not, the
// tests below still pass while a DPoP proof and an issuer's jwks_uri are held
// to different rules, which is the state this change was made to end.
func TestJWKSModulusCapIsTheSharedBound(t *testing.T) {
	if vjwt.MaxRSAModulusBits != jwksModulusCapBits {
		t.Fatalf("the shared RSA modulus ceiling is %d bits and this suite's boundary cases are "+
			"written against %d. Whichever moved, the boundary below no longer sits on the cap.",
			vjwt.MaxRSAModulusBits, jwksModulusCapBits)
	}
	if vjwt.MinRSAModulusBits != 2048 {
		t.Fatalf("the shared RSA modulus floor is %d bits, want 2048", vjwt.MinRSAModulusBits)
	}
}

// The modulus an OIDC issuer publishes at its jwks_uri is chosen by the remote
// end, and refreshJWKS installs whatever decodes as the id_token verification
// cache. rsaPublicKeyFromJWK enforced only the floor, so a key far past the
// ceiling its sibling importer in internal/crypto applies to a DPoP proof's jwk
// header was accepted and then paid for on every id_token carrying its kid.
//
// The boundary is asserted from both sides: a modulus of exactly the cap is a
// legitimate key and must still parse, and one bit more must not.
func TestRSAPublicKeyFromJWK_ModulusUpperBound(t *testing.T) {
	e := exponent65537()

	t.Run("exactly at the cap is accepted", func(t *testing.T) {
		pub, err := rsaPublicKeyFromJWK(modulusOfBits(jwksModulusCapBits), e)
		if err != nil {
			t.Fatalf("a %d-bit modulus is at the cap, not over it, and must parse: %v",
				jwksModulusCapBits, err)
		}
		if pub.N.BitLen() != jwksModulusCapBits {
			t.Fatalf("decoded modulus is %d bits, want %d", pub.N.BitLen(), jwksModulusCapBits)
		}
	})

	t.Run("one bit over the cap is refused", func(t *testing.T) {
		_, err := rsaPublicKeyFromJWK(modulusOfBits(jwksModulusCapBits+1), e)
		if err == nil {
			t.Fatalf("a %d-bit modulus is over the %d-bit cap and must be refused",
				jwksModulusCapBits+1, jwksModulusCapBits)
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("the refusal must name the size as the reason, got %v", err)
		}
	})

	t.Run("an absurd modulus is refused", func(t *testing.T) {
		if _, err := rsaPublicKeyFromJWK(modulusOfBits(65536), e); err == nil {
			t.Fatal("a 65536-bit modulus must be refused")
		}
	})
}

// An oversized key reaches the cache through refreshJWKS, so the refusal has to
// hold there too, and it has to hold the way the rest of that loop already
// behaves: the bad entry is skipped and the usable ones still load. Failing the
// whole refresh would hand an issuer a way to empty the key set by publishing
// one hostile entry alongside its real ones.
func TestRefreshJWKS_SkipsAnOversizedModulusAndKeepsTheRest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	goodN, goodE := rsaJWKParts(&key.PublicKey)

	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(
			jwkEntry{Kty: "RSA", Kid: "huge-1", N: modulusOfBits(16384), E: goodE, Use: "sig"},
			jwkEntry{Kty: "RSA", Kid: "good-1", N: goodN, E: goodE, Use: "sig"},
		))
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")

	if err := p.refreshJWKS(context.Background()); err != nil {
		t.Fatalf("one oversized entry must not fail a refresh that also carries a usable key: %v", err)
	}
	if p.cachedKey("good-1") == nil {
		t.Fatal("the usable 2048-bit key must still be cached")
	}
	if p.cachedKey("huge-1") != nil {
		t.Fatal("a 16384-bit modulus must not enter the id_token verification cache")
	}
}

// When the oversized key is the only one there is nothing to fall back to, and
// the refresh must fail rather than install an empty set. Nothing is written to
// the cache on that path, so a provider that had a working key set keeps it.
func TestRefreshJWKS_OversizedModulusAloneFailsAndLeavesTheCache(t *testing.T) {
	srv := configurableIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(
			jwkEntry{Kty: "RSA", Kid: "huge-1", N: modulusOfBits(16384), E: exponent65537(), Use: "sig"},
		))
	}, nil, false, true)
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")

	sentinel := &rsa.PublicKey{N: big.NewInt(3), E: 65537}
	p.jwks.keys = map[string]*rsa.PublicKey{"previous-1": sentinel}

	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("a JWKS whose only entry is oversized must fail the refresh")
	}
	if p.cachedKey("previous-1") != sentinel {
		t.Fatal("a failed refresh must leave the previously cached key set in place")
	}
	if p.cachedKey("huge-1") != nil {
		t.Fatal("the oversized key must not be cached")
	}
}
