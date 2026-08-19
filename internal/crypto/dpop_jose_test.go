package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// TestValidateDPoPProofRejectsACritHeader closes the DPoP half of the gap
// TestCritHeaderIsRejected closed for access tokens.
//
// RFC 7515 4.1.11 makes crit a MUST-reject for any recipient that does not
// implement every extension it lists, and vault42 implements no JOSE extension
// at all. ParseAndValidate refuses it; ValidateDPoPProof did not, and its
// Keyfunc is a bare `return pubKey, nil` that performs none of the header
// checks the jwt package's own doc comment says live there.
//
// The DPoP path is the reachable one of the two. An access token's header sits
// inside a signature made with vault42's signing key, so planting a crit there
// needs the key. A DPoP proof is self-signed with a key the caller invents in
// the same request, so every byte of its header, crit included, is chosen by
// whoever sends the request. The harm is the one the access-token fix names: a
// gateway or relying party that honors crit refuses a proof vault42 called
// valid, and the two stop agreeing on what a valid proof is.
//
// The empty array is included for the same reason it is there: RFC 7515
// forbids it outright, and it is the case a "nothing is listed, so nothing is
// required" reading waves through.
func TestValidateDPoPProofRejectsACritHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	for _, tc := range []struct {
		name string
		crit any
	}{
		{"unknown extension", []string{"nonce-ext"}},
		{"several unknown extensions", []string{"a", "b"}},
		{"empty array, forbidden by the RFC", []string{}},
		{"naming a header vault42 does understand", []string{"jwk"}},
		{"not an array at all", "nonce-ext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := createDPoPProof(t, key, "POST", "https://vault.test/auth/token",
				func(header map[string]any, _ *DPoPClaims) {
					header["crit"] = tc.crit
				})

			thumbprint, jti, err := ValidateDPoPProof(proof, "POST", "https://vault.test/auth/token", "")
			if err == nil {
				t.Fatalf("a DPoP proof carrying a crit header was accepted (thumbprint %q, jti %q). "+
					"RFC 7515 4.1.11 requires refusing a crit the recipient does not implement, and "+
					"vault42 implements no JOSE extensions, so a verifier that honors crit would "+
					"refuse a proof this vault called valid.", thumbprint, jti)
			}
			if !strings.Contains(err.Error(), "crit") {
				t.Errorf("the rejection did not come from the crit check, so this test is not "+
					"measuring what it claims: %v", err)
			}
		})
	}
}

// TestValidateDPoPProofStillAcceptsAProofWithoutCrit is the negative control
// for the check above: a header rejection that fires on every proof would pass
// that test and break every DPoP client.
func TestValidateDPoPProofStillAcceptsAProofWithoutCrit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	proof := createDPoPProof(t, key, "POST", "https://vault.test/auth/token")

	thumbprint, jti, err := ValidateDPoPProof(proof, "POST", "https://vault.test/auth/token", "")
	if err != nil {
		t.Fatalf("an ordinary DPoP proof was rejected: %v", err)
	}
	if thumbprint == "" || jti == "" {
		t.Errorf("thumbprint = %q, jti = %q, want both non-empty", thumbprint, jti)
	}
}

// TestValidateDPoPProofRejectsAJWKCarryingPrivateKeyMaterial pins RFC 9449
// 4.3 step 7: the jwk JOSE Header Parameter MUST NOT contain a private key.
//
// parseJWKHeader unmarshals the jwk into a struct holding only kty, n, e, crv,
// x and y, so a d, p, q, dp, dq, qi or k member was read past in silence and
// the proof validated. The private half changes nothing about the signature
// check or the thumbprint, which is exactly why this has to be an explicit
// refusal rather than something the parser gets right by accident: a client
// that ships its own private key in the header is a client whose key is
// disclosed to everything on the path, and the answer it needs from an
// authorization server is a rejection, not a 200 that hides the leak until the
// next audit.
func TestValidateDPoPProofRejectsAJWKCarryingPrivateKeyMaterial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	proof := createDPoPProof(t, key, "GET", "https://vault.test/user/profile",
		func(header map[string]any, _ *DPoPClaims) {
			jwk, ok := header["jwk"].(map[string]any)
			if !ok {
				t.Fatalf("jwk header is %T, want a map", header["jwk"])
			}
			jwk["d"] = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		})

	thumbprint, jti, err := ValidateDPoPProof(proof, "GET", "https://vault.test/user/profile", "")
	if err == nil {
		t.Fatalf("a DPoP proof whose jwk header carried the private scalar was accepted "+
			"(thumbprint %q, jti %q). RFC 9449 4.3 step 7 requires refusing it.", thumbprint, jti)
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("the rejection did not come from the private-material check: %v", err)
	}
}

// TestParseJWKHeaderRejectsEveryPrivateMember walks the whole JWK private
// vocabulary rather than d alone. RSA splits its private half across six
// members (RFC 7518 6.3.2) and an oct key carries it in k, so a check that
// only knew about d would let an RSA jwk hand over p and q and still pass.
func TestParseJWKHeaderRejectsEveryPrivateMember(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	base := func() map[string]any {
		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}
	}

	// Sanity: the same jwk without any private member must parse, or the
	// assertions below would hold for the wrong reason.
	if _, err := parseJWKHeader(base()); err != nil {
		t.Fatalf("the public-only jwk must parse: %v", err)
	}

	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		t.Run(member, func(t *testing.T) {
			jwk := base()
			jwk[member] = "AQAB"
			if _, err := parseJWKHeader(jwk); err == nil {
				t.Errorf("a jwk carrying %q was accepted", member)
			}
		})
	}
}

// TestParseJWKHeaderRejectsACurveNoDPoPAlgorithmCanVerify replaces
// TestParseJWKHeaderValidECP384, which asserted the opposite.
//
// That test pinned as a contract a branch that cannot produce an accepted
// proof. ValidateDPoPProof allows RS256 and ES256 and nothing else. RS256
// needs an *rsa.PublicKey, and RFC 7518 3.4 assigns exactly P-256 to ES256, a
// pin VerifyES256 now enforces. So every P-384 key parseJWKHeader built died
// one call later, and the only thing the branch could still do was go live
// without review the day ES384 appeared on that allowlist. The parser now
// admits only the curve the algorithms it feeds can actually verify.
//
// P-384 is not a weak curve, and this is not a strength judgement. It is the
// rule that the key a proof carries and the algorithm its header names must
// describe the same thing, which is also what the RFC 7638 thumbprint asserts:
// the curve name is inside it, so a proof vault42 accepted under a curve
// mismatch would bind to a thumbprint no conforming relying party computes.
func TestParseJWKHeaderRejectsACurveNoDPoPAlgorithmCanVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x, y := ecCoords(&key.PublicKey)

	_, err = parseJWKHeader(map[string]any{
		"kty": "EC",
		"crv": "P-384",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	})
	if err == nil {
		t.Fatal("a P-384 jwk was accepted by the DPoP key parser, whose only caller allows " +
			"RS256 and ES256; no proof carrying this key can ever verify, so building it is a " +
			"fail-open waiting for the allowlist to widen")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("the rejection did not come from the curve check: %v", err)
	}
}

// TestParseJWKHeaderStillAcceptsP256 is the negative control for the curve
// rule: rejecting P-256 would end every WebCrypto DPoP client.
func TestParseJWKHeaderStillAcceptsP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x, y := ecCoords(&key.PublicKey)

	pub, err := parseJWKHeader(map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	})
	if err != nil {
		t.Fatalf("a P-256 jwk was rejected: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("parseJWKHeader returned %T, want *ecdsa.PublicKey", pub)
	}
	if ec.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", ec.Curve.Params().Name)
	}
}
