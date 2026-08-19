package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// FuzzParseJWKHeader is the DPoP jwk-embedding parser: crit is handled
// next door, this one is curve handling, kty switching, and the private-
// member refusal.
func FuzzParseJWKHeader(f *testing.F) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	byteLen := (ec.Curve.Params().BitSize + 7) / 8
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(ec.X.Bytes()):], ec.X.Bytes())
	copy(yPadded[byteLen-len(ec.Y.Bytes()):], ec.Y.Bytes())
	validEC, _ := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(xPadded),
		"y": base64.RawURLEncoding.EncodeToString(yPadded),
	})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	validRSA, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	})

	f.Add(validEC)
	f.Add(validRSA)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"!!","y":"!!"}`))
	f.Add([]byte(`{"kty":"oct","k":"c2VjcmV0"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"cHJpdmF0ZQ"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AA","e":"AQAB","p":"cA","q":"cQ"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AA"}`))
	f.Add([]byte(`{"kty":123}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var asMap map[string]any
		if err := json.Unmarshal(raw, &asMap); err != nil {
			_, pErr := parseJWKHeader(string(raw))
			if pErr == nil {
				t.Fatal("parseJWKHeader accepted a non-object")
			}
			return
		}

		// Private members must be refused before any key is built.
		for _, member := range dpopPrivateJWKMembers {
			if _, ok := asMap[member]; ok {
				if _, err := parseJWKHeader(asMap); err == nil {
					t.Fatalf("jwk carrying private member %q was accepted", member)
				}
				return
			}
		}

		key, err := parseJWKHeader(asMap)
		if err != nil {
			return
		}
		switch k := key.(type) {
		case *rsa.PublicKey:
			if k.N.BitLen() < 2048 || k.N.BitLen() > 4096 {
				t.Fatalf("accepted an RSA modulus of %d bits", k.N.BitLen())
			}
		case *ecdsa.PublicKey:
			if k.Curve != elliptic.P256() {
				t.Fatalf("accepted a non-P-256 curve %s", k.Curve.Params().Name)
			}
			if _, ecdhErr := k.ECDH(); ecdhErr != nil {
				t.Fatalf("accepted an EC point that is not on the curve: %v", ecdhErr)
			}
		default:
			t.Fatalf("accepted an unsupported key type %T", key)
		}
		if _, thumbErr := ComputeJWKThumbprint(key); thumbErr != nil {
			t.Fatalf("accepted a key whose thumbprint cannot be computed: %v", thumbErr)
		}
	})
}

// FuzzRejectDPoPJOSEHeaders is the crit / kid gate that runs before the jwk
// is even read. A header that names either must be refused; a header that
// names neither must pass this function (later checks still apply).
func FuzzRejectDPoPJOSEHeaders(f *testing.F) {
	f.Add([]byte(`{"alg":"ES256","typ":"dpop+jwt"}`))
	f.Add([]byte(`{"alg":"ES256","typ":"dpop+jwt","crit":["b64"]}`))
	f.Add([]byte(`{"alg":"ES256","typ":"dpop+jwt","crit":[]}`))
	f.Add([]byte(`{"alg":"ES256","typ":"dpop+jwt","kid":"vault-1"}`))
	f.Add([]byte(`{"crit":"not-an-array"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var header map[string]any
		if err := json.Unmarshal(raw, &header); err != nil {
			return
		}
		err := rejectDPoPJOSEHeaders(header)
		_, hasKid := header["kid"]
		_, hasCrit := header["crit"]
		if hasKid || hasCrit {
			if err == nil {
				t.Fatalf("header with kid=%v crit=%v was accepted", hasKid, hasCrit)
			}
			if hasCrit && !strings.Contains(err.Error(), "crit") && !hasKid {
				t.Fatalf("crit rejection did not mention crit: %v", err)
			}
			if hasKid && !hasCrit && !strings.Contains(err.Error(), "kid") {
				t.Fatalf("kid rejection did not mention kid: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("a header with neither kid nor crit was rejected: %v", err)
		}
	})
}
