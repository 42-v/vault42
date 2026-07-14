package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The JWK thumbprint IS the DPoP binding: it is the value stamped into the access token
// as `cnf.jkt` and recomputed from every proof to decide whether this caller is the one
// the token was issued to. A thumbprint computed from a key the code does not really
// understand would be a binding to nothing.
//
// So every unsupported or malformed key must produce an error rather than some
// best-effort digest. A silent fallback here would let a proof carrying a key we cannot
// actually validate still produce a stable thumbprint — and sender-constraining would
// quietly become decorative.
func TestComputeJWKThumbprint_RejectsKeysItCannotBind(t *testing.T) {
	t.Run("an unsupported key type", func(t *testing.T) {
		if _, err := ComputeJWKThumbprint("not-a-key"); err == nil {
			t.Error("a thumbprint was computed for something that is not a public key")
		}
	})

	t.Run("an ECDSA key on a curve with no ECDH form", func(t *testing.T) {
		// P-224 has no crypto/ecdh representation, so the conversion must fail rather
		// than silently produce a thumbprint over an unvalidated point.
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Skipf("P-224 unavailable: %v", err)
		}
		if _, err := ComputeJWKThumbprint(&key.PublicKey); err == nil {
			t.Error("a thumbprint was computed for a curve the code cannot convert")
		}
	})

	t.Run("a supported key is accepted", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		got, err := ComputeJWKThumbprint(&key.PublicKey)
		if err != nil {
			t.Fatalf("P-256 must be supported: %v", err)
		}
		if got == "" {
			t.Error("an empty thumbprint would bind every token to every key")
		}
	})
}

// The jwk header arrives inside an attacker-supplied proof. Anything that is not a
// well-formed JWK must be refused outright — parsing it loosely is how a proof with a
// junk key ends up validating.
func TestParseJWKHeader_RejectsMalformedHeaders(t *testing.T) {
	cases := []struct {
		name string
		raw  interface{}
	}{
		{"not an object at all", "just-a-string"},
		{"an object that cannot be marshalled", map[string]interface{}{"kty": make(chan int)}},
		{"an object whose fields are the wrong types", map[string]interface{}{"kty": 42, "crv": true}},
		{"an empty object", map[string]interface{}{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseJWKHeader(tc.raw); err == nil {
				t.Error("a malformed jwk header was accepted — a proof carrying it would validate")
			}
		})
	}
}
