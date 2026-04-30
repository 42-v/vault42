package fuzz

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzParseToken feeds random input to the JWT parser to find panics.
func FuzzParseToken(f *testing.F) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Seed corpus
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid")
	f.Add("")
	f.Add("...")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.")
	f.Add("not-a-jwt-at-all")
	f.Add("\x00\x01\x02\x03")

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic, regardless of input
		vaultcrypto.ParseAndValidate(input, keyFunc, "test", "test")
	})
}
