package fuzz

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// FuzzArgon2Verify feeds random inputs to Argon2id verify.
func FuzzArgon2Verify(f *testing.F) {
	// Create a valid hash for the seed corpus
	hash, _ := vaultcrypto.HashPassword("seed-password")

	f.Add("test-password", hash)
	f.Add("", "")
	f.Add("password", "not-a-hash")
	f.Add("\x00\x01\x02", "$argon2id$v=19$m=46080,t=1,p=1$salt$hash")

	f.Fuzz(func(t *testing.T, password, hash string) {
		// Should never panic
		vaultcrypto.VerifyPassword(password, hash)
	})
}
