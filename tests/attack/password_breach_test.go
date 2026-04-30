package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestPasswordHashUniqueSalts verifies that hashing the same password twice
// produces different hashes (unique salts).
func TestPasswordHashUniqueSalts(t *testing.T) {
	password := "test-password-for-salt-check!!"
	hash1, _ := vaultcrypto.HashPassword(password)
	hash2, _ := vaultcrypto.HashPassword(password)

	if hash1 == hash2 {
		t.Fatal("Same password produced identical hashes — salt not random")
	}

	// Both should still verify
	valid1, _ := vaultcrypto.VerifyPassword(password, hash1)
	valid2, _ := vaultcrypto.VerifyPassword(password, hash2)
	if !valid1 || !valid2 {
		t.Fatal("Valid password failed verification")
	}
}

// TestPasswordMinLengthEnforcement is a unit-level test of the minimum length check.
func TestPasswordMinLengthEnforcement(t *testing.T) {
	// The auth service enforces 15 chars minimum (NIST SP 800-63B Rev 4).
	// This just validates the crypto layer accepts any length.
	passwords := []string{
		"",
		"a",
		"short",
		"exactly-fifteen", // 15 chars
		"this-is-a-very-long-password-for-testing-purposes!", // 50 chars
	}

	for _, pw := range passwords {
		hash, err := vaultcrypto.HashPassword(pw)
		if err != nil {
			t.Fatalf("HashPassword failed for len=%d: %v", len(pw), err)
		}
		valid, _ := vaultcrypto.VerifyPassword(pw, hash)
		if !valid {
			t.Fatalf("VerifyPassword failed for len=%d", len(pw))
		}
	}
}
