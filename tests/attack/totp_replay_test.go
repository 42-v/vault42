package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestTOTPCodeDeterministic verifies that TOTP codes are deterministic
// for the same secret and time window.
func TestTOTPCodeDeterministic(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()

	now := time.Now()
	code1, _ := vaultcrypto.GenerateTOTPCode(secret, now)
	code2, _ := vaultcrypto.GenerateTOTPCode(secret, now)

	if code1 != code2 {
		t.Fatal("TOTP codes should be deterministic for same time")
	}
}

// TestTOTPWrongCode verifies that wrong codes are rejected.
func TestTOTPWrongCode(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()

	wrongCodes := []string{"000000", "999999", "12345", "1234567", "", "abcdef"}

	for _, code := range wrongCodes {
		t.Run("code="+code, func(t *testing.T) {
			step, err := vaultcrypto.ValidateTOTPCode(secret, code, time.Now())
			if err == nil && step >= 0 {
				// Check if it's actually the correct code by coincidence
				correctCode, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())
				if code == correctCode {
					t.Skip("Randomly generated correct code")
				}
				t.Fatalf("Wrong code %q was accepted", code)
			}
		})
	}
}

// TestTOTPBruteForce simulates trying all 6-digit codes.
// This is a sampling test — we verify that random codes don't validate.
func TestTOTPBruteForce(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	// Try 100 random codes (not exhaustive, but validates rejection logic)
	accepted := 0
	for i := 0; i < 100; i++ {
		code := vaultcrypto.SHA256Hex(string(rune(i)))[:6] // pseudo-random 6 chars
		step, err := vaultcrypto.ValidateTOTPCode(secret, code, now)
		if err == nil && step >= 0 {
			accepted++
		}
	}

	// At most 3 codes should be valid (current + +-1 skew)
	if accepted > 3 {
		t.Fatalf("Too many codes accepted: %d/100", accepted)
	}
}
