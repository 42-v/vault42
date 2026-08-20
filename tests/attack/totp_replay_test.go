package attack

import (
	"fmt"
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
//
// ValidateTOTPCode signals acceptance with a non-negative step and reserves its
// error return for a secret it cannot decode, so a refused code is (-1, nil)
// and both halves are asserted here. The 6-digit candidates are filtered
// against every code the +-1 skew window accepts, because "000000" is a legal
// HOTP output: roughly one run in 300000 handed this test the right answer, and
// the t.Skip that caught it reported green for a case it never checked. An
// input that cannot collide beats a guard that hides the collision.
func TestTOTPWrongCode(t *testing.T) {
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()
	accepted := acceptedTOTPCodes(t, secret, now)

	wrongCodes := []string{"12345", "1234567", "", "abcdef"}
	for _, preferred := range []int{0, 999999} {
		wrongCodes = append(wrongCodes, unacceptedTOTPCode(preferred, accepted))
	}

	for _, code := range wrongCodes {
		t.Run("code="+code, func(t *testing.T) {
			step, err := vaultcrypto.ValidateTOTPCode(secret, code, now)
			if err != nil {
				t.Fatalf("ValidateTOTPCode(%q) returned %v; a decodable secret must refuse with (-1, nil)", code, err)
			}
			if step >= 0 {
				t.Fatalf("wrong code %q was accepted at step %d", code, step)
			}
		})
	}
}

// TestTOTPBruteForce samples the 6-digit space. Every candidate is filtered
// against the three codes the window accepts, so one acceptance is a defect
// rather than a lucky guess. The sample used to be six hex characters of a
// SHA-256, so most candidates carried a letter and could not have been a TOTP
// code under any implementation.
func TestTOTPBruteForce(t *testing.T) {
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()
	accepted := acceptedTOTPCodes(t, secret, now)

	// Stride by a value coprime with 1000000 so the 100 samples spread across
	// the space instead of clustering at the low end.
	for i := 0; i < 100; i++ {
		code := unacceptedTOTPCode(i*9721, accepted)
		step, err := vaultcrypto.ValidateTOTPCode(secret, code, now)
		if err != nil {
			t.Fatalf("ValidateTOTPCode(%q) returned %v; a decodable secret must refuse with (-1, nil)", code, err)
		}
		if step >= 0 {
			t.Fatalf("code %q is none of the three the window accepts, yet validated at step %d", code, step)
		}
	}
}

// acceptedTOTPCodes returns the three codes ValidateTOTPCode accepts at at:
// the current period and the +-1 skew the validator allows.
func acceptedTOTPCodes(t *testing.T, secret string, at time.Time) map[string]bool {
	t.Helper()
	accepted := make(map[string]bool, 3)
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := vaultcrypto.GenerateTOTPCode(secret, at.Add(offset))
		if err != nil {
			t.Fatalf("GenerateTOTPCode: %v", err)
		}
		accepted[code] = true
	}
	return accepted
}

// unacceptedTOTPCode formats n as a 6-digit code, stepping past any value the
// skew window would accept so the caller gets a code that must be refused.
func unacceptedTOTPCode(n int, accepted map[string]bool) string {
	code := fmt.Sprintf("%06d", n%1000000)
	for accepted[code] {
		n++
		code = fmt.Sprintf("%06d", n%1000000)
	}
	return code
}
