package attack

import (
	"fmt"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestTOTPWindow_CurrentCodeAccepted verifies that the current TOTP code is accepted.
func TestTOTPWindow_CurrentCodeAccepted(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	code, _ := vaultcrypto.GenerateTOTPCode(secret, now)
	step, _ := vaultcrypto.ValidateTOTPCode(secret, code, now)
	if step < 0 {
		t.Fatal("Current TOTP code should be accepted")
	}
}

// TestTOTPWindow_PreviousPeriodAccepted verifies that a code from the previous
// 30-second period is accepted (within +-1 skew).
func TestTOTPWindow_PreviousPeriodAccepted(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	// Use a time well within a period boundary to avoid flakiness
	now := time.Unix(1700000100, 0) // well within a period

	prevCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(-30*time.Second))
	step, _ := vaultcrypto.ValidateTOTPCode(secret, prevCode, now)
	if step < 0 {
		t.Fatal("Code from previous period (within +-1 skew) should be accepted")
	}
}

// TestTOTPWindow_NextPeriodAccepted verifies that a code from the next
// 30-second period is accepted (within +-1 skew).
func TestTOTPWindow_NextPeriodAccepted(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Unix(1700000100, 0)

	nextCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(30*time.Second))
	step, _ := vaultcrypto.ValidateTOTPCode(secret, nextCode, now)
	if step < 0 {
		t.Fatal("Code from next period (within +-1 skew) should be accepted")
	}
}

// TestTOTPWindow_FarPastRejected verifies that codes from far in the past are rejected.
func TestTOTPWindow_FarPastRejected(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Unix(1700000100, 0)

	offsets := []time.Duration{
		-2 * time.Minute,
		-5 * time.Minute,
		-10 * time.Minute,
		-1 * time.Hour,
		-24 * time.Hour,
	}

	for _, offset := range offsets {
		t.Run(fmt.Sprintf("offset=%v", offset), func(t *testing.T) {
			oldCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(offset))
			step, _ := vaultcrypto.ValidateTOTPCode(secret, oldCode, now)
			if step >= 0 {
				t.Fatalf("Code from %v ago should be rejected (outside +-1 window)", -offset)
			}
		})
	}
}

// TestTOTPWindow_FarFutureRejected verifies that codes from far in the future are rejected.
func TestTOTPWindow_FarFutureRejected(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Unix(1700000100, 0)

	offsets := []time.Duration{
		2 * time.Minute,
		5 * time.Minute,
		10 * time.Minute,
		1 * time.Hour,
		24 * time.Hour,
	}

	for _, offset := range offsets {
		t.Run(fmt.Sprintf("offset=+%v", offset), func(t *testing.T) {
			futureCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(offset))
			step, _ := vaultcrypto.ValidateTOTPCode(secret, futureCode, now)
			if step >= 0 {
				t.Fatalf("Code from %v in the future should be rejected", offset)
			}
		})
	}
}

// TestTOTPWindow_ExactBoundary tests codes at exactly the +-1 boundary.
func TestTOTPWindow_ExactBoundary(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	// Use a fixed time that's at the start of a period to make boundary tests deterministic
	// Period = 30 seconds, so counter = unix / 30
	// At time 1700000070, counter = 56666669
	now := time.Unix(1700000070, 0)

	// Code for counter-2 (two periods back) should be rejected
	twoPeriodsPast := now.Add(-60 * time.Second)
	oldCode, _ := vaultcrypto.GenerateTOTPCode(secret, twoPeriodsPast)
	step, _ := vaultcrypto.ValidateTOTPCode(secret, oldCode, now)
	if step >= 0 {
		t.Fatal("Code from 2 periods ago should be rejected (outside +-1 skew)")
	}

	// Code for counter+2 (two periods ahead) should be rejected
	twoPeriodsFuture := now.Add(60 * time.Second)
	futureCode, _ := vaultcrypto.GenerateTOTPCode(secret, twoPeriodsFuture)
	step, _ = vaultcrypto.ValidateTOTPCode(secret, futureCode, now)
	if step >= 0 {
		t.Fatal("Code from 2 periods ahead should be rejected (outside +-1 skew)")
	}
}

// TestTOTPWindow_DifferentSecretsSameTime verifies that two different secrets
// produce different codes at the same time.
func TestTOTPWindow_DifferentSecretsSameTime(t *testing.T) {
	secret1, _ := vaultcrypto.GenerateTOTPSecret()
	secret2, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	code1, _ := vaultcrypto.GenerateTOTPCode(secret1, now)
	code2, _ := vaultcrypto.GenerateTOTPCode(secret2, now)

	// While there's a small probability they match by coincidence (1/1000000),
	// we just verify that wrong-secret validation fails
	step, _ := vaultcrypto.ValidateTOTPCode(secret2, code1, now)
	if step >= 0 && code1 != code2 {
		t.Fatal("Code from secret1 should not validate against secret2")
	}
}
