package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestTimingAttackArgon2 verifies that Argon2id verify takes similar time
// for valid vs invalid passwords (constant-time behavior).
func TestTimingAttackArgon2(t *testing.T) {
	password := "correct-horse-battery-staple-long"
	hash, _ := vaultcrypto.HashPassword(password)

	const iterations = 15

	// Measure time for valid password
	var validTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword(password, hash)
		validTotal += time.Since(start)
	}
	validAvg := validTotal / iterations

	// Measure time for invalid password
	var invalidTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		vaultcrypto.VerifyPassword("wrong-password-entirely", hash)
		invalidTotal += time.Since(start)
	}
	invalidAvg := invalidTotal / iterations

	// They should be within 50% of each other (generous tolerance for CI)
	ratio := float64(validAvg) / float64(invalidAvg)
	if ratio < 0.5 || ratio > 2.0 {
		t.Fatalf("Timing difference too large: valid=%v invalid=%v ratio=%.2f", validAvg, invalidAvg, ratio)
	}

	t.Logf("Valid avg: %v, Invalid avg: %v, ratio: %.2f", validAvg, invalidAvg, ratio)
}

// TestTimingAttackMalformedHash verifies that verifying against a malformed hash
// still takes a reasonable amount of time (doesn't return instantly).
func TestTimingAttackMalformedHash(t *testing.T) {
	start := time.Now()
	vaultcrypto.VerifyPassword("test", "not-a-valid-hash")
	elapsed := time.Since(start)

	// Compare against a real hash to get a baseline, then use relative threshold.
	// Absolute thresholds are fragile across different hardware.
	realHash, _ := vaultcrypto.HashPassword("baseline-password-here!")
	realStart := time.Now()
	vaultcrypto.VerifyPassword("test", realHash)
	realElapsed := time.Since(realStart)

	// Malformed hash should take at least 1% of real hash time (dummy computation)
	threshold := realElapsed / 100
	if elapsed < threshold {
		t.Fatalf("Malformed hash returned too quickly (%v) vs real hash (%v) — timing leak", elapsed, realElapsed)
	}
}
