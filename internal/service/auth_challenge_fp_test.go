package service

import (
	"context"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// M1: the 2fa_challenge fingerprint claim must be enforced on redemption.
func TestChallengeFingerprintMatches(t *testing.T) {
	svc, _ := newMockAuthService(t)
	ctx := context.Background()

	fpA := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{IP: "1.1.1.1", UserAgent: "A"})
	fpB := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{IP: "2.2.2.2", UserAgent: "B"})

	if !svc.ChallengeFingerprintMatches(ctx, "u1", fpA, fpA, "1.1.1.1", "A") {
		t.Error("matching fingerprints must pass")
	}
	if svc.ChallengeFingerprintMatches(ctx, "u1", fpA, fpB, "2.2.2.2", "B") {
		t.Error("mismatched fingerprints must be rejected (device/network switch)")
	}
	// Legacy challenge token with no embedded fingerprint must not be bricked.
	if !svc.ChallengeFingerprintMatches(ctx, "u1", "", fpB, "2.2.2.2", "B") {
		t.Error("empty challenge fingerprint must be treated as a match")
	}
}
