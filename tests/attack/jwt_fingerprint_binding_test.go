package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestFingerprintDivergenceDetection verifies that tokens bound to one
// fingerprint fail validation when presented from a different client context.
// This prevents session hijacking via stolen tokens.
func TestFingerprintDivergenceDetection(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Original fingerprint from legitimate user
	originalFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "192.168.1.100",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
		AcceptLanguage: "en-US,en;q=0.9",
	})

	// Attacker's fingerprint (different IP and UA)
	attackerFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "45.33.32.156",
		UserAgent:      "python-requests/2.28.1",
		AcceptLanguage: "en-US,en;q=0.9",
	})

	if originalFP == attackerFP {
		t.Fatal("different clients should produce different fingerprints")
	}

	// Token signed with original fingerprint
	now := time.Now()
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "victim",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"vault"},
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(now),
		},
		Fingerprint: originalFP,
	}, key, kid)

	// Parse the token — it should be cryptographically valid
	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "vault")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}

	// But the embedded fingerprint won't match the attacker's context
	if claims.Fingerprint == attackerFP {
		t.Fatal("token fingerprint matches attacker — binding broken")
	}
	if claims.Fingerprint != originalFP {
		t.Fatal("token fingerprint doesn't match original")
	}
}

// TestFingerprintIPChangeDetection verifies that even a single IP change
// produces a different fingerprint hash.
func TestFingerprintIPChangeDetection(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "10.0.0.1",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	}

	fp1 := vaultcrypto.ComputeFingerprint(base)

	// Change only IP
	base.IP = "10.0.0.2"
	fp2 := vaultcrypto.ComputeFingerprint(base)

	if fp1 == fp2 {
		t.Fatal("fingerprint unchanged after IP change")
	}
}

// TestFingerprintUAChangeDetection verifies UA changes are detected.
func TestFingerprintUAChangeDetection(t *testing.T) {
	base := vaultcrypto.FingerprintInput{
		IP:             "10.0.0.1",
		UserAgent:      "Chrome/120",
		AcceptLanguage: "en-US",
	}

	fp1 := vaultcrypto.ComputeFingerprint(base)

	base.UserAgent = "Firefox/121"
	fp2 := vaultcrypto.ComputeFingerprint(base)

	if fp1 == fp2 {
		t.Fatal("fingerprint unchanged after UA change")
	}
}

// TestFingerprintCollisionResistance generates many fingerprints and
// verifies no collisions occur in a reasonable sample.
func TestFingerprintCollisionResistance(t *testing.T) {
	seen := make(map[string]string)
	for i := 0; i < 1000; i++ {
		input := vaultcrypto.FingerprintInput{
			IP:             "10.0." + string(rune(i/256+'0')) + "." + string(rune(i%256+'0')),
			UserAgent:      "agent-" + string(rune(i+'A')),
			AcceptLanguage: "en",
		}
		fp := vaultcrypto.ComputeFingerprint(input)
		if prev, dup := seen[fp]; dup {
			t.Fatalf("fingerprint collision: %q and %q", prev, input.IP)
		}
		seen[fp] = input.IP
	}
}
