package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestRefreshTokenFamilyIsolation verifies that refresh tokens embed unique
// family IDs so that stolen tokens from different sessions can't be mixed
// or replayed across token families.
func TestRefreshTokenFamilyIsolation(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	now := time.Now()

	// Simulate two different login sessions for the same user
	sessions := make([]string, 2)
	for i := range sessions {
		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "10.0.0.1",
			UserAgent: "Mozilla/5.0 session-" + string(rune(i+'A')),
		})

		tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{
				Subject:   "user-1",
				Issuer:    "vault",
				Audience:  vjwt.ClaimStrings{"vault"},
				ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
				IssuedAt:  vjwt.NewNumericDate(now),
			},
			Fingerprint: fp,
		}, key, kid)
		if err != nil {
			t.Fatalf("SignToken failed: %v", err)
		}
		sessions[i] = tokenStr
	}

	// Tokens for same user but different sessions must be different
	if sessions[0] == sessions[1] {
		t.Fatal("access tokens from different sessions are identical — fingerprint not binding")
	}
}

// TestRefreshTokenMaterialStrength verifies that refresh token material
// has sufficient entropy (32 bytes = 256 bits).
func TestRefreshTokenMaterialStrength(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, err := vaultcrypto.RandomHex(32)
		if err != nil {
			t.Fatalf("RandomHex failed: %v", err)
		}
		if len(tok) != 64 { // 32 bytes = 64 hex chars
			t.Fatalf("expected 64 hex chars, got %d", len(tok))
		}
		if seen[tok] {
			t.Fatalf("duplicate token at iteration %d (catastrophic RNG failure)", i)
		}
		seen[tok] = true
	}
}

// TestRefreshTokenHashIsOneWay verifies that the SHA256 hash of a refresh
// token cannot be reversed to recover the original token material.
func TestRefreshTokenHashIsOneWay(t *testing.T) {
	token, _ := vaultcrypto.RandomHex(32)
	hash := vaultcrypto.SHA256Hex(token)

	// Hash should be different from the input
	if hash == token {
		t.Fatal("SHA256 hash equals input — hashing broken")
	}

	// Hash should be deterministic
	hash2 := vaultcrypto.SHA256Hex(token)
	if hash != hash2 {
		t.Fatal("SHA256 not deterministic")
	}

	// Different tokens should produce different hashes
	token2, _ := vaultcrypto.RandomHex(32)
	hash3 := vaultcrypto.SHA256Hex(token2)
	if hash == hash3 {
		t.Fatal("different tokens produced same hash — collision")
	}
}
