package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestExpiredTokens verifies that expired tokens at various ages are rejected.
func TestExpiredTokens(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	expiryOffsets := []struct {
		name   string
		offset time.Duration
	}{
		{"1_second_ago", -1 * time.Second},
		{"1_hour_ago", -1 * time.Hour},
		{"1_day_ago", -24 * time.Hour},
		{"100_years_ago", -100 * 365 * 24 * time.Hour},
	}

	for _, tc := range expiryOffsets {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "test",
					Audience:  vjwt.ClaimStrings{"test"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(tc.offset)),
					IssuedAt:  vjwt.NewNumericDate(time.Now().Add(tc.offset - time.Hour)),
				},
			}, key, kid)

			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Expired token (%s) was NOT rejected", tc.name)
			}
		})
	}
}
