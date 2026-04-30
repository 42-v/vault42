package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestMissingClaims verifies that tokens with missing required claims are rejected.
func TestMissingClaims(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tests := []struct {
		name   string
		claims vaultcrypto.VaultClaims
	}{
		{
			"missing_issuer",
			vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Audience:  vjwt.ClaimStrings{"test"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			},
		},
		{
			"missing_audience",
			vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "test",
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			},
		},
		{
			"missing_expiry",
			vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:  "user-123",
					Issuer:   "test",
					Audience: vjwt.ClaimStrings{"test"},
					IssuedAt: vjwt.NewNumericDate(time.Now()),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, _ := vaultcrypto.SignToken(tc.claims, key, kid)
			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Token with %s was NOT rejected", tc.name)
			}
		})
	}
}
