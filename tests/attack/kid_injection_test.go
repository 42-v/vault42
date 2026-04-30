package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestKIDPathTraversal tests that malicious kid values are rejected.
func TestKIDPathTraversal(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	maliciousKIDs := []string{
		"../../etc/passwd",
		"../../../proc/self/environ",
		"key'; DROP TABLE keys;--",
		"key\x00.pem",
		"/etc/shadow",
		"http://evil.com/key.pem",
		"key\ninjection: true",
		"a]]]]]]]",
	}

	for _, badKID := range maliciousKIDs {
		t.Run("kid="+badKID, func(t *testing.T) {
			// Try to create a token with malicious kid
			tokenString, err := vjwt.SignRS256WithHeader(map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": badKID,
			}, &vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "test",
					Audience:  vjwt.ClaimStrings{"test"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key)
			if err != nil {
				return // Can't even sign with this kid — fine
			}

			_, err = vaultcrypto.ParseAndValidate(tokenString, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Malicious kid=%q was NOT rejected", badKID)
			}
		})
	}
}
