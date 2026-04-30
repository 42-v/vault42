package attack

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestAlgNone verifies that alg:none tokens are rejected in all case variants.
func TestAlgNone(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Create a valid token first to get the payload structure
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:  []string{"user"},
		Scopes: []string{"read"},
	}

	// Build alg:none tokens manually
	noneVariants := []string{"none", "None", "NONE", "nOnE", "noNe"}

	for _, algVariant := range noneVariants {
		t.Run("alg="+algVariant, func(t *testing.T) {
			header := map[string]string{"alg": algVariant, "typ": "JWT", "kid": kid}
			headerJSON, _ := json.Marshal(header)
			claimsJSON, _ := json.Marshal(claims)

			token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
				base64.RawURLEncoding.EncodeToString(claimsJSON) + "."

			_, err := vaultcrypto.ParseAndValidate(token, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("alg=%s token was NOT rejected", algVariant)
			}
			if !strings.Contains(err.Error(), "algorithm") && !strings.Contains(err.Error(), "invalid") {
				t.Logf("Error: %v (acceptable rejection)", err)
			}
		})
	}
}
