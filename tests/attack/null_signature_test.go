package attack

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestNullSignature tests tokens with empty, truncated, or missing signatures.
func TestNullSignature(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Build a valid-looking header and payload
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	claims := vjwt.MapClaims{
		"sub": "user-123",
		"iss": "test",
		"aud": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	tests := []struct {
		name  string
		token string
	}{
		{"empty_signature", payload + "."},
		{"missing_signature_part", payload},
		{"truncated_signature", payload + ".AQID"},
		{"null_bytes_signature", payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 256))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vaultcrypto.ParseAndValidate(tc.token, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Token with %s was NOT rejected", tc.name)
			}
		})
	}
}
