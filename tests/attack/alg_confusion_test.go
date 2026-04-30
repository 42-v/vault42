package attack

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestAlgConfusion tests RS256→HS256 algorithm confusion attack.
// Attack: sign token with HS256 using the RSA public key as the HMAC secret.
func TestAlgConfusion(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Get public key bytes (what an attacker would use as HMAC key)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKeyBytes})

	// Build HS256 token signed with the public key
	header := map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid}
	claims := vjwt.MapClaims{
		"sub": "admin",
		"iss": "test",
		"aud": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	payload := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, pubKeyPEM)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	confusedToken := payload + "." + sig

	_, err := vaultcrypto.ParseAndValidate(confusedToken, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("HS256 confusion attack was NOT rejected — critical vulnerability")
	}
}
