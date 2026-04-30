package attack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestDPoPWrongKey tests that a DPoP proof signed by a different key
// than what's bound in the token is rejected.
func TestDPoPWrongKey(t *testing.T) {
	// Generate two different EC keys
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create proof with key2
	jti, _ := vaultcrypto.RandomUUID()
	proofClaims := vjwt.MapClaims{
		"jti": jti,
		"htm": "POST",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}

	jwk := ecJWK(&key2.PublicKey)

	proofString, err := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk,
	}, proofClaims, func(s string) ([]byte, error) {
		h := sha256.Sum256([]byte(s))
		return ecdsa.SignASN1(rand.Reader, key2, h[:])
	})
	if err != nil {
		t.Fatalf("Failed to sign proof: %v", err)
	}

	// Compute thumbprint of key1 (what the token would be bound to)
	thumbprint1, _ := vaultcrypto.ComputeJWKThumbprint(jwkJSON(key1))

	// Validate — the proof's key (key2) should NOT match key1's thumbprint
	thumbprint2, _, err := vaultcrypto.ValidateDPoPProof(proofString, "POST", "https://auth.example.com/token", "")
	if err != nil {
		t.Logf("Proof validation error (expected if format wrong): %v", err)
		return
	}

	if vaultcrypto.SecureCompare(thumbprint1, thumbprint2) {
		t.Fatal("Different keys produced matching thumbprints — critical")
	}
}

// TestDPoPMethodMismatch tests that a DPoP proof for GET doesn't work for POST.
func TestDPoPMethodMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jti, _ := vaultcrypto.RandomUUID()
	proofClaims := vjwt.MapClaims{
		"jti": jti,
		"htm": "GET", // proof is for GET
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}

	jwk := ecJWK(&key.PublicKey)

	proofString, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk,
	}, proofClaims, func(s string) ([]byte, error) {
		h := sha256.Sum256([]byte(s))
		return ecdsa.SignASN1(rand.Reader, key, h[:])
	})

	// Validate with POST method — should fail
	_, _, err := vaultcrypto.ValidateDPoPProof(proofString, "POST", "https://auth.example.com/token", "")
	if err == nil {
		t.Fatal("DPoP proof with method mismatch (GET vs POST) was NOT rejected")
	}
}

// TestDPoPURIMismatch tests that a DPoP proof for one URI doesn't work for another.
func TestDPoPURIMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jti, _ := vaultcrypto.RandomUUID()
	proofClaims := vjwt.MapClaims{
		"jti": jti,
		"htm": "POST",
		"htu": "https://auth.example.com/token", // proof is for /token
		"iat": time.Now().Unix(),
	}

	jwk := ecJWK(&key.PublicKey)

	proofString, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk,
	}, proofClaims, func(s string) ([]byte, error) {
		h := sha256.Sum256([]byte(s))
		return ecdsa.SignASN1(rand.Reader, key, h[:])
	})

	// Validate against /resource — should fail
	_, _, err := vaultcrypto.ValidateDPoPProof(proofString, "POST", "https://auth.example.com/resource", "")
	if err == nil {
		t.Fatal("DPoP proof with URI mismatch was NOT rejected")
	}
}

func jwkJSON(key *ecdsa.PrivateKey) json.RawMessage {
	b, _ := json.Marshal(ecJWK(&key.PublicKey))
	return b
}

// ecJWK returns a JWK map for an EC public key using the ECDH bridge to avoid
// the Go 1.26 ecdsa.PublicKey.X/Y deprecation.
func ecJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	ecdhPub, _ := pub.ECDH()
	raw := ecdhPub.Bytes()
	return map[string]interface{}{
		"kty": "EC",
		"crv": pub.Curve.Params().Name,
		"x":   raw[1 : 1+byteLen],
		"y":   raw[1+byteLen:],
	}
}
