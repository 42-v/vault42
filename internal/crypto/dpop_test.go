package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

func createDPoPProof(t *testing.T, key interface{}, method, uri string, opts ...func(map[string]any, *DPoPClaims)) string {
	t.Helper()
	claims := &DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "dpop-jti-123",
		},
		HTM: method,
		HTU: uri,
	}

	var alg string
	var jwkHeader map[string]any

	switch k := key.(type) {
	case *rsa.PrivateKey:
		alg = "RS256"
		jwkHeader = map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
		}
	case *ecdsa.PrivateKey:
		alg = "ES256"
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)
		jwkHeader = map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(xPadded),
			"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		}
	}

	header := map[string]any{
		"alg": alg,
		"typ": "dpop+jwt",
		"jwk": jwkHeader,
	}

	for _, opt := range opts {
		opt(header, claims)
	}

	var tokenStr string
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		tokenStr, err = vjwt.SignRS256WithHeader(header, claims, k)
	case *ecdsa.PrivateKey:
		tokenStr, err = vjwt.SignTokenCustom(header, claims, func(signingString string) ([]byte, error) {
			hash := sha256.Sum256([]byte(signingString))
			return ecdsa.SignASN1(crand.Reader, k, hash[:])
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return tokenStr
}

func TestDPoPValidProofRSA(t *testing.T) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")
	thumbprint, _, err := ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint == "" {
		t.Error("thumbprint should not be empty")
	}
}

func TestDPoPValidProofEC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	proof := createDPoPProof(t, key, "GET", "https://vault.example.com/user/profile")
	thumbprint, _, err := ValidateDPoPProof(proof, "GET", "https://vault.example.com/user/profile", "")
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint == "" {
		t.Error("thumbprint should not be empty")
	}
}

func TestDPoPMethodMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(crand.Reader, 2048)
	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")

	_, _, err := ValidateDPoPProof(proof, "GET", "https://vault.example.com/auth/token", "")
	if err == nil {
		t.Error("HTTP method mismatch should be rejected")
	}
}

func TestDPoPURIMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(crand.Reader, 2048)
	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")

	_, _, err := ValidateDPoPProof(proof, "POST", "https://evil.example.com/auth/token", "")
	if err == nil {
		t.Error("URI mismatch should be rejected (forwarding attack)")
	}
}

func TestDPoPWrongKeyProof(t *testing.T) {
	key1, _ := rsa.GenerateKey(crand.Reader, 2048)
	key2, _ := rsa.GenerateKey(crand.Reader, 2048)

	proof := createDPoPProof(t, key1, "POST", "https://vault.example.com/auth/token")
	thumbprint, _, err := ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "")
	if err != nil {
		t.Fatal(err)
	}

	// Thumbprint should match key1, not key2
	tp2, _ := ComputeJWKThumbprint(&key2.PublicKey)
	if thumbprint == tp2 {
		t.Error("thumbprint should not match different key")
	}
}

func TestDPoPThumbprintConsistency(t *testing.T) {
	key, _ := rsa.GenerateKey(crand.Reader, 2048)

	tp1, err := ComputeJWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tp2, _ := ComputeJWKThumbprint(&key.PublicKey)
	if tp1 != tp2 {
		t.Error("same key should produce same thumbprint")
	}

	key2, _ := rsa.GenerateKey(crand.Reader, 2048)
	tp3, _ := ComputeJWKThumbprint(&key2.PublicKey)
	if tp1 == tp3 {
		t.Error("different keys should produce different thumbprints")
	}
}
