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

// A proof commits to one method and one URI. Presenting it anywhere else is the
// forwarding attack the htm/htu claims exist to stop: a proof captured at one
// endpoint replayed against another, or against another host entirely.
func TestDPoPProofIsBoundToOneEndpoint(t *testing.T) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	const (
		method = "POST"
		uri    = "https://vault.example.com/auth/token"
	)
	proof := createDPoPProof(t, key, method, uri)

	tests := []struct {
		name        string
		method, uri string
	}{
		{name: "another method on the same URI", method: "GET", uri: uri},
		{name: "the same path on another host", method: method, uri: "https://evil.example.com/auth/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ValidateDPoPProof(proof, tt.method, tt.uri, ""); err == nil {
				t.Errorf("a proof for %s %s validated against %s %s", method, uri, tt.method, tt.uri)
			}
		})
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
