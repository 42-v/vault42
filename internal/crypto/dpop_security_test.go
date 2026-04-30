package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

func TestDPoPATHMismatchRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create a DPoP proof with a specific ath value
	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.ATH = "wrong-ath-value"
		})

	// Validate with a different ath
	_, _, err = ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "correct-ath-value")
	if err == nil {
		t.Error("DPoP proof with mismatched ath should be rejected")
	}
}

func TestDPoPATHMatchAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	expectedATH := SHA256Hex("my-access-token")

	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.ATH = expectedATH
		})

	tp, _, err := ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", expectedATH)
	if err != nil {
		t.Fatalf("DPoP proof with matching ath should be accepted: %v", err)
	}
	if tp == "" {
		t.Error("thumbprint should not be empty")
	}
}

func TestDPoPATHEmptySkipsValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token")

	// When accessTokenHash is empty, ath validation should be skipped
	tp, _, err := ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "")
	if err != nil {
		t.Fatalf("DPoP proof with empty ath should not fail ath check: %v", err)
	}
	if tp == "" {
		t.Error("thumbprint should not be empty")
	}
}

func TestDPoPExpiredProofRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create a proof with IssuedAt 2 hours ago
	proof := createDPoPProof(t, key, "POST", "https://vault.example.com/auth/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.IssuedAt = vjwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
		})

	_, _, err = ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "")
	if err == nil {
		t.Error("expired DPoP proof should be rejected")
	}
}

func TestDPoPECThumbprintConsistency(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tp1, err := ComputeJWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tp2, _ := ComputeJWKThumbprint(&key.PublicKey)
	if tp1 != tp2 {
		t.Error("same EC key should produce same thumbprint")
	}
}

func TestEncodeRSAExponent(t *testing.T) {
	tests := []struct {
		name     string
		exponent int
		expected []byte
	}{
		{"e=3", 3, []byte{3}},
		{"e=17", 17, []byte{17}},
		{"e=65537", 65537, []byte{1, 0, 1}},
		{"e=255", 255, []byte{255}},
		{"e=256", 256, []byte{1, 0}},
		{"e=65535", 65535, []byte{255, 255}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeRSAExponent(tt.exponent)
			if len(result) != len(tt.expected) {
				t.Errorf("encodeRSAExponent(%d) length = %d, want %d", tt.exponent, len(result), len(tt.expected))
				return
			}
			for i, b := range result {
				if b != tt.expected[i] {
					t.Errorf("encodeRSAExponent(%d)[%d] = %d, want %d", tt.exponent, i, b, tt.expected[i])
				}
			}
		})
	}
}

func TestJWKSExponentMatchesBigInt(t *testing.T) {
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Our encoding
	ourEncoding := base64.RawURLEncoding.EncodeToString(encodeRSAExponent(key.E))

	// Standard big.Int encoding (for comparison)
	bigIntEncoding := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	if ourEncoding != bigIntEncoding {
		t.Errorf("encodeRSAExponent result %q should match big.Int.Bytes() %q for standard exponent", ourEncoding, bigIntEncoding)
	}
}
