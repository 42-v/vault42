package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
)

// L2: parseJWKHeader must reject an RSA modulus larger than 4096 bits (a
// self-signed DPoP proof carries an attacker-chosen modulus → DoS vector).
func TestParseJWKHeader_RSAUpperBound(t *testing.T) {
	mkJWK := func(nBytes []byte) map[string]any {
		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
		}
	}

	// 1025 bytes of 0xFF ≈ 8200-bit modulus → over the 4096-bit cap.
	oversized := bytes.Repeat([]byte{0xFF}, 1025)
	if _, err := parseJWKHeader(mkJWK(oversized)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized RSA key should be rejected with 'too large', got %v", err)
	}

	// A legitimate 2048-bit key must still parse.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := parseJWKHeader(mkJWK(key.N.Bytes())); err != nil {
		t.Fatalf("valid 2048-bit RSA key should parse, got %v", err)
	}
}
