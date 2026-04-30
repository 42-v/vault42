package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignRS256_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now()
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-42",
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  NewNumericDate(now),
		ID:        "jti-123",
	}

	tokenStr, err := SignRS256(claims, key, "kid-1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !tok.Valid {
		t.Error("token not valid")
	}
	if parsed.Issuer != "vault" {
		t.Errorf("issuer = %q, want vault", parsed.Issuer)
	}
	if parsed.Subject != "user-42" {
		t.Errorf("subject = %q, want user-42", parsed.Subject)
	}
	if parsed.ID != "jti-123" {
		t.Errorf("ID = %q, want jti-123", parsed.ID)
	}
}

func TestSignRS256_KIDInHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := &RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}

	tokenStr, err := SignRS256(claims, key, "my-kid")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Parse to inspect header
	parts := strings.SplitN(tokenStr, ".", 3)
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)

	if header["kid"] != "my-kid" {
		t.Errorf("kid = %q, want my-kid", header["kid"])
	}
}

func TestSignRS256_HeaderContents(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := &RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}

	tokenStr, err := SignRS256(claims, key, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)

	if header["alg"] != "RS256" {
		t.Errorf("alg = %q, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ = %q, want JWT", header["typ"])
	}
}

func TestEncodeDecodeSegment(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello world")},
		{"binary", []byte{0x00, 0xff, 0x80, 0x7f}},
		{"json", []byte(`{"key":"value"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeSegment(tt.data)
			decoded, err := decodeSegment(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(decoded) != string(tt.data) {
				t.Errorf("round-trip mismatch: got %v, want %v", decoded, tt.data)
			}
		})
	}
}

func TestSignRS256_NilKey(t *testing.T) {
	claims := &RegisteredClaims{}
	_, err := SignRS256(claims, nil, "kid")
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestSignRS256_ClaimsIntegrity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		Audience:  ClaimStrings{"a", "b"},
		ExpiresAt: NewNumericDate(now.Add(time.Hour)),
		NotBefore: NewNumericDate(now),
		IssuedAt:  NewNumericDate(now),
		ID:        "jti-abc",
	}

	tokenStr, err := SignRS256(claims, key, "k")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Decode payload to verify all fields
	parts := strings.SplitN(tokenStr, ".", 3)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var decoded RegisteredClaims
	json.Unmarshal(payloadBytes, &decoded)

	if decoded.Issuer != "vault" {
		t.Errorf("Issuer mismatch")
	}
	if len(decoded.Audience) != 2 {
		t.Errorf("Audience len = %d, want 2", len(decoded.Audience))
	}
}

func TestToken_ThreeSegments(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := &RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}

	tokenStr, _ := SignRS256(claims, key, "k")
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Errorf("token has %d segments, want 3", len(parts))
	}
}
