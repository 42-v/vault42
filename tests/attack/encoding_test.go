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

// TestEncoding_Base64PaddingVariations verifies that base64 padding variations
// in JWTs are handled correctly.
func TestEncoding_Base64PaddingVariations(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Create a valid token
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	// Modify the token by adding standard base64 padding (= chars)
	// JWT uses raw URL encoding (no padding)
	parts := strings.SplitN(tokenStr, ".", 3)

	paddedVariants := []struct {
		name   string
		modify func(parts []string) string
	}{
		{
			"header with padding",
			func(p []string) string { return p[0] + "=" + "." + p[1] + "." + p[2] },
		},
		{
			"payload with padding",
			func(p []string) string { return p[0] + "." + p[1] + "==" + "." + p[2] },
		},
		{
			"signature with padding",
			func(p []string) string { return p[0] + "." + p[1] + "." + p[2] + "==" },
		},
	}

	for _, tt := range paddedVariants {
		t.Run(tt.name, func(t *testing.T) {
			modified := tt.modify(parts)
			_, err := vaultcrypto.ParseAndValidate(modified, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Modified token with %s should be rejected", tt.name)
			}
		})
	}
}

// TestEncoding_NullBytesInJWTSegments verifies that null bytes in JWT segments
// are handled safely.
func TestEncoding_NullBytesInJWTSegments(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Create a hand-crafted token with null bytes in the payload
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, _ := json.Marshal(header)

	claims := map[string]interface{}{
		"sub": "user\x00admin",
		"iss": "test",
		"aud": []string{"test"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// This won't be a validly signed token, so it should be rejected
	fakeToken := headerB64 + "." + claimsB64 + ".fakesignature"

	_, err := vaultcrypto.ParseAndValidate(fakeToken, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with null bytes in subject should be rejected")
	}
}

// TestEncoding_DoubleEncodedPayload verifies that double-encoded base64 payloads
// are rejected.
func TestEncoding_DoubleEncodedPayload(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Create a valid token
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	parts := strings.SplitN(tokenStr, ".", 3)

	// Double-encode the payload
	doubleEncoded := base64.RawURLEncoding.EncodeToString([]byte(parts[1]))
	modifiedToken := parts[0] + "." + doubleEncoded + "." + parts[2]

	_, err := vaultcrypto.ParseAndValidate(modifiedToken, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Double-encoded payload should be rejected")
	}
}

// TestEncoding_EmptyJWTSegments verifies that empty JWT segments are rejected.
func TestEncoding_EmptyJWTSegments(t *testing.T) {
	keyFunc := func(t *vjwt.Token) (any, error) { return nil, nil }

	malformed := []struct {
		name  string
		token string
	}{
		{"empty header", "." + "eyJ0ZXN0IjoiMSJ9" + ".signature"},
		{"empty payload", "eyJhbGciOiJSUzI1NiJ9" + "." + ".signature"},
		{"empty signature", "eyJhbGciOiJSUzI1NiJ9" + "." + "eyJ0ZXN0IjoiMSJ9" + "."},
		{"all empty", ".."},
		{"no dots", "justabunchoftext"},
		{"single dot", "a.b"},
		{"four segments", "a.b.c.d"},
	}

	for _, tt := range malformed {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vaultcrypto.ParseAndValidate(tt.token, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Malformed token (%s) should be rejected", tt.name)
			}
		})
	}
}

// TestEncoding_URLEncodingVsStandardBase64 verifies that standard base64
// (with + and /) is properly handled vs URL-safe base64 (with - and _).
func TestEncoding_URLEncodingVsStandardBase64(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	// Replace URL-safe chars with standard base64 chars
	modified := strings.ReplaceAll(tokenStr, "-", "+")
	modified = strings.ReplaceAll(modified, "_", "/")

	if modified != tokenStr {
		// Only test if there were actual substitutions
		_, err := vaultcrypto.ParseAndValidate(modified, keyFunc, "test", "test")
		if err == nil {
			t.Fatal("Token with standard base64 encoding (instead of URL-safe) should be rejected")
		}
	}
}

// TestEncoding_TruncatedToken verifies that truncated tokens are rejected.
func TestEncoding_TruncatedToken(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	// Truncate at various points
	truncations := []struct {
		name string
		at   int
	}{
		{"first 10 chars", 10},
		{"half length", len(tokenStr) / 2},
		{"minus 1 char", len(tokenStr) - 1},
		{"minus 10 chars", len(tokenStr) - 10},
	}

	for _, tt := range truncations {
		t.Run(tt.name, func(t *testing.T) {
			if tt.at <= 0 || tt.at >= len(tokenStr) {
				t.Skip("Invalid truncation point")
			}
			truncated := tokenStr[:tt.at]
			_, err := vaultcrypto.ParseAndValidate(truncated, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Truncated token (at %d) should be rejected", tt.at)
			}
		})
	}
}
