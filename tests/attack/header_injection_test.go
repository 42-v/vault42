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

// TestHeaderInjection_JKU verifies that tokens with a jku header are rejected.
func TestHeaderInjection_JKU(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"jku": "https://evil.com/.well-known/jwks.json",
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with jku header should be rejected")
	}
	if !strings.Contains(err.Error(), "jku") {
		t.Logf("Error: %v (acceptable rejection)", err)
	}
}

// TestHeaderInjection_X5U verifies that tokens with an x5u header are rejected.
func TestHeaderInjection_X5U(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"x5u": "https://evil.com/cert.pem",
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with x5u header should be rejected")
	}
}

// TestHeaderInjection_X5C verifies that tokens with an x5c header are rejected.
func TestHeaderInjection_X5C(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"x5c": []string{"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIx"},
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with x5c header should be rejected")
	}
}

// TestHeaderInjection_JWK verifies that tokens with an embedded jwk header are rejected.
func TestHeaderInjection_JWK(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"jwk": map[string]string{
			"kty": "RSA",
			"n":   "attacker-controlled-key",
			"e":   "AQAB",
		},
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with jwk header should be rejected")
	}
}

// TestHeaderInjection_SignTokenStrips verifies that SignToken removes dangerous headers.
func TestHeaderInjection_SignTokenStrips(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	// Decode the header to verify no dangerous headers are present
	parts := strings.SplitN(tokenStr, ".", 3)
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)

	dangerous := []string{"jku", "x5u", "x5c", "jwk"}
	for _, h := range dangerous {
		if _, exists := header[h]; exists {
			t.Fatalf("SignToken should strip %q header, but it was present", h)
		}
	}

	// Verify expected headers are present
	if header["alg"] != "RS256" {
		t.Fatalf("Expected alg=RS256, got %v", header["alg"])
	}
	if header["kid"] != kid {
		t.Fatalf("Expected kid=%s, got %v", kid, header["kid"])
	}
}

// TestHeaderInjection_AllDangerousHeaders tests all dangerous header types in a table-driven test.
func TestHeaderInjection_AllDangerousHeaders(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	dangerousHeaders := []struct {
		name  string
		key   string
		value interface{}
	}{
		{"jku with HTTP URL", "jku", "http://evil.com/jwks"},
		{"jku with HTTPS URL", "jku", "https://evil.com/jwks.json"},
		{"x5u with URL", "x5u", "https://evil.com/cert.pem"},
		{"x5c with cert chain", "x5c", []string{"base64-cert-data"}},
		{"jwk with RSA key", "jwk", map[string]string{"kty": "RSA", "n": "abc", "e": "AQAB"}},
	}

	for _, tt := range dangerousHeaders {
		t.Run(tt.name, func(t *testing.T) {
			header := map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": kid,
			}
			header[tt.key] = tt.value

			tokenStr, err := vjwt.SignRS256WithHeader(header, &vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "test",
					Audience:  vjwt.ClaimStrings{"test"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key)
			if err != nil {
				return // Can't sign — acceptable
			}

			_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
			if err == nil {
				t.Fatalf("Token with %s header should be rejected", tt.key)
			}
		})
	}
}
