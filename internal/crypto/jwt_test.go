package crypto

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	testIssuer   = "https://vault.example.com"
	testAudience = "test-app"
)

func setupTestKeys(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := RandomUUID()
	return key, kid
}

func validClaims() VaultClaims {
	now := time.Now()
	return VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  vjwt.ClaimStrings{testAudience},
			Subject:   "user-123",
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "jti-abc-123",
		},
		Roles:       []string{"user"},
		Scopes:      []string{"read", "write"},
		ClientID:    "frontend",
		Fingerprint: "abc123fingerprint",
	}
}

func keyFunc(key *rsa.PrivateKey) vjwt.Keyfunc {
	return func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
}

func TestSignAndParseRoundTrip(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()

	tokenStr, err := SignToken(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", parsed.Subject)
	}
	if parsed.ClientID != "frontend" {
		t.Errorf("client_id = %q, want frontend", parsed.ClientID)
	}
	if len(parsed.Roles) != 1 || parsed.Roles[0] != "user" {
		t.Errorf("roles = %v, want [user]", parsed.Roles)
	}
}

func TestAlgNone(t *testing.T) {
	key, _ := setupTestKeys(t)
	variants := []string{"none", "None", "NONE", "nOnE", "noNe"}
	for _, alg := range variants {
		t.Run(alg, func(t *testing.T) {
			// Craft a token with alg:none
			claims := validClaims()
			tokenStr, _ := vjwt.UnsignedToken(map[string]any{
				"alg": alg, "typ": "JWT", "kid": "some-kid",
			}, claims)

			_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Errorf("alg:%s should be rejected", alg)
			}
		})
	}
}

func TestAlgHS256Confusion(t *testing.T) {
	key, _ := setupTestKeys(t)
	// Attack: sign with HS256 using the RSA public key as the HMAC secret
	pubKeyBytes := key.N.Bytes()

	tokenStr, err := vjwt.SignTokenCustom(
		map[string]any{"alg": "HS256", "typ": "JWT", "kid": "test-kid"},
		validClaims(),
		func(signingString string) ([]byte, error) {
			mac := hmac.New(sha256.New, pubKeyBytes)
			mac.Write([]byte(signingString))
			return mac.Sum(nil), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("HS256 confusion attack should be rejected")
	}
}

func TestOversizedJWT(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	// Stuff extra data to exceed 8KB
	claims.Scopes = make([]string, 1000)
	for i := range claims.Scopes {
		claims.Scopes[i] = fmt.Sprintf("scope-%d-with-extra-padding-to-make-it-big-%d", i, i*999)
	}
	tokenStr, _ := SignToken(claims, key, kid)
	if len(tokenStr) <= MaxJWTSize {
		t.Skip("token not large enough to test")
	}

	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("oversized JWT should be rejected")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error should mention size: %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	claims.ExpiresAt = vjwt.NewNumericDate(time.Now().Add(-1 * time.Hour))

	tokenStr, _ := SignToken(claims, key, kid)
	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("expired token should be rejected")
	}
}

func TestFutureNBF(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	claims.NotBefore = vjwt.NewNumericDate(time.Now().Add(1 * time.Hour))

	tokenStr, _ := SignToken(claims, key, kid)
	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("token with future nbf should be rejected")
	}
}

func TestWrongIssuer(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	claims.Issuer = "https://evil.example.com"

	tokenStr, _ := SignToken(claims, key, kid)
	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("wrong issuer should be rejected")
	}
}

func TestWrongAudience(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	claims.Audience = vjwt.ClaimStrings{"wrong-audience"}

	tokenStr, _ := SignToken(claims, key, kid)
	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("wrong audience should be rejected")
	}
}

func TestMissingKID(t *testing.T) {
	key, _ := setupTestKeys(t)
	// Sign normally but without kid
	tokenStr, _ := vjwt.SignRS256WithHeader(
		map[string]any{"alg": "RS256", "typ": "JWT"},
		validClaims(), key,
	)

	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Error("missing kid should be rejected")
	}
}

func TestKIDPathTraversal(t *testing.T) {
	key, _ := setupTestKeys(t)
	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\windows\\system32",
		"/etc/shadow",
		"key; DROP TABLE users;--",
		"key\x00.pem",
		"../../../../proc/self/environ",
	}

	for _, kid := range payloads {
		t.Run(kid, func(t *testing.T) {
			tokenStr, _ := vjwt.SignRS256WithHeader(
				map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid},
				validClaims(), key,
			)

			_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Errorf("kid %q should be rejected", kid)
			}
		})
	}
}

func TestDangerousHeaders(t *testing.T) {
	key, _ := setupTestKeys(t)
	headers := []string{"jku", "x5u", "x5c", "jwk"}

	for _, h := range headers {
		t.Run(h, func(t *testing.T) {
			hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "valid-kid"}
			hdr[h] = "https://evil.example.com/keys"
			tokenStr, _ := vjwt.SignRS256WithHeader(hdr, validClaims(), key)

			_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Errorf("header %q should be rejected", h)
			}
		})
	}
}

func TestSignTokenRemovesDangerousHeaders(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	tokenStr, err := SignToken(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}

	// Parse unverified to check headers
	token, err := vjwt.ParseUnverified(tokenStr, &VaultClaims{})
	if err != nil {
		t.Fatal(err)
	}

	for _, h := range []string{"jku", "x5u", "x5c", "jwk"} {
		if _, exists := token.Header[h]; exists {
			t.Errorf("SignToken should remove %q header", h)
		}
	}
}

func TestSerializeJWKS(t *testing.T) {
	key, _ := GenerateRSAKeyPair()
	kid := "test-key-1"

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	jwks := SerializeJWKS(keys)

	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS should have 1 key, got %d", len(jwks.Keys))
	}

	jwk := jwks.Keys[0]
	if jwk.KTY != "RSA" {
		t.Errorf("kty = %q, want RSA", jwk.KTY)
	}
	if jwk.ALG != "RS256" {
		t.Errorf("alg = %q, want RS256", jwk.ALG)
	}
	if jwk.KID != kid {
		t.Errorf("kid = %q, want %q", jwk.KID, kid)
	}

	// Verify N and E decode to valid values
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.Cmp(key.N) != 0 {
		t.Error("JWKS N does not match original key")
	}
}

func TestSerializeJWKSJSON(t *testing.T) {
	key, _ := GenerateRSAKeyPair()
	keys := map[string]*rsa.PublicKey{"k1": &key.PublicKey}

	data, err := SerializeJWKSJSON(keys)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"keys"`) {
		t.Error("JSON should contain keys array")
	}
}

func TestIsValidKID(t *testing.T) {
	tests := []struct {
		kid  string
		want bool
	}{
		{"abc-123-def", true},
		{"ABCDEF0123456789", true},
		{"a1b2c3d4-e5f6-7890-abcd-ef1234567890", true},
		{"", false},
		{"../etc/passwd", false},
		{"key;DROP TABLE", false},
		{"key\x00", false},
		{strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		if got := isValidKID(tt.kid); got != tt.want {
			t.Errorf("isValidKID(%q) = %v, want %v", tt.kid, got, tt.want)
		}
	}
}

func TestLoadSigningKeyPEM_RoundTrip(t *testing.T) {
	// Generate a key pair
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	// Marshal to PEM
	pemData, err := MarshalSigningKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalSigningKeyPEM: %v", err)
	}

	// Load from PEM
	loaded, kid, err := LoadSigningKeyPEM(pemData)
	if err != nil {
		t.Fatalf("LoadSigningKeyPEM: %v", err)
	}

	// Keys must match
	if key.N.Cmp(loaded.N) != 0 {
		t.Error("loaded key has different N")
	}
	if key.D.Cmp(loaded.D) != 0 {
		t.Error("loaded key has different D")
	}

	// kid must be valid and deterministic
	if !isValidKID(kid) {
		t.Errorf("kid %q does not pass isValidKID", kid)
	}
	_, kid2, _ := LoadSigningKeyPEM(pemData)
	if kid != kid2 {
		t.Errorf("kid not deterministic: %q vs %q", kid, kid2)
	}

	// Must be usable for signing
	claims := validClaims()
	tokenStr, err := SignToken(claims, loaded, kid)
	if err != nil {
		t.Fatalf("SignToken with loaded key: %v", err)
	}
	if tokenStr == "" {
		t.Error("SignToken returned empty string")
	}
}

func TestLoadSigningKeyPEM_InvalidPEM(t *testing.T) {
	_, _, err := LoadSigningKeyPEM([]byte("not a PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}
