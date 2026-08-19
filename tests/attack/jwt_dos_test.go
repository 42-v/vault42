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

// TestJWT_DeeplyNestedJSON verifies that deeply nested JSON in claims does not panic.
func TestJWT_DeeplyNestedJSON(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	// Build deeply nested JSON in a custom claim
	nested := `"x"`
	for i := 0; i < 100; i++ {
		nested = `{"a":` + nested + `}`
	}

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) +
		`,"nested":` + nested + `}`)

	// Only attempt if the token stays under MaxJWTSize
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	if len(headerB64)+len(claimsB64)+300 > vaultcrypto.MaxJWTSize {
		// Too large — will be caught by size check, which is fine
		tokenStr := headerB64 + "." + claimsB64 + ".fakesig"
		_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
		if err == nil {
			t.Fatal("Oversized deeply nested token should be rejected")
		}
		return
	}

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	// Should not panic — either parse or error
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	_ = err // any outcome is fine as long as no panic
}

// TestJWT_LargeClaimValue verifies that a single claim exceeding MaxJWTSize is rejected.
func TestJWT_LargeClaimValue(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// 10KB subject string — token will exceed 8KB MaxJWTSize
	bigSubject := strings.Repeat("A", 10000)
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   bigSubject,
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with 10KB subject should exceed MaxJWTSize and be rejected")
	}
}

// TestJWT_LargeArray verifies that a claim with a large array is handled safely.
func TestJWT_LargeArray(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Build an array with many elements (will likely exceed MaxJWTSize)
	elements := make([]string, 1000)
	for i := range elements {
		elements[i] = `"item"`
	}
	arrayJSON := "[" + strings.Join(elements, ",") + "]"

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) +
		`,"scopes":` + arrayJSON + `}`)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	estimatedSize := len(headerB64) + len(claimsB64) + 300

	if estimatedSize > vaultcrypto.MaxJWTSize {
		// Expected: will be rejected by size check
		tokenStr := headerB64 + "." + claimsB64 + ".fakesig"
		_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
		if err == nil {
			t.Fatal("Oversized token with large array should be rejected")
		}
		return
	}

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)
	// Should not panic
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	_ = err
}

// TestJWT_OversizedToken verifies that a token just over 8KB is rejected.
func TestJWT_OversizedToken(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Build a token that is exactly over 8KB
	// Start with a normal token and pad the subject
	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})
	now := time.Now()

	// Estimate overhead and create a subject that pushes over the limit
	// Header b64 ~80 chars, sig ~344 chars, claims overhead ~100 chars, dots = 2
	// We need total > 8192 bytes
	padSize := 6000 // base64 expands ~4/3, so 6000 chars → ~8000 base64 chars for claims
	claimsJSON := []byte(`{"sub":"` + strings.Repeat("X", padSize) +
		`","iss":"test","aud":["test"],"exp":` + intToString(now.Add(time.Hour).Unix()) +
		`,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	// The rejection assertion below only means anything if the token really is
	// oversized. Skipping instead of failing turns a padding constant that no
	// longer clears MaxJWTSize into a green run of a test that checked nothing.
	if len(tokenStr) <= vaultcrypto.MaxJWTSize {
		t.Fatalf("this test built a %d-byte token, which does not exceed MaxJWTSize (%d), so the "+
			"oversized-token rejection below would never be exercised. Raise padSize (currently "+
			"%d) past the limit.", len(tokenStr), vaultcrypto.MaxJWTSize, padSize)
	}

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatalf("Token of %d bytes (>8KB) should be rejected", len(tokenStr))
	}
}

// TestJWT_ManyHeaders verifies that 100 custom header fields don't cause a panic.
func TestJWT_ManyHeaders(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	for i := 0; i < 100; i++ {
		header["custom_"+intToString(int64(i))] = "value"
	}

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
		t.Fatalf("SignRS256WithHeader failed: %v", err)
	}

	// Should not panic — may be rejected by MaxJWTSize or parse fine
	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	_ = err // any outcome is acceptable as long as no panic
}
