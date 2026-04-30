package attack

import (
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_RFC7519_StringNumericClaims verifies behavior when exp is a JSON string containing a number.
// Go's json.Number accepts both JSON numbers and JSON strings containing numbers,
// so "exp":"1700000000" is actually parsed successfully (lenient behavior).
// This test verifies the parser does not panic and handles it consistently.
func TestJWT_RFC7519_StringNumericClaims(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	// exp as string instead of number — Go's json.Number is lenient and accepts this
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":"` +
		intToString(now.Add(time.Hour).Unix()) + `","iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	// json.Number accepts quoted numeric strings, so this may parse successfully
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		// Rejection is also acceptable — stricter parsers may reject string exp
		t.Logf("String exp rejected: %v (acceptable)", err)
	}

	// Now test with a truly non-numeric string — this should always fail
	claimsJSON = []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":"not-a-number","iat":` +
		intToString(now.Unix()) + `}`)
	tokenStr = signRawPayload(t, headerJSON, claimsJSON, key)

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with non-numeric string exp should be rejected")
	}
}

// TestJWT_RFC7519_ArrayAudienceDedup verifies handling of duplicate audience entries.
func TestJWT_RFC7519_ArrayAudienceDedup(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"a", "a", "b"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	// Parse with audience "b" — should match even with duplicates
	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "b")
	if err != nil {
		t.Fatalf("Token with aud=[a,a,b] should match audience 'b': %v", err)
	}

	// Verify all entries are preserved (no dedup)
	aud := claims.GetAudience()
	if len(aud) != 3 {
		t.Fatalf("Expected 3 audience entries, got %d: %v", len(aud), aud)
	}
}

// TestJWT_RFC7519_MissingIss verifies that a token with empty issuer fails validation.
func TestJWT_RFC7519_MissingIss(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "", // empty issuer
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with empty iss should fail when issuer 'test' is expected")
	}
}

// TestJWT_RFC7519_MissingExp verifies that a token with no exp fails when exp is required.
func TestJWT_RFC7519_MissingExp(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:  "user-123",
			Issuer:   "test",
			Audience: vjwt.ClaimStrings{"test"},
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			// No ExpiresAt
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with no exp should fail when exp is required (WithExpirationRequired)")
	}
}
