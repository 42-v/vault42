package attack

import (
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_AudienceEmptyArray verifies that aud:[] fails audience validation.
func TestJWT_AudienceEmptyArray(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":[],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with empty aud array should be rejected (no audience match)")
	}
}

// TestJWT_AudienceNull verifies that aud:null fails audience validation.
func TestJWT_AudienceNull(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":null,"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with null aud should be rejected (no audience match)")
	}
}

// TestJWT_AudienceDuplicates verifies that aud:["test","test"] still matches.
func TestJWT_AudienceDuplicates(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test", "test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with duplicate aud entries should still match: %v", err)
	}
}

// TestJWT_AudienceSingleString verifies that aud:"test" (string, not array) works.
func TestJWT_AudienceSingleString(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	// aud as a single string, not an array
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":"test","exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with single string aud should parse (ClaimStrings handles both): %v", err)
	}
}

// TestJWT_AudienceEmptyStringInArray verifies that aud:["","test"] matches on "test".
func TestJWT_AudienceEmptyStringInArray(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"", "test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with empty string + valid aud should match on 'test': %v", err)
	}
}

// TestJWT_AudienceWrongType verifies that aud as integer is rejected.
func TestJWT_AudienceWrongType(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	// aud as integer
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":12345,"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with integer aud should be rejected")
	}
}
