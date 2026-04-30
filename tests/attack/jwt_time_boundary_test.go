package attack

import (
	"encoding/json"
	"math"
	"strconv"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_FloatingPointExp verifies that floating-point exp values are handled (truncated to seconds).
func TestJWT_FloatingPointExp(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	iat := now.Unix()
	// exp as float with fractional seconds — far future to ensure not expired
	exp := float64(now.Add(time.Hour).Unix()) + 0.999
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		strconv.FormatFloat(exp, 'f', 3, 64) + `,"iat":` + intToString(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with float exp should parse (truncated to seconds): %v", err)
	}
}

// TestJWT_NegativeTimestamp verifies that negative exp results in an expired token.
func TestJWT_NegativeTimestamp(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	// exp as negative number — time before UNIX epoch (1969)
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":-100,"iat":-200}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with negative exp (1969) should be rejected as expired")
	}
}

// TestJWT_ZeroTimestamp verifies that exp=0 (UNIX epoch) results in an expired token.
func TestJWT_ZeroTimestamp(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	iat := now.Unix()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":0,"iat":` +
		intToString(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with exp=0 (epoch 1970) should be rejected as expired")
	}
}

// TestJWT_MaxInt64Timestamp verifies that exp=MaxInt32 does not panic and is valid.
func TestJWT_MaxInt64Timestamp(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	iat := now.Unix()
	// Use MaxInt32 (2147483647 = Jan 2038) which is representable as float64
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(math.MaxInt32) + `,"iat":` + intToString(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	// Should not panic
	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with large exp should be valid (far future): %v", err)
	}
}

// TestJWT_ExactExpBoundary verifies that exp=now means the token is expired.
// Per validate.go: `!now.Before(exp.Time)` — when exp equals now, the token is expired.
func TestJWT_ExactExpBoundary(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Sign a token with exp set to 1 second ago (to ensure it's expired by the time we verify)
	now := time.Now().Truncate(time.Second)
	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  vjwt.NewNumericDate(now.Add(-2 * time.Second)),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with exp in the past should be rejected as expired")
	}
}

// TestJWT_NBFInFuture_ExpInPast verifies both nbf and exp violations are caught.
func TestJWT_NBFInFuture_ExpInPast(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	iat := now.Add(-2 * time.Hour).Unix()
	exp := now.Add(-time.Hour).Unix() // expired 1 hour ago
	nbf := now.Add(time.Hour).Unix()  // not valid for another hour

	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(exp) + `,"nbf":` + intToString(nbf) + `,"iat":` + intToString(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with exp in past AND nbf in future should be rejected")
	}
}
