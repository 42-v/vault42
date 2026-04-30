package attack

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// signRawPayload builds a JWT by signing raw header and claims JSON bytes with RS256.
func signRawPayload(t *testing.T, headerJSON, claimsJSON []byte, key *rsa.PrivateKey) string {
	t.Helper()
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingString := headerB64 + "." + claimsB64
	sig, err := vjwt.SignRS256Bytes(signingString, key)
	if err != nil {
		t.Fatalf("SignRS256Bytes failed: %v", err)
	}
	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestJWT_DuplicateClaimKeys verifies behavior when payload JSON contains duplicate keys.
// Go's encoding/json takes the last value for duplicate keys.
func TestJWT_DuplicateClaimKeys(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	// Manually build JSON with duplicate "sub" key — Go takes last value
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	iat := now.Unix()
	claimsJSON := []byte(`{"sub":"attacker","sub":"user-123","iss":"test","aud":["test"],"exp":` +
		json.Number(itoa(exp)).String() + `,"iat":` + json.Number(itoa(iat)).String() + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		// Rejection is also acceptable — the parser may reject malformed payloads
		t.Logf("Duplicate key token rejected (acceptable): %v", err)
		return
	}
	// If parsed, Go should have taken the last "sub" value
	if claims.Subject != "user-123" {
		t.Fatalf("Expected sub=user-123 (last value), got %q", claims.Subject)
	}
}

// TestJWT_WhitespacePayload verifies that payload JSON with extra whitespace parses correctly.
func TestJWT_WhitespacePayload(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	iat := now.Unix()
	// Valid JSON with extra whitespace
	claimsJSON := []byte("{\n\t\"sub\" : \"user-123\" ,\n\t\"iss\" : \"test\" ,\n\t\"aud\" : [ \"test\" ] ,\n\t\"exp\" : " +
		itoa(exp) + " ,\n\t\"iat\" : " + itoa(iat) + "\n}")

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Valid token with whitespace in payload should parse: %v", err)
	}
}

// TestJWT_UnicodeEscapes verifies handling of unicode escape sequences in claim names.
func TestJWT_UnicodeEscapes(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	iat := now.Unix()
	// Use unicode escapes for "sub", "iss", "aud" — JSON decoder should resolve these
	claimsJSON := []byte(`{"\u0073\u0075\u0062":"user-123","\u0069\u0073\u0073":"test","\u0061\u0075\u0064":["test"],"exp":` +
		itoa(exp) + `,"iat":` + itoa(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with unicode-escaped claim names should parse: %v", err)
	}
}

// TestJWT_TypeConfusion_StringExp verifies behavior when exp is a quoted string.
// Go's json.Number is lenient and accepts JSON strings that contain numeric values,
// so "exp":"<number>" may parse successfully. We test that truly non-numeric strings fail.
func TestJWT_TypeConfusion_StringExp(t *testing.T) {
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
	// exp as non-numeric string — must be rejected
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":"never","iat":` +
		itoa(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with non-numeric string exp should be rejected")
	}
}

// TestJWT_TypeConfusion_ArrayAlg verifies that alg as an array is rejected.
func TestJWT_TypeConfusion_ArrayAlg(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// alg as array instead of string
	headerJSON := []byte(`{"alg":["RS256"],"typ":"JWT","kid":"` + kid + `"}`)

	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	iat := now.Unix()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		itoa(exp) + `,"iat":` + itoa(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with array alg should be rejected")
	}
}

// TestJWT_TypeConfusion_ObjectSub verifies that sub as an object is rejected or handled safely.
func TestJWT_TypeConfusion_ObjectSub(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	iat := now.Unix()
	// sub as object instead of string
	claimsJSON := []byte(`{"sub":{"id":"user"},"iss":"test","aud":["test"],"exp":` +
		itoa(exp) + `,"iat":` + itoa(iat) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with object sub should be rejected or result in empty sub")
	}
}

// TestJWT_NullClaims verifies that tokens with all null claims are rejected.
func TestJWT_NullClaims(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	claimsJSON := []byte(`{"sub":null,"iss":null,"aud":null,"exp":null,"iat":null}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with all null claims should be rejected (missing exp, wrong iss/aud)")
	}
}

// itoa converts an int64 to a string for building raw JSON.
func itoa(n int64) string {
	return json.Number(intToString(n)).String()
}

func intToString(n int64) string {
	buf := make([]byte, 0, 20)
	if n < 0 {
		buf = append(buf, '-')
		n = -n
	}
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i := len(digits) - 1; i >= 0; i-- {
		buf = append(buf, digits[i])
	}
	return string(buf)
}
