package attack

import (
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_KID_Length63 verifies that a 63-char hex kid passes validation.
func TestJWT_KID_Length63(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid := strings.Repeat("a", 63)
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
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
	if err != nil {
		t.Fatalf("63-char hex kid should be valid: %v", err)
	}
}

// TestJWT_KID_Length64 verifies that a 64-char hex kid passes (at the limit).
func TestJWT_KID_Length64(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid := strings.Repeat("b", 64)
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
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
	if err != nil {
		t.Fatalf("64-char hex kid should be valid (at limit): %v", err)
	}
}

// TestJWT_KID_Length65 verifies that a 65-char kid is rejected (exceeds max 64).
func TestJWT_KID_Length65(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid := strings.Repeat("c", 65)
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
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
		t.Fatal("65-char kid should be rejected (exceeds max 64)")
	}
}

// TestJWT_KID_CaseSensitive verifies that uppercase and lowercase kids are both valid formats
// but treated as different keys.
func TestJWT_KID_CaseSensitive(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kidLower := "abcdef0123456789"
	kidUpper := "ABCDEF0123456789"
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	for _, kid := range []string{kidLower, kidUpper} {
		t.Run("kid="+kid, func(t *testing.T) {
			tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": kid,
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
			if err != nil {
				t.Fatalf("kid=%q should pass format validation: %v", kid, err)
			}
		})
	}
}

// TestJWT_KID_Empty verifies that empty kid is rejected.
func TestJWT_KID_Empty(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": "",
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
		t.Fatal("Empty kid should be rejected")
	}
}

// TestJWT_KID_OnlyDashes verifies that a kid of only dashes passes format validation.
func TestJWT_KID_OnlyDashes(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid := "----"
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
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
	if err != nil {
		t.Fatalf("kid of only dashes should pass format validation: %v", err)
	}
}

// TestJWT_KID_Unicode verifies that non-hex unicode characters in kid are rejected.
func TestJWT_KID_Unicode(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid := "abcd\u00e9f" // "abcdéf" — contains non-hex character
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
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
		t.Fatal("kid with unicode char should be rejected (non-hex)")
	}
}
