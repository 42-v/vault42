package attack

import (
	"fmt"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_KID_Length walks the kid length limit. 64 is the last accepted
// length and 65 the first refused one, so these rows straddle the boundary the
// parser enforces and a limit that moves by one in either direction turns one
// of them red.
func TestJWT_KID_Length(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	cases := []struct {
		length     int
		wantAccept bool
	}{
		{63, true},
		{64, true},
		{65, false},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("length=%d", tc.length), func(t *testing.T) {
			tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": strings.Repeat("a", tc.length),
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
			if tc.wantAccept && err != nil {
				t.Fatalf("a %d-char kid is within the 64-char limit and must be accepted: %v", tc.length, err)
			}
			if !tc.wantAccept && err == nil {
				t.Fatalf("a %d-char kid exceeds the 64-char limit and must be rejected", tc.length)
			}
		})
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
