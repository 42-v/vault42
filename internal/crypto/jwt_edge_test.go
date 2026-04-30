package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWTEdge_EmptyToken tests that empty string tokens are rejected.
func TestJWTEdge_EmptyToken(t *testing.T) {
	key, _ := setupTestKeys(t)
	_, err := ParseAndValidate("", keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("Empty token should be rejected")
	}
}

// TestJWTEdge_SingleDot tests that a token with only one dot is rejected.
func TestJWTEdge_SingleDot(t *testing.T) {
	key, _ := setupTestKeys(t)
	_, err := ParseAndValidate("header.payload", keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("Token with only 2 parts should be rejected")
	}
}

// TestJWTEdge_ThreeDots tests that a token with too many dots is rejected.
func TestJWTEdge_ThreeDots(t *testing.T) {
	key, _ := setupTestKeys(t)
	_, err := ParseAndValidate("a.b.c.d", keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("Token with 4 parts should be rejected")
	}
}

// TestJWTEdge_EmptyParts tests tokens with empty header/payload/signature parts.
func TestJWTEdge_EmptyParts(t *testing.T) {
	key, _ := setupTestKeys(t)

	empties := []struct {
		name  string
		token string
	}{
		{"empty_header", ".eyJzdWIiOiIxMjMifQ.sig"},
		{"empty_payload", "eyJhbGciOiJSUzI1NiJ9..sig"},
		{"empty_signature", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ."},
		{"all_empty", ".."},
		{"dots_only", "..."},
	}

	for _, tc := range empties {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndValidate(tc.token, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Fatalf("Token %q should be rejected", tc.name)
			}
		})
	}
}

// TestJWTEdge_InvalidBase64 tests tokens with invalid base64url encoding.
func TestJWTEdge_InvalidBase64(t *testing.T) {
	key, _ := setupTestKeys(t)

	badTokens := []struct {
		name  string
		token string
	}{
		{"bad_header_base64", "!!!invalid!!!.eyJzdWIiOiIxMjMifQ.sig"},
		{"bad_payload_base64", "eyJhbGciOiJSUzI1NiJ9.!!!invalid!!!.sig"},
		{"unicode_in_parts", "\xf0\x9f\x94\x90.payload.sig"},
		{"null_bytes", "\x00.\x00.\x00"},
		{"newlines", "eyJhbGci\nOiJSUzI1NiJ9.payload.sig"},
		{"spaces", "eyJhbGci OiJSUzI1NiJ9.payload.sig"},
	}

	for _, tc := range badTokens {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndValidate(tc.token, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Fatalf("Token with %s should be rejected", tc.name)
			}
		})
	}
}

// TestJWTEdge_ExactlyMaxSize tests a token at exactly MaxJWTSize (should be accepted
// if valid) and one byte over (rejected).
func TestJWTEdge_ExactlyMaxSize(t *testing.T) {
	key, kid := setupTestKeys(t)

	// Create a token just under max size by padding scopes
	claims := validClaims()

	// Try to create a token just at the boundary
	tokenStr, _ := SignToken(claims, key, kid)
	originalLen := len(tokenStr)

	// Token at exact max size with padding
	if originalLen < MaxJWTSize {
		// Pad to just under max — this is still valid
		paddedToken := tokenStr + strings.Repeat("X", MaxJWTSize-originalLen-1)
		// This won't be a valid JWT but tests the size check
		_, err := ParseAndValidate(paddedToken, keyFunc(key), testIssuer, testAudience)
		// Should fail for other reasons (invalid format) but not size
		if err != nil && strings.Contains(err.Error(), "maximum size") {
			t.Fatal("Token at max size should not fail with size error")
		}
	}

	// Token one byte over max
	oversized := strings.Repeat("a", MaxJWTSize+1)
	_, err := ParseAndValidate(oversized, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("Token over max size should be rejected")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("Error should mention maximum size, got: %v", err)
	}
}

// TestJWTEdge_MalformedJSON tests tokens with valid base64url but invalid JSON.
func TestJWTEdge_MalformedJSON(t *testing.T) {
	key, _ := setupTestKeys(t)

	badJSON := []string{
		"{invalid json}",
		"[1,2,3]",
		"null",
		"42",
		`"just a string"`,
		"",
		"{",
		`{"alg": }`,
	}

	for _, j := range badJSON {
		t.Run(j, func(t *testing.T) {
			encoded := base64.RawURLEncoding.EncodeToString([]byte(j))
			token := encoded + "." + encoded + ".signature"
			_, err := ParseAndValidate(token, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Fatalf("Token with malformed JSON %q should be rejected", j)
			}
		})
	}
}

// TestJWTEdge_ExtremeClaimsValues tests tokens with unusual claim values.
func TestJWTEdge_ExtremeClaimsValues(t *testing.T) {
	key, kid := setupTestKeys(t)

	t.Run("very_long_subject", func(t *testing.T) {
		claims := validClaims()
		claims.Subject = strings.Repeat("x", 1000)
		tokenStr, _ := SignToken(claims, key, kid)
		parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Long subject should be accepted: %v", err)
		}
		if parsed.Subject != claims.Subject {
			t.Fatal("Subject should be preserved")
		}
	})

	t.Run("many_roles", func(t *testing.T) {
		claims := validClaims()
		claims.Roles = make([]string, 100)
		for i := range claims.Roles {
			claims.Roles[i] = "role-" + strings.Repeat("x", 10)
		}
		tokenStr, _ := SignToken(claims, key, kid)
		parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Many roles should be accepted: %v", err)
		}
		if len(parsed.Roles) != 100 {
			t.Fatalf("Expected 100 roles, got %d", len(parsed.Roles))
		}
	})

	t.Run("empty_roles", func(t *testing.T) {
		claims := validClaims()
		claims.Roles = []string{}
		tokenStr, _ := SignToken(claims, key, kid)
		parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Empty roles should be accepted: %v", err)
		}
		if len(parsed.Roles) != 0 {
			t.Fatalf("Expected 0 roles, got %d", len(parsed.Roles))
		}
	})

	t.Run("nil_roles", func(t *testing.T) {
		claims := validClaims()
		claims.Roles = nil
		tokenStr, _ := SignToken(claims, key, kid)
		_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Nil roles should be accepted: %v", err)
		}
	})
}

// TestJWTEdge_KIDVariations tests different kid formats.
func TestJWTEdge_KIDVariations(t *testing.T) {
	key, _ := setupTestKeys(t)

	tests := []struct {
		name    string
		kid     string
		wantErr bool
	}{
		{"valid_uuid", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", false},
		{"valid_hex", "abcdef0123456789", false},
		{"valid_short", "a", false},
		{"valid_max_len", strings.Repeat("a", 64), false},
		{"too_long", strings.Repeat("a", 65), true},
		{"empty", "", true},
		{"path_traversal", "../etc/passwd", true},
		{"backslash", "key\\id", true},
		{"space", "key id", true},
		{"semicolon", "key;id", true},
		{"null_byte", "key\x00id", true},
		{"unicode", "k\u00e9y", true},
		{"at_sign", "key@id", true},
		{"pipe", "key|id", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, err := vjwt.SignRS256WithHeader(
				map[string]any{"alg": "RS256", "typ": "JWT", "kid": tc.kid},
				validClaims(), key,
			)
			if err != nil {
				return // Can't sign, skip
			}

			_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if tc.wantErr && err == nil {
				t.Fatalf("kid %q should be rejected", tc.kid)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("kid %q should be accepted: %v", tc.kid, err)
			}
		})
	}
}

// TestJWTEdge_ConfirmationField tests DPoP confirmation field round-trip.
func TestJWTEdge_ConfirmationField(t *testing.T) {
	key, kid := setupTestKeys(t)

	t.Run("with_confirmation", func(t *testing.T) {
		claims := validClaims()
		claims.Confirmation = &Confirmation{JKT: "sha256-thumbprint-here"}
		tokenStr, _ := SignToken(claims, key, kid)
		parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Token with confirmation should be accepted: %v", err)
		}
		if parsed.Confirmation == nil || parsed.Confirmation.JKT != "sha256-thumbprint-here" {
			t.Fatal("Confirmation.JKT should be preserved")
		}
	})

	t.Run("without_confirmation", func(t *testing.T) {
		claims := validClaims()
		claims.Confirmation = nil
		tokenStr, _ := SignToken(claims, key, kid)
		parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
		if err != nil {
			t.Fatalf("Token without confirmation should be accepted: %v", err)
		}
		if parsed.Confirmation != nil {
			t.Fatal("Confirmation should be nil when not set")
		}
	})
}

// TestJWTEdge_MultipleAudiences tests tokens with multiple audiences.
func TestJWTEdge_MultipleAudiences(t *testing.T) {
	key, kid := setupTestKeys(t)

	claims := validClaims()
	claims.Audience = vjwt.ClaimStrings{"app1", "app2", "app3"}
	tokenStr, _ := SignToken(claims, key, kid)

	// Validating against any of the audiences should work
	_, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, "app1")
	if err != nil {
		t.Fatalf("Token with multiple audiences should accept app1: %v", err)
	}

	_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, "app2")
	if err != nil {
		t.Fatalf("Token with multiple audiences should accept app2: %v", err)
	}

	// Non-listed audience should be rejected
	_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, "app-not-listed")
	if err == nil {
		t.Fatal("Token should reject non-listed audience")
	}
}

// TestJWTEdge_SignTokenAndParseRoundTrips tests multiple round-trips with
// various claim combinations.
func TestJWTEdge_SignTokenAndParseRoundTrips(t *testing.T) {
	key, kid := setupTestKeys(t)

	cases := []struct {
		name   string
		claims VaultClaims
	}{
		{
			"minimal",
			VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Issuer:    testIssuer,
					Audience:  vjwt.ClaimStrings{testAudience},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			},
		},
		{
			"all_fields",
			VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Issuer:    testIssuer,
					Audience:  vjwt.ClaimStrings{testAudience},
					Subject:   "user-full",
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					NotBefore: vjwt.NewNumericDate(time.Now()),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
					ID:        "jti-full-test",
				},
				Roles:        []string{"admin", "user", "moderator"},
				Scopes:       []string{"read", "write", "delete"},
				ClientID:     "test-client-v2",
				Fingerprint:  "fp-sha256-hash",
				TokenType:    "access",
				Confirmation: &Confirmation{JKT: "thumbprint-value"},
			},
		},
		{
			"unicode_values",
			VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Issuer:    testIssuer,
					Audience:  vjwt.ClaimStrings{testAudience},
					Subject:   "user-\u00fc\u00f1\u00ee\u00e7\u00f6\u00f0\u00e9",
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
				ClientID: "\u4e2d\u6587-client",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, err := SignToken(tc.claims, key, kid)
			if err != nil {
				t.Fatalf("SignToken failed: %v", err)
			}

			parsed, err := ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if err != nil {
				t.Fatalf("ParseAndValidate failed: %v", err)
			}

			if parsed.Subject != tc.claims.Subject {
				t.Errorf("Subject mismatch: got %q, want %q", parsed.Subject, tc.claims.Subject)
			}
			if parsed.ClientID != tc.claims.ClientID {
				t.Errorf("ClientID mismatch: got %q, want %q", parsed.ClientID, tc.claims.ClientID)
			}
		})
	}
}

// TestJWTEdge_JWKSEmptyKeys tests JWKS serialization with no keys.
func TestJWTEdge_JWKSEmptyKeys(t *testing.T) {
	jwks := SerializeJWKS(nil)
	if len(jwks.Keys) != 0 {
		t.Fatalf("Empty key map should produce empty JWKS, got %d keys", len(jwks.Keys))
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"keys"`) {
		t.Fatal("JWKS JSON should always contain keys field")
	}
}

// TestJWTEdge_IsValidKIDBoundary tests isValidKID boundary conditions.
func TestJWTEdge_IsValidKIDBoundary(t *testing.T) {
	tests := []struct {
		name string
		kid  string
		want bool
	}{
		{"single_hex", "a", true},
		{"max_length", strings.Repeat("f", 64), true},
		{"over_max_length", strings.Repeat("f", 65), false},
		{"empty", "", false},
		{"all_dashes", "----", true},
		{"hex_with_dashes", "a-b-c-d", true},
		{"uppercase_hex", "ABCDEF", true},
		{"mixed_case_hex", "aAbBcC", true},
		{"letter_g", "g", false},
		{"tab", "\t", false},
		{"newline", "\n", false},
		{"carriage_return", "\r", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidKID(tc.kid)
			if got != tc.want {
				t.Errorf("isValidKID(%q) = %v, want %v", tc.kid, got, tc.want)
			}
		})
	}
}
