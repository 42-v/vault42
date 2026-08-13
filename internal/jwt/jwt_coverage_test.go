package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// EncodeSegment (exported wrapper at jwt.go:33)
// ---------------------------------------------------------------------------

func TestEncodeSegment_Exported(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"hello", []byte("hello"), base64.RawURLEncoding.EncodeToString([]byte("hello"))},
		{"binary_with_padding_needed", []byte{0xfb, 0xff, 0xfe}, base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeSegment(tt.data)
			if got != tt.want {
				t.Errorf("EncodeSegment(%v) = %q, want %q", tt.data, got, tt.want)
			}
			// Verify round-trip through stdlib decode
			decoded, err := base64.RawURLEncoding.DecodeString(got)
			if err != nil {
				t.Fatalf("stdlib decode failed: %v", err)
			}
			if string(decoded) != string(tt.data) {
				t.Errorf("round-trip mismatch: got %v, want %v", decoded, tt.data)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SignRS256WithHeader (jwt.go:68)
// ---------------------------------------------------------------------------

func TestSignRS256WithHeader_ValidToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "custom-kid",
	}
	claims := map[string]any{
		"iss": "vault",
		"sub": "user-42",
		"aud": []string{"api"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenStr, err := SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader: %v", err)
	}

	// Verify it produces 3 segments
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}

	// Parse and verify the token is valid
	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("ParseWithClaims failed: %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid")
	}
	if parsed.Subject != "user-42" {
		t.Errorf("subject = %q, want user-42", parsed.Subject)
	}

	// Verify custom kid is in header
	kid, _ := tok.Header["kid"].(string)
	if kid != "custom-kid" {
		t.Errorf("kid = %q, want custom-kid", kid)
	}
}

func TestSignRS256WithHeader_CustomHeaders(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	header := map[string]any{
		"alg":   "RS256",
		"typ":   "JWT",
		"kid":   "test-kid",
		"extra": "should-appear",
	}
	claims := map[string]any{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenStr, err := SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader: %v", err)
	}

	// Parse unverified to inspect header
	tok, err := ParseUnverified(tokenStr, &RegisteredClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}

	extra, _ := tok.Header["extra"].(string)
	if extra != "should-appear" {
		t.Errorf("extra header = %q, want should-appear", extra)
	}
}

func TestSignRS256WithHeader_NilKey(t *testing.T) {
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{"sub": "user"}

	_, err := SignRS256WithHeader(header, claims, nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestSignRS256WithHeader_UnmarshalableClaims(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	header := map[string]any{"alg": "RS256"}

	// func values cannot be marshaled to JSON
	badClaims := map[string]any{
		"fn": func() {},
	}

	_, err := SignRS256WithHeader(header, badClaims, key)
	if err == nil {
		t.Fatal("expected error for unmarshalable claims")
	}
}

func TestSignRS256WithHeader_UnmarshalableHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	badHeader := map[string]any{
		"fn": func() {},
	}
	claims := map[string]any{"sub": "user"}

	_, err := SignRS256WithHeader(badHeader, claims, key)
	if err == nil {
		t.Fatal("expected error for unmarshalable header")
	}
}

// ---------------------------------------------------------------------------
// SignTokenCustom (jwt.go:92)
// ---------------------------------------------------------------------------

func TestSignTokenCustom_DummySignFunc(t *testing.T) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	dummySig := []byte("test-signature-bytes")
	tokenStr, err := SignTokenCustom(header, claims, func(signingString string) ([]byte, error) {
		// Verify the signing string is header.payload
		if !strings.Contains(signingString, ".") {
			t.Error("signingString should contain a dot separator")
		}
		return dummySig, nil
	})
	if err != nil {
		t.Fatalf("SignTokenCustom: %v", err)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}

	// Verify the signature segment decodes to our dummy signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if string(sigBytes) != string(dummySig) {
		t.Errorf("sig = %v, want %v", sigBytes, dummySig)
	}
}

func TestSignTokenCustom_SignFuncError(t *testing.T) {
	header := map[string]any{"alg": "custom", "typ": "JWT"}
	claims := map[string]any{"sub": "user"}

	_, err := SignTokenCustom(header, claims, func(signingString string) ([]byte, error) {
		return nil, errors.New("signing failed")
	})
	if err == nil {
		t.Fatal("expected error when signFunc fails")
	}
	if !strings.Contains(err.Error(), "sign") {
		t.Errorf("error should mention signing: %v", err)
	}
}

func TestSignTokenCustom_UnmarshalableHeader(t *testing.T) {
	badHeader := map[string]any{"fn": func() {}}
	claims := map[string]any{"sub": "user"}

	_, err := SignTokenCustom(badHeader, claims, func(s string) ([]byte, error) {
		return []byte("sig"), nil
	})
	if err == nil {
		t.Fatal("expected error for unmarshalable header")
	}
}

func TestSignTokenCustom_UnmarshalableClaims(t *testing.T) {
	header := map[string]any{"alg": "test"}
	badClaims := map[string]any{"fn": func() {}}

	_, err := SignTokenCustom(header, badClaims, func(s string) ([]byte, error) {
		return []byte("sig"), nil
	})
	if err == nil {
		t.Fatal("expected error for unmarshalable claims")
	}
}

func TestSignTokenCustom_EmptySignature(t *testing.T) {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	claims := map[string]any{"sub": "user"}

	tokenStr, err := SignTokenCustom(header, claims, func(s string) ([]byte, error) {
		return []byte{}, nil
	})
	if err != nil {
		t.Fatalf("SignTokenCustom: %v", err)
	}

	// With empty sig bytes, the last segment should be empty base64url encoding of []byte{}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
}

// ---------------------------------------------------------------------------
// UnsignedToken (jwt.go:114)
// ---------------------------------------------------------------------------

func TestUnsignedToken_Format(t *testing.T) {
	header := map[string]any{
		"alg": "none",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "user-1",
		"iss": "vault",
	}

	tokenStr, err := UnsignedToken(header, claims)
	if err != nil {
		t.Fatalf("UnsignedToken: %v", err)
	}

	// Must have exactly 3 segments with empty signature
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}

	// Signature segment must be empty
	if parts[2] != "" {
		t.Errorf("signature segment = %q, want empty string", parts[2])
	}

	// Must end with a dot
	if !strings.HasSuffix(tokenStr, ".") {
		t.Error("unsigned token should end with a dot")
	}

	// Verify header decodes correctly
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if !strings.Contains(string(headerBytes), `"alg":"none"`) {
		t.Errorf("header should contain alg:none, got %s", headerBytes)
	}

	// Verify payload decodes correctly
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !strings.Contains(string(payloadBytes), `"sub":"user-1"`) {
		t.Errorf("payload should contain sub:user-1, got %s", payloadBytes)
	}
}

func TestUnsignedToken_UnmarshalableHeader(t *testing.T) {
	badHeader := map[string]any{"fn": func() {}}
	claims := map[string]any{"sub": "user"}

	_, err := UnsignedToken(badHeader, claims)
	if err == nil {
		t.Fatal("expected error for unmarshalable header")
	}
}

func TestUnsignedToken_UnmarshalableClaims(t *testing.T) {
	header := map[string]any{"alg": "none"}
	badClaims := map[string]any{"fn": func() {}}

	_, err := UnsignedToken(header, badClaims)
	if err == nil {
		t.Fatal("expected error for unmarshalable claims")
	}
}

// ---------------------------------------------------------------------------
// MapClaims getters (claims.go:39-62)
// ---------------------------------------------------------------------------

func TestMapClaims_GetExpirationTime(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		isNil  bool
		unix   int64
	}{
		{"float64_nonzero", MapClaims{"exp": float64(1700000000)}, false, 1700000000},
		{"float64_zero", MapClaims{"exp": float64(0)}, false, 0},
		{"int64_nonzero", MapClaims{"exp": int64(1700000000)}, false, 1700000000},
		{"int64_zero", MapClaims{"exp": int64(0)}, false, 0},
		{"numeric_date", MapClaims{"exp": NewNumericDate(time.Unix(1700000000, 0))}, false, 1700000000},
		{"string_default", MapClaims{"exp": "not-a-number"}, true, 0},
		{"missing_key", MapClaims{}, true, 0},
		{"nil_value", MapClaims{"exp": nil}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetExpirationTime()
			if tt.isNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil")
			}
			if got.Unix() != tt.unix {
				t.Errorf("unix = %d, want %d", got.Unix(), tt.unix)
			}
		})
	}
}

func TestMapClaims_GetIssuedAt(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		isNil  bool
		unix   int64
	}{
		{"float64_nonzero", MapClaims{"iat": float64(1700000000)}, false, 1700000000},
		{"float64_zero", MapClaims{"iat": float64(0)}, false, 0},
		{"int64_nonzero", MapClaims{"iat": int64(1700000000)}, false, 1700000000},
		{"int64_zero", MapClaims{"iat": int64(0)}, false, 0},
		{"numeric_date", MapClaims{"iat": NewNumericDate(time.Unix(1700000000, 0))}, false, 1700000000},
		{"string_default", MapClaims{"iat": "not-a-number"}, true, 0},
		{"missing_key", MapClaims{}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetIssuedAt()
			if tt.isNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil")
			}
			if got.Unix() != tt.unix {
				t.Errorf("unix = %d, want %d", got.Unix(), tt.unix)
			}
		})
	}
}

func TestMapClaims_GetNotBefore(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		isNil  bool
		unix   int64
	}{
		{"float64_nonzero", MapClaims{"nbf": float64(1700000000)}, false, 1700000000},
		{"float64_zero", MapClaims{"nbf": float64(0)}, false, 0},
		{"int64_nonzero", MapClaims{"nbf": int64(1700000000)}, false, 1700000000},
		{"int64_zero", MapClaims{"nbf": int64(0)}, false, 0},
		{"numeric_date", MapClaims{"nbf": NewNumericDate(time.Unix(1700000000, 0))}, false, 1700000000},
		{"string_default", MapClaims{"nbf": "not-a-number"}, true, 0},
		{"missing_key", MapClaims{}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetNotBefore()
			if tt.isNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil")
			}
			if got.Unix() != tt.unix {
				t.Errorf("unix = %d, want %d", got.Unix(), tt.unix)
			}
		})
	}
}

func TestMapClaims_GetIssuer(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		want   string
	}{
		{"present", MapClaims{"iss": "vault"}, "vault"},
		{"missing", MapClaims{}, ""},
		{"non_string", MapClaims{"iss": 42}, ""},
		{"nil_value", MapClaims{"iss": nil}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetIssuer()
			if got != tt.want {
				t.Errorf("GetIssuer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapClaims_GetSubject(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		want   string
	}{
		{"present", MapClaims{"sub": "user-42"}, "user-42"},
		{"missing", MapClaims{}, ""},
		{"non_string", MapClaims{"sub": 123}, ""},
		{"nil_value", MapClaims{"sub": nil}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetSubject()
			if got != tt.want {
				t.Errorf("GetSubject() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapClaims_GetAudience(t *testing.T) {
	tests := []struct {
		name    string
		claims  MapClaims
		want    ClaimStrings
		wantNil bool
	}{
		{
			name:   "string_value",
			claims: MapClaims{"aud": "api"},
			want:   ClaimStrings{"api"},
		},
		{
			name:   "string_slice",
			claims: MapClaims{"aud": []string{"api", "web"}},
			want:   ClaimStrings{"api", "web"},
		},
		{
			name:   "any_slice_all_strings",
			claims: MapClaims{"aud": []any{"api", "web", "mobile"}},
			want:   ClaimStrings{"api", "web", "mobile"},
		},
		{
			name:   "any_slice_with_non_strings",
			claims: MapClaims{"aud": []any{"api", 42, "web"}},
			want:   ClaimStrings{"api", "web"},
		},
		{
			name:    "any_slice_all_non_strings",
			claims:  MapClaims{"aud": []any{1, 2, 3}},
			want:    nil,
			wantNil: true,
		},
		{
			name:    "nil_value",
			claims:  MapClaims{"aud": nil},
			wantNil: true,
		},
		{
			name:    "missing_key",
			claims:  MapClaims{},
			wantNil: true,
		},
		{
			name:    "integer_type",
			claims:  MapClaims{"aud": 42},
			wantNil: true,
		},
		{
			name:    "bool_type",
			claims:  MapClaims{"aud": true},
			wantNil: true,
		},
		{
			name:    "any_slice_empty",
			claims:  MapClaims{"aud": []any{}},
			want:    nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.GetAudience()
			if tt.wantNil {
				if got != nil {
					t.Errorf("GetAudience() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("GetAudience() len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetAudience()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mapNumericDate (claims.go:64) — exhaustive type switch coverage
// ---------------------------------------------------------------------------

// The zero cases below expect a timestamp, not nil. A numeric 0 is the epoch,
// which is a real and long-past deadline; only an absent or non-numeric claim
// reads as "no deadline", because that is the reading validateClaims turns into
// skipping the check entirely.
func TestMapNumericDate_AllPaths(t *testing.T) {
	tests := []struct {
		name   string
		claims MapClaims
		key    string
		isNil  bool
		unix   int64
	}{
		{"float64_nonzero", MapClaims{"exp": float64(1700000000)}, "exp", false, 1700000000},
		{"float64_zero", MapClaims{"exp": float64(0)}, "exp", false, 0},
		{"int64_nonzero", MapClaims{"exp": int64(1700000000)}, "exp", false, 1700000000},
		{"int64_zero", MapClaims{"exp": int64(0)}, "exp", false, 0},
		{"numeric_date_ptr", MapClaims{"exp": NewNumericDate(time.Unix(1700000000, 0))}, "exp", false, 1700000000},
		{"numeric_date_nil_ptr", MapClaims{"exp": (*NumericDate)(nil)}, "exp", true, 0},
		{"string_falls_to_default", MapClaims{"exp": "2023-11-14"}, "exp", true, 0},
		{"bool_falls_to_default", MapClaims{"exp": true}, "exp", true, 0},
		{"missing_key", MapClaims{}, "exp", true, 0},
		{"nil_value", MapClaims{"exp": nil}, "exp", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapNumericDate(tt.claims, tt.key)
			if tt.isNil {
				if got != nil {
					t.Errorf("expected nil, got %v (unix=%d)", got, got.Unix())
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil")
			}
			if got.Unix() != tt.unix {
				t.Errorf("unix = %d, want %d", got.Unix(), tt.unix)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MapClaims implements Claims interface (compile-time check)
// ---------------------------------------------------------------------------

var _ Claims = MapClaims{}

// ---------------------------------------------------------------------------
// WithIssuedAt parse option (parse.go:43)
// ---------------------------------------------------------------------------

func TestWithIssuedAt_FutureIAT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Create a token with iat set 1 hour in the future
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(2 * time.Hour)),
		IssuedAt:  NewNumericDate(time.Now().Add(time.Hour)),
	}

	tokenStr, err := SignRS256(claims, key, "k")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Parse with WithIssuedAt — should fail because iat is in the future
	_, err = ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithIssuedAt())

	if !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Errorf("got %v, want ErrTokenUsedBeforeIssued", err)
	}
}

func TestWithIssuedAt_PastIAT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Create a token with iat in the past — should pass
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  NewNumericDate(time.Now().Add(-time.Minute)),
	}

	tokenStr, err := SignRS256(claims, key, "k")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithIssuedAt())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid")
	}
}

func TestWithIssuedAt_NoIATClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Token without iat — WithIssuedAt should not fail (iat is nil, validation skipped)
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}

	tokenStr, err := SignRS256(claims, key, "k")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithIssuedAt())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid")
	}
}

// ---------------------------------------------------------------------------
// ParseUnverified edge cases (parse.go:184)
// ---------------------------------------------------------------------------

func TestParseUnverified_BadHeaderBase64(t *testing.T) {
	// Use invalid base64url characters in the header segment
	token := "!!!invalid-base64!!!.eyJzdWIiOiJ1c2VyIn0."
	_, err := ParseUnverified(token, &RegisteredClaims{})
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("got %v, want ErrTokenMalformed", err)
	}
}

func TestParseUnverified_BadHeaderJSON(t *testing.T) {
	// Valid base64url encoding of non-JSON data
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("this is not json{{{"))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	token := notJSON + "." + payload + "."

	_, err := ParseUnverified(token, &RegisteredClaims{})
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("got %v, want ErrTokenMalformed", err)
	}
}

func TestParseUnverified_BadPayloadBase64(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	token := header + ".!!!invalid-base64!!!."

	_, err := ParseUnverified(token, &RegisteredClaims{})
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("got %v, want ErrTokenMalformed", err)
	}
}

func TestParseUnverified_BadPayloadJSON(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("not json at all"))
	token := header + "." + badPayload + "."

	_, err := ParseUnverified(token, &RegisteredClaims{})
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("got %v, want ErrTokenMalformed", err)
	}
}

func TestParseUnverified_MalformedSegmentCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no_dots", "nodots"},
		{"one_dot", "one.dot"},
		{"four_segments", "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUnverified(tt.token, &RegisteredClaims{})
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("got %v, want ErrTokenMalformed", err)
			}
		})
	}
}

func TestParseUnverified_BadSignatureBase64Tolerated(t *testing.T) {
	// ParseUnverified should tolerate bad signature encoding (best-effort decode)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	token := header + "." + payload + ".!!!bad-sig!!!"

	tok, err := ParseUnverified(token, &RegisteredClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified should not fail on bad sig encoding, got %v", err)
	}
	if tok.Valid {
		t.Error("token should not be marked valid")
	}
	// Signature should be nil/empty since decode failed
	if len(tok.Signature) != 0 {
		t.Errorf("expected empty signature, got %d bytes", len(tok.Signature))
	}
}

func TestParseUnverified_EmptySignature(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user","iss":"vault"}`))
	token := header + "." + payload + "."

	parsed := &RegisteredClaims{}
	tok, err := ParseUnverified(token, parsed)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if tok.Valid {
		t.Error("token should not be marked valid")
	}
	if parsed.Subject != "user" {
		t.Errorf("Subject = %q, want user", parsed.Subject)
	}
	if parsed.Issuer != "vault" {
		t.Errorf("Issuer = %q, want vault", parsed.Issuer)
	}
}

// ---------------------------------------------------------------------------
// Integration: SignRS256WithHeader round-trip through ParseWithClaims
// ---------------------------------------------------------------------------

func TestSignRS256WithHeader_RoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "roundtrip-kid",
	}
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-roundtrip",
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  NewNumericDate(now.Add(-time.Minute)),
	}

	tokenStr, err := SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader: %v", err)
	}

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid != "roundtrip-kid" {
			return nil, errors.New("wrong kid")
		}
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithIssuer("vault"), WithAudience("api"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid")
	}
	if parsed.Issuer != "vault" {
		t.Errorf("Issuer = %q, want vault", parsed.Issuer)
	}
	if parsed.Subject != "user-roundtrip" {
		t.Errorf("Subject = %q, want user-roundtrip", parsed.Subject)
	}
}

// ---------------------------------------------------------------------------
// Integration: UnsignedToken rejected by ParseWithClaims
// ---------------------------------------------------------------------------

func TestUnsignedToken_RejectedByParser(t *testing.T) {
	header := map[string]any{
		"alg": "none",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenStr, err := UnsignedToken(header, claims)
	if err != nil {
		t.Fatalf("UnsignedToken: %v", err)
	}

	// Attempt to parse with RS256 whitelist — should be rejected
	_, err = ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestUnsignedToken_RejectedWithoutWhitelist(t *testing.T) {
	header := map[string]any{
		"alg": "none",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "attacker",
	}

	tokenStr, err := UnsignedToken(header, claims)
	if err != nil {
		t.Fatalf("UnsignedToken: %v", err)
	}

	// Without whitelist, "none" should still fail (unsupported algorithm)
	_, err = ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	})

	if !errors.Is(err, ErrTokenUnverifiable) {
		t.Errorf("got %v, want ErrTokenUnverifiable", err)
	}
}

// ---------------------------------------------------------------------------
// Integration: SignTokenCustom with real RS256 signer
// ---------------------------------------------------------------------------

func TestSignTokenCustom_WithRS256Signer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "custom-signer-kid",
	}
	claims := map[string]any{
		"sub": "user-custom",
		"iss": "vault",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}

	tokenStr, err := SignTokenCustom(header, claims, func(signingString string) ([]byte, error) {
		return SignRS256Bytes(signingString, key)
	})
	if err != nil {
		t.Fatalf("SignTokenCustom: %v", err)
	}

	// Should be parseable and valid
	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid")
	}
	if parsed.Subject != "user-custom" {
		t.Errorf("Subject = %q, want user-custom", parsed.Subject)
	}
}
