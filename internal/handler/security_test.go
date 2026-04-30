package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// ---------------------------------------------------------------------------
// TOTP code validation tests
// ---------------------------------------------------------------------------

func TestIsValidTOTPCode(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"valid_6_digits", "123456", true},
		{"valid_all_zeros", "000000", true},
		{"valid_all_nines", "999999", true},
		{"too_short", "12345", false},
		{"too_long", "1234567", false},
		{"empty", "", false},
		{"letters", "abcdef", false},
		{"mixed", "12ab34", false},
		{"spaces", "123 56", false},
		{"newline", "12345\n", false},
		{"null_byte", "12345\x00", false},
		{"negative", "-12345", false},
		{"decimal", "12.456", false},
		{"unicode_digits", "１２３４５６", false}, // fullwidth digits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidTOTPCode(tt.code)
			if got != tt.valid {
				t.Errorf("isValidTOTPCode(%q) = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Healthz version removal test
// ---------------------------------------------------------------------------

func TestHealthzNoVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	Healthz(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "version") {
		t.Error("healthz response should NOT contain version field")
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("healthz should contain status:ok, got %s", body)
	}
}

// ---------------------------------------------------------------------------
// DecodeJSON DisallowUnknownFields test
// ---------------------------------------------------------------------------

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	body := strings.NewReader(`{"email":"test@example.com","unknown_field":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)

	var dst struct {
		Email string `json:"email"`
	}

	err := decodeJSON(req, &dst)
	if err == nil {
		t.Error("decodeJSON should reject unknown fields")
	}
}

func TestDecodeJSONAcceptsKnownFields(t *testing.T) {
	body := strings.NewReader(`{"email":"test@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)

	var dst struct {
		Email string `json:"email"`
	}

	err := decodeJSON(req, &dst)
	if err != nil {
		t.Errorf("decodeJSON should accept known fields: %v", err)
	}
	if dst.Email != "test@example.com" {
		t.Errorf("expected email=test@example.com, got %q", dst.Email)
	}
}

// ---------------------------------------------------------------------------
// Password reset timing defense test
// ---------------------------------------------------------------------------

func TestDummyResetHashIsValidFormat(t *testing.T) {
	// Verify the pre-computed dummy hash is valid Argon2id format
	if !strings.HasPrefix(vaultcrypto.DummyHash, "$argon2id$v=19$") {
		t.Errorf("vaultcrypto.DummyHash should be valid Argon2id format, got %s", vaultcrypto.DummyHash[:30])
	}
	parts := strings.Split(vaultcrypto.DummyHash, "$")
	if len(parts) != 6 {
		t.Errorf("vaultcrypto.DummyHash should have 6 PHC format parts, got %d", len(parts))
	}
}
