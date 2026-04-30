package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// TOTP Setup edge cases
// ---------------------------------------------------------------------------

func TestTOTPSetup_Unauthorized(t *testing.T) {
	h := NewTOTPHandler(&mocks.MockTOTPRepo{}, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	// No auth context
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestTOTPSetup_UnverifiedExistingDeleted(t *testing.T) {
	masterKey := make([]byte, 32)
	deleteCalled := false

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:       "totp-old",
				UserID:   userID,
				Verified: false, // not verified yet
			}, nil
		},
		DeleteByUserIDFn: func(ctx context.Context, userID string) error {
			deleteCalled = true
			return nil
		},
		CreateFn: func(ctx context.Context, secret *model.TOTPSecret) error {
			return nil
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", &mocks.MockCache{}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	if !deleteCalled {
		t.Fatal("expected DeleteByUserID to have been called for unverified TOTP")
	}
}

func TestTOTPSetup_CreateRepoError(t *testing.T) {
	masterKey := make([]byte, 32)

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil
		},
		CreateFn: func(ctx context.Context, secret *model.TOTPSecret) error {
			return errors.New("db error")
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", &mocks.MockCache{}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPSetup_GetByUserIDError(t *testing.T) {
	masterKey := make([]byte, 32)

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, errors.New("db read error")
		},
		CreateFn: func(ctx context.Context, secret *model.TOTPSecret) error {
			return nil
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", &mocks.MockCache{}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	req = setAuthContext(req, "user-err")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	// When GetByUserID returns error, existing is nil, code continues to create
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TOTP Verify edge cases
// ---------------------------------------------------------------------------

func TestTOTPVerify_Unauthorized(t *testing.T) {
	h := NewTOTPHandler(&mocks.MockTOTPRepo{}, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	// No auth context
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPVerify_InvalidJSON(t *testing.T) {
	h := NewTOTPHandler(&mocks.MockTOTPRepo{}, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", strings.NewReader("not json"))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPVerify_InvalidCodes(t *testing.T) {
	h := NewTOTPHandler(&mocks.MockTOTPRepo{}, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	tests := []struct {
		name string
		code string
	}{
		{"short", "123"},
		{"long", "12345678"},
		{"non_digit", "abcdef"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := jsonBody(t, map[string]string{"code": tt.code})
			req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
			req = setAuthContext(req, "user-123")
			rec := httptest.NewRecorder()
			h.Verify(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTOTPVerify_NotSetup(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil // no TOTP configured
		},
	}

	h := NewTOTPHandler(mockTOTP, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "totp_not_setup" {
		t.Fatalf("expected error=totp_not_setup, got %q", result["error"])
	}
}

func TestTOTPVerify_GetByUserIDError(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewTOTPHandler(mockTOTP, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPVerify_InvalidEncryptedSecret(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-bad",
				UserID:    userID,
				SecretEnc: "not-valid-hex!!!",
				Verified:  false,
			}, nil
		},
	}

	h := NewTOTPHandler(mockTOTP, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPVerify_DecryptionError(t *testing.T) {
	// Create ciphertext encrypted with a different key
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = 0xFF
	}
	encrypted, _ := vaultcrypto.Encrypt([]byte("secret"), otherKey, []byte("user-123"))

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-wrongkey",
				UserID:    userID,
				SecretEnc: hex.EncodeToString(encrypted),
				Verified:  false,
			}, nil
		},
	}

	masterKey := make([]byte, 32) // different key -> decryption fails
	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", &mocks.MockCache{}, nil, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPVerify_ReplayAttack(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	secret, _ := vaultcrypto.GenerateTOTPSecret()
	encrypted, _ := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte("user-123"))
	encHex := hex.EncodeToString(encrypted)

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-replay",
				UserID:    userID,
				SecretEnc: encHex,
				Verified:  true,
			}, nil
		},
	}

	// SetIfNotExists returns false when code was already used (key already exists)
	mockCache := &mocks.MockCache{
		SetIfNotExistsFn: func(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
			return false, nil // code already used — key already existed
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, nil, false)

	code, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())

	body := jsonBody(t, map[string]string{"code": code})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "totp_code_already_used" {
		t.Fatalf("expected error=totp_code_already_used, got %q", result["error"])
	}
}
