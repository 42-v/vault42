package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// BackupCodeHandler edge cases
// ---------------------------------------------------------------------------

func TestBackupCodeGenerate_DeleteError(t *testing.T) {
	mockBackup := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(ctx context.Context, userID string) error {
			return errors.New("db delete error")
		},
	}

	h := NewBackupCodeHandler(mockBackup, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestBackupCodeGenerate_CreateBatchError(t *testing.T) {
	mockBackup := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(ctx context.Context, userID string) error {
			return nil
		},
		CreateBatchFn: func(ctx context.Context, codes []*model.BackupCode) error {
			return errors.New("db insert error")
		},
	}

	h := NewBackupCodeHandler(mockBackup, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestBackupCodeGenerate_CodesAreUnique(t *testing.T) {
	mockBackup := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(ctx context.Context, userID string) error {
			return nil
		},
		CreateBatchFn: func(ctx context.Context, codes []*model.BackupCode) error {
			return nil
		},
	}

	h := NewBackupCodeHandler(mockBackup, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	codes := result["codes"].([]interface{})

	// All codes should be unique
	seen := make(map[string]bool)
	for _, c := range codes {
		code := c.(string)
		if seen[code] {
			t.Fatalf("duplicate backup code found: %q", code)
		}
		seen[code] = true
	}
}

func TestBackupCodeGenerate_CodeLength(t *testing.T) {
	mockBackup := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(ctx context.Context, userID string) error {
			return nil
		},
		CreateBatchFn: func(ctx context.Context, codes []*model.BackupCode) error {
			return nil
		},
	}

	h := NewBackupCodeHandler(mockBackup, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	codes := result["codes"].([]interface{})

	for _, c := range codes {
		code := c.(string)
		// RandomHex(8) generates 16 hex chars
		if len(code) != 16 {
			t.Fatalf("expected code length 16, got %d for code %q", len(code), code)
		}
	}
}
