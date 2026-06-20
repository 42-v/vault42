package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// WS3: completing a password reset for an import_pending account claims it —
// ResetConfirm must call ClearImportPending so future logins verify normally.
func TestResetConfirm_ClearsImportPending(t *testing.T) {
	var cleared bool
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if strings.HasPrefix(key, "reset:") {
				return "u-imp", nil
			}
			return "", nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "u-imp", Email: "rider@legacy.test", ImportPending: true}, nil
		},
		ClearImportPendingFn: func(_ context.Context, id string) error {
			if id == "u-imp" {
				cleared = true
			}
			return nil
		},
	}
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), cache,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	body := strings.NewReader(`{"token":"magic-token-abc","password":"aNewStrongPassword!123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()
	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("reset confirm should succeed (200), got %d: %s", rec.Code, rec.Body.String())
	}
	if !cleared {
		t.Error("ClearImportPending must be called when claiming an imported account")
	}
}
