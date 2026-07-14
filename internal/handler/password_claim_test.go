package handler

import (
	"context"
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

// An imported account claims itself by setting a password through the magic link, which
// clears import_pending. If that clear fails, reporting success would leave the account in
// a state where the password IS set but the flag says otherwise — so the next login takes
// the import-claim path again and mails another link, forever, while the user is certain
// they already chose a password.
//
// Failing closed keeps it recoverable: import_pending stays true, the link can be
// re-issued, and the user is told the reset did not complete rather than being sent in a
// loop.
func TestResetConfirm_ImportClaimFailureIsNotReportedAsSuccess(t *testing.T) {
	const token = "reset-token-value"
	tokenHash := vaultcrypto.SHA256Hex(token)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "imported@example.com", ImportPending: true}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error { return nil },
		// Both the lockout clear and the import-claim clear fail: the first is
		// best-effort and must not sink the request, the second is not.
		ResetFailedLoginFn: func(context.Context, string) error {
			return errors.New("db down")
		},
		ClearImportPendingFn: func(context.Context, string) error {
			return errors.New("db down")
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if strings.Contains(key, tokenHash) {
				return "user-import", nil
			}
			return "", nil
		},
		GetFn: func(context.Context, string) (string, error) { return "user-import", nil },
		SetFn: func(context.Context, string, string, time.Duration) error { return nil },
	}

	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), mockCache,
		"https://vault.test", "TestVault", "", 12, nil, false,
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset-confirm",
		jsonBody(t, map[string]string{"token": token, "password": "a-brand-new-password"}))
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("the reset reported success while the account is still import_pending — the user would be sent round the claim loop forever")
	}
}
