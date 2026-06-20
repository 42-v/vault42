package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// newChangePasswordHandler wires a PasswordHandler with caller-supplied refresh
// and cache mocks so updatePassword's session-revoke and reset-invalidation
// branches can be exercised.
func newChangePasswordHandler(users *mocks.MockUserRepo, tokens *mocks.MockRefreshTokenRepo, c cache.Cache) *PasswordHandler {
	return NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		tokens,
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		c,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)
}

// updatePassword's session-revoke failure surfaces as a 500 from ChangePassword.
func TestChangePassword_RevokeSessionsError500(t *testing.T) {
	current := "currentValidPassword!1"
	hash, _ := vaultcrypto.HashPassword(current)
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@x.test", PasswordHash: hash}, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, _ string) error { return nil },
	}
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, _ string) error { return errors.New("revoke failed") },
	}
	h := newChangePasswordHandler(users, tokens, &mocks.MockCache{})

	body := jsonBody(t, map[string]string{"current_password": current, "new_password": "aBrandNewPassword!9"})
	req := setAuthContext(httptest.NewRequest(http.MethodPost, "/user/password", body), "user-rev")
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

// A pending reset token cached for the user is invalidated on a successful
// password change (the GetAndDelete-hit + Delete branch in updatePassword).
func TestChangePassword_InvalidatesPendingReset200(t *testing.T) {
	current := "currentValidPassword!2"
	hash, _ := vaultcrypto.HashPassword(current)
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@x.test", PasswordHash: hash}, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, _ string) error { return nil },
	}
	var deletedKeys []string
	c := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, _ string) (string, error) {
			return "pending-reset-token-hash", nil
		},
		DeleteFn: func(_ context.Context, key string) error {
			deletedKeys = append(deletedKeys, key)
			return nil
		},
	}
	h := newChangePasswordHandler(users, &mocks.MockRefreshTokenRepo{}, c)

	body := jsonBody(t, map[string]string{"current_password": current, "new_password": "aBrandNewPassword!8"})
	req := setAuthContext(httptest.NewRequest(http.MethodPost, "/user/password", body), "user-reset")
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	// Expect the reset:<hash> deletion and the confirm:<userID> deletion.
	var sawReset, sawConfirm bool
	for _, k := range deletedKeys {
		if k == "reset:pending-reset-token-hash" {
			sawReset = true
		}
		if k == "confirm:user-reset" {
			sawConfirm = true
		}
	}
	if !sawReset || !sawConfirm {
		t.Fatalf("expected reset+confirm cache keys deleted, got %v", deletedKeys)
	}
}
