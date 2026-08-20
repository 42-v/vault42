package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// ResetRequest edge cases
// ---------------------------------------------------------------------------

// A body with no usable address is the one input ResetRequest answers with an
// error at all: every well-formed request gets the same neutral 200 so the
// response is not an enumeration signal.
func TestResetRequest_RejectsBodyWithoutAnAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json at all", "not json"},
		{"empty email", `{"email":""}`},
		{"no email field", "{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestPasswordHandler(t, &mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{})

			req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.ResetRequest(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != "invalid_request" {
				t.Fatalf("error = %q, want %q", result["error"], "invalid_request")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ResetConfirm edge cases
// ---------------------------------------------------------------------------

// Both halves of the confirm body are mandatory. The error code is part of the
// assertion because a missing field that fell through to the token lookup would
// also answer 400, as invalid_or_expired_token, having burnt a one-shot token on
// the way.
func TestResetConfirm_RejectsIncompleteBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json at all", "not json"},
		{"no token", `{"token":"","password":"validpassword12345"}`},
		{"no password", `{"token":"some-token","password":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestPasswordHandler(t, &mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{})

			req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.ResetConfirm(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != "invalid_request" {
				t.Fatalf("error = %q, want %q", result["error"], "invalid_request")
			}
		})
	}
}

func TestResetConfirm_ExpiredToken(t *testing.T) {
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound // token not found (expired)
		},
	}

	h := NewPasswordHandler(
		&mocks.MockUserRepo{},
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    "expired-token-xyz",
		"password": "aNewStrongPassword!123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_or_expired_token" {
		t.Fatalf("expected error=invalid_or_expired_token, got %q", result["error"])
	}
}

func TestResetConfirm_UserNotFound(t *testing.T) {
	token := "user-notfound-token"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "reset:" + tokenHash

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, nil // user not found
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "deleted-user-id", nil
			}
			return "", cache.ErrNotFound
		},
	}

	h := NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    token,
		"password": "aNewStrongPassword!123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestResetConfirm_PasswordHistoryReject(t *testing.T) {
	token := "history-check-token"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "reset:" + tokenHash
	password := "reusedPassword12345"

	// Pre-hash the password we are going to try to reuse
	oldHash, _ := vaultcrypto.HashPassword(password)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}

	pwHistory := &mocks.MockPasswordHistoryRepo{
		GetRecentByUserFn: func(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error) {
			return []*model.PasswordHistory{
				{ID: "ph-1", UserID: userID, PasswordHash: oldHash, CreatedAt: time.Now()},
			}, nil
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-hist", nil
			}
			return "", cache.ErrNotFound
		},
	}

	h := NewPasswordHandler(
		users,
		pwHistory,
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    token,
		"password": password, // reusing old password
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_recently_used" {
		t.Fatalf("expected error=password_recently_used, got %q", result["error"])
	}
}

func TestResetConfirm_UpdatePasswordError(t *testing.T) {
	token := "update-error-token"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "reset:" + tokenHash

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, passwordHash string) error {
			return errors.New("db write error")
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-update-err", nil
			}
			return "", cache.ErrNotFound
		},
	}

	h := NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    token,
		"password": "aNewStrongPassword!123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ChangePassword edge cases
// ---------------------------------------------------------------------------

func TestChangePassword_InvalidJSON(t *testing.T) {
	h := newTestPasswordHandler(t, &mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{})

	req := httptest.NewRequest(http.MethodPost, "/user/password", strings.NewReader("not json"))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePassword_UserNotFound(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, nil // user not found
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": "oldPassword12345678",
		"new_password":     "newPassword12345678",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "nonexistent-user")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestChangePassword_UserRepoError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, errors.New("db error")
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": "oldPassword12345678",
		"new_password":     "newPassword12345678",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-err")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePassword_PasswordHistoryReject(t *testing.T) {
	currentPassword := "myCurrentP@ssw0rd!"
	newPassword := "reusedFromHistory!"
	currentHash, _ := vaultcrypto.HashPassword(currentPassword)
	reusedHash, _ := vaultcrypto.HashPassword(newPassword)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: currentHash,
			}, nil
		},
	}

	pwHistory := &mocks.MockPasswordHistoryRepo{
		GetRecentByUserFn: func(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error) {
			return []*model.PasswordHistory{
				{PasswordHash: reusedHash},
			}, nil
		},
	}

	h := newTestPasswordHandler(t, users, pwHistory)

	body := jsonBody(t, map[string]string{
		"current_password": currentPassword,
		"new_password":     newPassword,
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-hist")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_recently_used" {
		t.Fatalf("expected error=password_recently_used, got %q", result["error"])
	}
}

func TestChangePassword_UpdatePasswordError(t *testing.T) {
	currentPassword := "myCurrentP@ssw0rd!!"
	currentHash, _ := vaultcrypto.HashPassword(currentPassword)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: currentHash,
			}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, passwordHash string) error {
			return errors.New("db write error")
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": currentPassword,
		"new_password":     "brandNewPassword!xyz!",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-upd-err")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
