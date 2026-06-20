package unit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	pwTestMinLength = 15
	pwTestOrigin    = "https://vault.test"
	pwTestAppName   = "VaultTest"
)

// newPasswordHandler is a convenience factory that fills in sensible defaults
// for fields the test does not care about. Callers can override any mock field
// after construction by mutating the struct, but for most tests the mocks
// passed in are the only ones that matter.
func newPasswordHandler(
	users *mocks.MockUserRepo,
	pwHistory *mocks.MockPasswordHistoryRepo,
	tokens *mocks.MockRefreshTokenRepo,
	sender *mocks.MockEmailSender,
	c *mocks.MockCache,
) *handler.PasswordHandler {
	auditRepo := &mocks.MockAuditRepo{}
	auditLog := audit.NewLogger(auditRepo, 0)
	return handler.NewPasswordHandler(users, pwHistory, tokens, sender, auditLog, c, pwTestOrigin, pwTestAppName, "", pwTestMinLength, nil, false)
}

func jsonBody(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return bytes.NewBuffer(b)
}

// ---- TestResetRequest_Valid ----

func TestResetRequest_Valid(t *testing.T) {
	var emailSent atomic.Bool
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-abc", Email: email, PasswordHash: "$argon2id$v=19$m=47104,t=1,p=1$dummy$dummy"}, nil
		},
	}
	sender := &mocks.MockEmailSender{
		SendFn: func(_ context.Context, to, subject, _, _ string) error {
			emailSent.Store(true)
			if to != "user@example.com" {
				t.Errorf("expected email to user@example.com, got %q", to)
			}
			return nil
		},
	}
	c := &mocks.MockCache{
		SetFn: func(_ context.Context, key, value string, ttl time.Duration) error {
			if strings.HasPrefix(key, "reset:") {
				if value != "user-abc" {
					t.Errorf("expected cached user ID=user-abc, got %q", value)
				}
			} else if strings.HasPrefix(key, "pwreset_user:") {
				// Reverse mapping: pwreset_user:{userID} → tokenHash
				if key != "pwreset_user:user-abc" {
					t.Errorf("expected pwreset_user:user-abc, got %q", key)
				}
			} else {
				t.Errorf("unexpected cache key %q", key)
			}
			if ttl != time.Hour {
				t.Errorf("expected 1h TTL, got %v", ttl)
			}
			return nil
		},
	}

	h := newPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, sender, c)

	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetRequest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Email is sent asynchronously; wait briefly for the goroutine to complete.
	deadline := time.Now().Add(2 * time.Second)
	for !emailSent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !emailSent.Load() {
		t.Error("email was not sent")
	}
}

// ---- TestResetRequest_NonExistentEmail ----

func TestResetRequest_NonExistentEmail(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil // user not found
		},
	}

	h := newPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, &mocks.MockCache{})

	body := jsonBody(t, map[string]string{"email": "nobody@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetRequest(w, req)

	// Must still return 200 to prevent user enumeration
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (anti-enumeration), got %d: %s", w.Code, w.Body.String())
	}
}

// ---- TestResetConfirm_Valid ----

func TestResetConfirm_Valid(t *testing.T) {
	resetToken := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	tokenHash := vaultcrypto.SHA256Hex(resetToken)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		UpdatePasswordFn: func(_ context.Context, id, hash string) error {
			if id != "user-abc" {
				t.Errorf("expected user-abc, got %q", id)
			}
			return nil
		},
	}

	c := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if key == "reset:"+tokenHash {
				return "user-abc", nil
			}
			return "", nil
		},
	}

	h := newPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, c)

	body := jsonBody(t, map[string]string{
		"token":    resetToken,
		"password": "this-is-a-very-long-new-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetConfirm(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "password_reset_complete" {
		t.Errorf("expected status=password_reset_complete, got %v", resp["status"])
	}
}

// ---- TestResetConfirm_InvalidToken ----

func TestResetConfirm_InvalidToken(t *testing.T) {
	c := &mocks.MockCache{
		GetFn: func(_ context.Context, _ string) (string, error) {
			return "", nil // token not found / expired
		},
	}

	h := newPasswordHandler(&mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, c)

	body := jsonBody(t, map[string]string{
		"token":    "bad-token",
		"password": "this-is-a-very-long-new-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetConfirm(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_or_expired_token" {
		t.Errorf("expected error=invalid_or_expired_token, got %v", resp["error"])
	}
}

// ---- TestResetConfirm_ShortPassword ----

func TestResetConfirm_ShortPassword(t *testing.T) {
	// Cache does not even need to be checked; short password fails first
	c := &mocks.MockCache{}

	h := newPasswordHandler(&mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, c)

	body := jsonBody(t, map[string]string{
		"token":    "some-token",
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetConfirm(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "password_too_short" {
		t.Errorf("expected error=password_too_short, got %v", resp["error"])
	}
}

// ---- TestResetConfirm_PasswordReused ----

func TestResetConfirm_PasswordReused(t *testing.T) {
	reusedPassword := "this-is-a-reused-long-password"

	// Hash the reused password so VerifyPassword will match
	oldHash, err := vaultcrypto.HashPassword(reusedPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	resetToken := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	tokenHash := vaultcrypto.SHA256Hex(resetToken)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id}, nil
		},
	}

	pwHistory := &mocks.MockPasswordHistoryRepo{
		GetRecentByUserFn: func(_ context.Context, _ string, _ int) ([]*model.PasswordHistory, error) {
			return []*model.PasswordHistory{
				{ID: "ph-1", PasswordHash: oldHash},
			}, nil
		},
	}

	c := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if key == "reset:"+tokenHash {
				return "user-abc", nil
			}
			return "", nil
		},
	}

	h := newPasswordHandler(users, pwHistory, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, c)

	body := jsonBody(t, map[string]string{
		"token":    resetToken,
		"password": reusedPassword,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetConfirm(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "password_recently_used" {
		t.Errorf("expected error=password_recently_used, got %v", resp["error"])
	}
}

// ---- TestChangePassword_Valid ----

func TestChangePassword_Valid(t *testing.T) {
	currentPassword := "my-current-long-password"
	currentHash, err := vaultcrypto.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: currentHash}, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, _ string) error {
			return nil
		},
	}

	h := newPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, &mocks.MockCache{})

	_, _, keys, token := signedAuthContext(t)
	mux := http.NewServeMux()
	wrapped := middleware.Auth(keys, testIssuer, testAudience)(http.HandlerFunc(h.ChangePassword))
	mux.Handle("POST /user/password", wrapped)

	body := jsonBody(t, map[string]string{
		"current_password": currentPassword,
		"new_password":     "a-brand-new-secure-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "password_changed" {
		t.Errorf("expected status=password_changed, got %v", resp["status"])
	}
}

// ---- TestChangePassword_WrongCurrent ----

func TestChangePassword_WrongCurrent(t *testing.T) {
	// Hash a known password; the test will send a different one
	correctHash, err := vaultcrypto.HashPassword("correct-long-password-here")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: correctHash}, nil
		},
	}

	h := newPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{}, &mocks.MockCache{})

	_, _, keys, token := signedAuthContext(t)
	mux := http.NewServeMux()
	wrapped := middleware.Auth(keys, testIssuer, testAudience)(http.HandlerFunc(h.ChangePassword))
	mux.Handle("POST /user/password", wrapped)

	body := jsonBody(t, map[string]string{
		"current_password": "wrong-password-not-correct",
		"new_password":     "a-brand-new-secure-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_current_password" {
		t.Errorf("expected error=invalid_current_password, got %v", resp["error"])
	}
}
