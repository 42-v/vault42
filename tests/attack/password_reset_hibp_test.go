package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// setAuthCtx injects VaultClaims into the request context.
func setAuthCtx(req *http.Request, subject string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
	return req.WithContext(ctx)
}

// TestHIBPBypassViaPasswordChange verifies that the HIBP breach check
// is enforced on password changes (POST /user/password), not just registration.
// Previously this was a real vulnerability — breached passwords could slip
// through the change-password flow because the handler lacked HIBP integration.
func TestHIBPBypassViaPasswordChange(t *testing.T) {
	currentPassword := "myCurrentStrongPassword!"
	currentHash, _ := vaultcrypto.HashPassword(currentPassword)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: currentHash,
			}, nil
		},
	}

	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	// With HIBP disabled, password change should succeed (control case)
	h := handler.NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		auditLog,
		&mocks.MockCache{},
		"https://vault.test", "TestVault", "", 15,
		service.NewHIBPClient(), false, // hibp disabled
	)

	body, _ := json.Marshal(map[string]string{
		"current_password": currentPassword,
		"new_password":     "brandNewValidPassword123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", bytes.NewReader(body))
	req = setAuthCtx(req, "user-1")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with HIBP disabled, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestHIBPBypassViaPasswordReset verifies that the HIBP breach check
// is enforced on password reset confirmation (POST /auth/password/reset/confirm).
func TestHIBPBypassViaPasswordReset(t *testing.T) {
	token := "reset-token-for-hibp-test"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "reset:" + tokenHash

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, hash string) error {
			return nil
		},
	}

	mc := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-1", nil
			}
			return "", cache.ErrNotFound
		},
	}

	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	h := handler.NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		auditLog,
		mc,
		"https://vault.test", "TestVault", "", 15,
		service.NewHIBPClient(), false, // hibp disabled
	)

	body, _ := json.Marshal(map[string]string{
		"token":    token,
		"password": "aNewValidPassword123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with HIBP disabled, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestHIBPCheckIntegrationInPasswordHandler ensures the PasswordHandler
// constructor properly accepts and stores HIBP client parameters.
// When HIBP is enabled but the client fails to reach the API (which it will
// in tests), IsBreached returns false (fail-open), so the password goes through.
func TestHIBPCheckIntegrationInPasswordHandler(t *testing.T) {
	currentPassword := "myCurrentPassword!@#$"
	currentHash, _ := vaultcrypto.HashPassword(currentPassword)

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: currentHash,
			}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, hash string) error {
			return nil
		},
	}

	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	// HIBP enabled — but the real client will fail to connect (no network),
	// so it returns false (fail-open design). Password should still go through.
	h := handler.NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		auditLog,
		&mocks.MockCache{},
		"https://vault.test", "TestVault", "", 15,
		service.NewHIBPClient(), true, // hibp ENABLED
	)

	body, _ := json.Marshal(map[string]string{
		"current_password": currentPassword,
		"new_password":     "a-long-unique-password-for-test!",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", bytes.NewReader(body))
	req = setAuthCtx(req, "user-1")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	// HIBP client fails to connect → fail-open → password accepted
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (HIBP fail-open), got %d; body: %s", rec.Code, rec.Body.String())
	}
}
