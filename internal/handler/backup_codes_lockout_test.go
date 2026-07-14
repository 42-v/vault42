package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// backupCodeAuthService builds an AuthService with no cache, so the per-account lockout
// falls back to the failed-login counter on the user row.
func backupCodeAuthService(t *testing.T, users *mocks.MockUserRepo) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, newTestAuditLogger(),
		nil, nil, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// A backup code is 16 hex characters. The per-IP rate limit alone does not protect it,
// because an attacker rotating IPs simply pays nothing for the limit — which is exactly
// why the per-account lockout exists and is shared with the password and TOTP failure
// counters.
//
// A locked account must be refused before the codes are even fetched. If this gate ever
// fell through, backup codes would be brute-forceable in the challenge window from a pool
// of addresses, and each guess would look like a fresh, unremarkable request.
func TestBackupCodeVerify_LockedAccountIsRefusedBeforeAnyCodeIsChecked(t *testing.T) {
	fetched := false
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(context.Context, string) ([]*model.BackupCode, error) {
			fetched = true
			return nil, nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			// Well past the lockout threshold.
			return &model.User{ID: id, Email: "user@example.com", FailedLoginCount: 99}, nil
		},
	}

	h := NewBackupCodeHandler(repo, []byte("hmac-key"), backupCodeAuthService(t, users), false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes/verify",
		jsonBody(t, map[string]string{"code": "0123456789abcdef"}))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 — a locked account was allowed to keep guessing backup codes", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "account_locked") {
		t.Errorf("body = %s, want account_locked", body)
	}
	if fetched {
		t.Error("the backup codes were fetched for a locked account")
	}
}

// A wrong code is refused and routed through the shared MFA-failure recorder, which is what
// feeds the lockout gate above. The code that was guessed must never be echoed back, and no
// code may be consumed on a failed attempt — otherwise an attacker could burn a victim's
// backup codes simply by guessing at them.
func TestBackupCodeVerify_WrongCodeIsRefusedAndConsumesNothing(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(context.Context, string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{{ID: "bc-1", UserID: "user-1", CodeHash: "not-the-hash-of-the-guess"}}, nil
		},
	}
	consumed := false
	repo.MarkUsedFn = func(context.Context, string) (bool, error) {
		consumed = true
		return true, nil
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", FailedLoginCount: 0}, nil
		},
	}

	h := NewBackupCodeHandler(repo, []byte("hmac-key"), backupCodeAuthService(t, users), false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes/verify",
		jsonBody(t, map[string]string{"code": "0123456789abcdef"}))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "invalid_backup_code") {
		t.Errorf("body = %s, want invalid_backup_code", body)
	}
	if consumed {
		t.Error("a failed guess consumed one of the user's backup codes — an attacker could burn them all by guessing")
	}
}
