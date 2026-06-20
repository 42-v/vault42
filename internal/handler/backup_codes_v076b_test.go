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
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// setChallengeContext sets a 2fa_challenge VaultClaims so completeMFAIfChallenge runs.
func setChallengeContext(req *http.Request, subject, jti string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		TokenType:        "2fa_challenge",
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject, ID: jti},
	}
	ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
	return req.WithContext(ctx)
}

// backupHMACKey is the fixed HMAC key used to derive code hashes in these tests.
var backupHMACKey = []byte("backup-test-hmac-key")

// makeBackupCode returns a stored code whose hash matches the given plaintext.
func makeBackupCode(id, code string) *model.BackupCode {
	return &model.BackupCode{ID: id, CodeHash: vaultcrypto.HMACSign([]byte(code), backupHMACKey)}
}

func TestBackupCodeVerify_Unauthorized(t *testing.T) {
	h := NewBackupCodeHandler(&mocks.MockBackupCodeRepo{}, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"x"}`))
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBackupCodeVerify_MissingCode(t *testing.T) {
	h := NewBackupCodeHandler(&mocks.MockBackupCodeRepo{}, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestBackupCodeVerify_ListError(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return nil, errors.New("db down")
		},
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"abc"}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestBackupCodeVerify_NoMatch(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "right-code")}, nil
		},
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"wrong-code"}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_backup_code" {
		t.Errorf("expected invalid_backup_code, got %v", result["error"])
	}
}

func TestBackupCodeVerify_MarkUsedError(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("update failed")
		},
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestBackupCodeVerify_AlreadyUsed(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil // CAS lost the race
		},
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

// Non-challenge token: a verified backup code returns a plain verified response.
func TestBackupCodeVerify_SuccessNoChallenge(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["verified"] != true {
		t.Errorf("expected verified=true, got %v", result["verified"])
	}
}

// newChallengeAuthService builds an AuthService whose CompleteMFALogin succeeds.
func newChallengeAuthService(t *testing.T, cache *mocks.MockCache) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Roles: []string{"user"}}, nil
		},
	}
	return service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, newTestAuditLogger(), nil, cache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// Challenge token + verified backup code completes MFA login and sets a cookie.
func TestBackupCodeVerify_CompletesChallenge(t *testing.T) {
	authSvc := newChallengeAuthService(t, &mocks.MockCache{})
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) { return true, nil },
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, authSvc, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setChallengeContext(req, "user-1", "jti-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Error("challenge completion should issue an access token")
	}
}

// A re-used challenge token surfaces as 401 challenge_consumed.
func TestBackupCodeVerify_ChallengeConsumed(t *testing.T) {
	mc := &mocks.MockCache{
		SetIfNotExistsFn: func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
			return false, nil // single-use challenge key already present
		},
	}
	authSvc := newChallengeAuthService(t, mc)
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) { return true, nil },
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, authSvc, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setChallengeContext(req, "user-1", "jti-dup")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 challenge_consumed, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Hitting the session cap during challenge completion yields 429.
func TestBackupCodeVerify_ChallengeTooManySessions(t *testing.T) {
	mc := &mocks.MockCache{}
	tokenSvc, _ := newTestTokenService(t)
	tokenRepo := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(_ context.Context, _ string) (int, error) { return 9, nil },
	}
	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Roles: []string{"user"}}, nil
			},
		},
		tokenRepo, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, newTestAuditLogger(), nil, mc, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	authSvc.SetMaxSessionsPerUser(1)

	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{makeBackupCode("bc-1", "the-code")}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) { return true, nil },
	}
	h := NewBackupCodeHandler(repo, backupHMACKey, authSvc, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", strings.NewReader(`{"code":"the-code"}`))
	req = setChallengeContext(req, "user-1", "jti-cap")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 too_many_sessions, got %d: %s", rec.Code, rec.Body.String())
	}
}
