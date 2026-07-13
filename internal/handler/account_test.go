package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func newTestAccountHandler(users *mocks.MockUserRepo) *AccountHandler {
	erasure := service.NewErasureService(
		users, &mocks.MockIdentityRepo{}, &mocks.MockBlobRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockSocialAccountRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{},
		&mocks.MockAccountRecoveryRepo{}, newTestAuditLogger(), nil, nil,
	)
	return NewAccountHandler(erasure, users, newTestAuditLogger(), "")
}

func TestAccountDelete_Success(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correctP@ssw0rd!")
	scrubbed := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", PasswordHash: hash}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			scrubbed = true
			return nil
		},
	}
	h := newTestAccountHandler(users)

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "correctP@ssw0rd!"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !scrubbed {
		t.Error("expected account to be scrubbed/soft-deleted")
	}
}

func TestAccountDelete_Unauthenticated(t *testing.T) {
	h := newTestAccountHandler(&mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "whatever"}))
	// No auth context set.
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAccountDelete_WrongPassword(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("realP@ssw0rd!!!")
	scrubbed := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", PasswordHash: hash}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			scrubbed = true
			return nil
		},
	}
	h := newTestAccountHandler(users)

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "wrongPassword999"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if scrubbed {
		t.Error("account must not be deleted on wrong password")
	}
}

func TestAccountDelete_MissingPassword(t *testing.T) {
	h := newTestAccountHandler(&mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
