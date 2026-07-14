package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Account deletion re-confirms the password before it does anything. If the user lookup
// itself fails, the handler must not fall through to the erasure with an unverified
// caller — a database blip would otherwise become "delete this account, no password
// required".
func TestAccountDelete_UserLookupFailureDoesNotErase(t *testing.T) {
	erased := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) {
			return nil, errors.New("db down")
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			erased = true
			return nil
		},
	}
	h := newTestAccountHandler(users)

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "whatever"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if erased {
		t.Fatal("the account was erased even though the password could never be verified")
	}
}

// The erasure cascade failing is a 500 the user retries, not a 200. Reporting success
// here is the single worst bug this endpoint can have: the user is told their data is
// gone, they stop asking, and it is all still there.
func TestAccountDelete_ErasureFailureIsNotReportedAsDeleted(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correctP@ssw0rd!")
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", PasswordHash: hash}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			return errors.New("db down")
		},
	}
	h := newTestAccountHandler(users)

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "correctP@ssw0rd!"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a failed erasure must not read as 'deleted'", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "deleted") {
		t.Error("the response claims the account was deleted after the cascade failed")
	}
}

// An account that is already gone is a 404, not a 500: the caller asked to delete
// something that does not exist, which is a different answer from "we tried and broke".
func TestAccountDelete_MissingAccountIs404(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correctP@ssw0rd!")
	calls := 0
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			calls++
			if calls == 1 {
				// The handler's own password re-confirmation still sees the user.
				return &model.User{ID: id, Email: "user@example.com", PasswordHash: hash}, nil
			}
			// By the time the erasure service loads it, the row is gone.
			return nil, nil
		},
	}
	h := newTestAccountHandler(users)

	req := httptest.NewRequest(http.MethodDelete, "/user/account",
		jsonBody(t, map[string]string{"password": "correctP@ssw0rd!"}))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an account that no longer exists", rec.Code)
	}
}
