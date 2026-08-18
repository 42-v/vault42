package unit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// --- ConfirmPassword -----------------------------------------------------

func TestConfirmPassword_EmptyBody_BadRequest(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: testUserID, PasswordHash: "ignored"}, nil
		},
	}
	c := &mocks.MockCache{}
	h := handler.NewAuthHandler(nil, users, c, nil, "pepper", false, nil)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/confirm-password", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(`{}`)}
	serveWithAuth(t, "POST /auth/confirm-password", h.ConfirmPassword, keys, w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 password_required, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConfirmPassword_UserNotFound_Unauthorized(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
	}
	h := handler.NewAuthHandler(nil, users, &mocks.MockCache{}, nil, "pepper", false, nil)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/confirm-password", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(`{"password":"hunter2"}`)}
	serveWithAuth(t, "POST /auth/confirm-password", h.ConfirmPassword, keys, w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

// --- UpdateProfile -------------------------------------------------------

func TestUpdateProfile_UserNotFound_Unauthorized(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
	}
	h := handler.NewUserHandler(users, nil, nil, nil)

	req, w, keys := authedRequest(t, http.MethodPut, "/user/profile", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(`{}`)}
	serveWithAuth(t, "PUT /user/profile", h.UpdateProfile, keys, w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user lookup returns nil, got %d", w.Code)
	}
}

func TestUpdateProfile_BadJSON_BadRequest(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: testUserID}, nil
		},
	}
	h := handler.NewUserHandler(users, nil, nil, nil)

	req, w, keys := authedRequest(t, http.MethodPut, "/user/profile", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(`not json`)}
	serveWithAuth(t, "PUT /user/profile", h.UpdateProfile, keys, w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- WebAuthn DeleteCredential ------------------------------------------

func TestWebAuthnDeleteCredential_MissingID_BadRequest(t *testing.T) {
	wa := &mocks.MockWebAuthnRepo{}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodDelete, "/auth/2fa/webauthn/credentials/", nil)
	serveWithAuth(t, "DELETE /auth/2fa/webauthn/credentials/{id}", h.DeleteCredential, keys, w, req)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Fatalf("expected 400 or 404, got %d", w.Code)
	}
}

func TestWebAuthnDeleteCredential_NotFound(t *testing.T) {
	wa := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{}, nil
		},
	}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodDelete, "/auth/2fa/webauthn/credentials/abc", nil)
	serveWithAuth(t, "DELETE /auth/2fa/webauthn/credentials/{id}", h.DeleteCredential, keys, w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWebAuthnDeleteCredential_RepoError(t *testing.T) {
	wa := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return nil, errors.New("db boom")
		},
	}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodDelete, "/auth/2fa/webauthn/credentials/abc", nil)
	serveWithAuth(t, "DELETE /auth/2fa/webauthn/credentials/{id}", h.DeleteCredential, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestWebAuthnDeleteCredential_Success(t *testing.T) {
	cid := "cred-1"
	wa := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: cid}}, nil
		},
		DeleteFn: func(_ context.Context, id, _ string) error {
			if id != cid {
				return errors.New("wrong id")
			}
			return nil
		},
	}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodDelete, "/auth/2fa/webauthn/credentials/"+cid, nil)
	serveWithAuth(t, "DELETE /auth/2fa/webauthn/credentials/{id}", h.DeleteCredential, keys, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWebAuthnListCredentials_Success(t *testing.T) {
	wa := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "a", SignCount: 1}, {ID: "b", SignCount: 5}}, nil
		},
	}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodGet, "/auth/2fa/webauthn/credentials", nil)
	serveWithAuth(t, "GET /auth/2fa/webauthn/credentials", h.ListCredentials, keys, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestWebAuthnListCredentials_NoClaims401(t *testing.T) {
	h := &handler.WebAuthnHandler{}
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/webauthn/credentials", nil)
	rec := httptest.NewRecorder()
	h.ListCredentials(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWebAuthnListCredentials_RepoError(t *testing.T) {
	wa := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return nil, errors.New("db boom")
		},
	}
	h := handler.NewWebAuthnHandler(wa, nil, nil, nil, nil, false)
	req, w, keys := authedRequest(t, http.MethodGet, "/auth/2fa/webauthn/credentials", nil)
	serveWithAuth(t, "GET /auth/2fa/webauthn/credentials", h.ListCredentials, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// --- TOTP Disable ---------------------------------------------------------

func TestTOTPDisable_NotSetup_NotFound(t *testing.T) {
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return nil, nil
		},
	}
	h := handler.NewTOTPHandler(repo, testMasterKey(), testIssuer, &mocks.MockCache{}, nil, false)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/totp/disable", nil)
	serveWithAuth(t, "POST /auth/2fa/totp/disable", h.Disable, keys, w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 totp_not_setup, got %d", w.Code)
	}
}

func TestTOTPDisable_DeleteError_Internal(t *testing.T) {
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{UserID: testUserID}, nil
		},
		DeleteByUserIDFn: func(_ context.Context, _ string) error { return errors.New("boom") },
	}
	h := handler.NewTOTPHandler(repo, testMasterKey(), testIssuer, &mocks.MockCache{}, nil, false)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/totp/disable", nil)
	serveWithAuth(t, "POST /auth/2fa/totp/disable", h.Disable, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestTOTPDisable_Success(t *testing.T) {
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{UserID: testUserID}, nil
		},
		DeleteByUserIDFn: func(_ context.Context, _ string) error { return nil },
	}
	h := handler.NewTOTPHandler(repo, testMasterKey(), testIssuer, &mocks.MockCache{}, nil, false)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/totp/disable", nil)
	serveWithAuth(t, "POST /auth/2fa/totp/disable", h.Disable, keys, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// compile-time assertions that mock types satisfy real interfaces — fails
// the test build loudly if anyone breaks the contract in a future refactor.
var (
	_ repository.UserRepository     = (*mocks.MockUserRepo)(nil)
	_ repository.WebAuthnRepository = (*mocks.MockWebAuthnRepo)(nil)
	_ repository.TOTPRepository     = (*mocks.MockTOTPRepo)(nil)
)
