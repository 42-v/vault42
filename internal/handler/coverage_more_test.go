package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// UpdateProfile error and success branches (PUT /user/profile)
// ---------------------------------------------------------------------------

func TestUpdateProfile_UserNotFound(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil // user no longer exists
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPut, "/user/profile", jsonBody(t, map[string]string{"display_name": "Alice"}))
	req = setAuthContext(req, "ghost-user")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateProfile_InvalidJSON(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "alice@example.com"}, nil
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPut, "/user/profile", strings.NewReader("{not json"))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateProfile_UpdateError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "alice@example.com"}, nil
		},
		UpdateFn: func(_ context.Context, _ *model.User) error {
			return errors.New("db write failed")
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPut, "/user/profile", jsonBody(t, map[string]string{"display_name": "Alice"}))
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	var updated bool
	locale := "sk"
	avatar := "https://example.com/a.png"
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "alice@example.com"}, nil
		},
		UpdateFn: func(_ context.Context, _ *model.User) error {
			updated = true
			return nil
		},
	}
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"display_name": "Alice", "locale": locale, "avatar_url": avatar})
	req := httptest.NewRequest(http.MethodPut, "/user/profile", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !updated {
		t.Fatal("expected Update to have been called")
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["locale"] != "sk" {
		t.Fatalf("expected locale=sk in response, got %v", result["locale"])
	}
}

// ---------------------------------------------------------------------------
// TOTP Disable error branches (DELETE /auth/2fa/totp)
// ---------------------------------------------------------------------------

func newTestTOTPHandler(repo *mocks.MockTOTPRepo) *TOTPHandler {
	return NewTOTPHandler(repo, identityMasterKey(), "vault-test", &mocks.MockCache{}, nil, false)
}

func TestTOTPDisable_NotSetup(t *testing.T) {
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return nil, nil // no TOTP configured
		},
	}
	h := newTestTOTPHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Disable(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "totp_not_setup" {
		t.Fatalf("expected error=totp_not_setup, got %q", result["error"])
	}
}

func TestTOTPDisable_DeleteError(t *testing.T) {
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true}, nil
		},
		DeleteByUserIDFn: func(_ context.Context, _ string) error {
			return errors.New("db delete failed")
		},
	}
	h := newTestTOTPHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Disable(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPDisable_Success(t *testing.T) {
	var deleted bool
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true}, nil
		},
		DeleteByUserIDFn: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}
	h := newTestTOTPHandler(repo)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Disable(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !deleted {
		t.Fatal("expected DeleteByUserID to have been called")
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "totp_disabled" {
		t.Fatalf("expected status=totp_disabled, got %q", result["status"])
	}
}

// ---------------------------------------------------------------------------
// WebAuthn DeleteCredential error and success branches
// ---------------------------------------------------------------------------

func TestWebAuthnDeleteCredential_MissingID(t *testing.T) {
	h := newWebAuthnHandler(nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/", nil)
	req = setAuthContext(req, "user-1")
	// No path value set -> r.PathValue("id") returns ""
	rec := httptest.NewRecorder()

	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_credential_id" {
		t.Fatalf("expected error=missing_credential_id, got %q", result["error"])
	}
}

func TestWebAuthnDeleteCredential_ListError(t *testing.T) {
	repo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return nil, errors.New("db error")
		},
	}
	h := newWebAuthnHandler(nil, repo, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil)
	req = setAuthContext(req, "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()

	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestWebAuthnDeleteCredential_NotFound(t *testing.T) {
	repo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "other-cred", UserID: userID}}, nil
		},
	}
	h := newWebAuthnHandler(nil, repo, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil)
	req = setAuthContext(req, "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()

	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "credential_not_found" {
		t.Fatalf("expected error=credential_not_found, got %q", result["error"])
	}
}

func TestWebAuthnDeleteCredential_DeleteError(t *testing.T) {
	repo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-1", UserID: userID}}, nil
		},
		DeleteFn: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	h := newWebAuthnHandler(nil, repo, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil)
	req = setAuthContext(req, "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()

	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestWebAuthnDeleteCredential_Success(t *testing.T) {
	var deleted bool
	repo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-1", UserID: userID}}, nil
		},
		DeleteFn: func(_ context.Context, _, _ string) error {
			deleted = true
			return nil
		},
	}
	h := newWebAuthnHandler(nil, repo, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil)
	req = setAuthContext(req, "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()

	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !deleted {
		t.Fatal("expected Delete to have been called")
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "credential_removed" {
		t.Fatalf("expected status=credential_removed, got %q", result["status"])
	}
}

// ---------------------------------------------------------------------------
// MFA Status error branch (GET /auth/2fa/status)
// ---------------------------------------------------------------------------

func TestMFAStatus_Unauthorized(t *testing.T) {
	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)
	h := NewMFAHandler(mfaSvc)

	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
	// No auth context.
	rec := httptest.NewRecorder()

	h.Status(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Identity Put service-rejected branch (PUT /user/identity -> 400)
// ---------------------------------------------------------------------------

func TestIdentityPut_ServiceRejectsProfile(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			return service.ErrInvalidProfile
		},
	}
	h := newTestIdentityHandler(repo)

	body := jsonBody(t, map[string]string{"username": "this-username-violates-service-rules"})
	req := httptest.NewRequest(http.MethodPut, "/user/identity", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_profile" {
		t.Fatalf("expected error=invalid_profile, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// Capabilities handler (GET /auth/capabilities)
// ---------------------------------------------------------------------------

func TestCapabilities_ReportsConfiguredFlags(t *testing.T) {
	h := Capabilities(true, false, []string{"google", "github"})

	req := httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil)
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		RegistrationEnabled bool     `json:"registration_enabled"`
		MFARequired         bool     `json:"mfa_required"`
		OAuthProviders      []string `json:"oauth_providers"`
	}
	decodeResponse(t, rec, &result)
	if !result.RegistrationEnabled {
		t.Fatal("expected registration_enabled=true")
	}
	if result.MFARequired {
		t.Fatal("expected mfa_required=false")
	}
	if len(result.OAuthProviders) != 2 {
		t.Fatalf("expected 2 oauth providers, got %d", len(result.OAuthProviders))
	}
}

func TestCapabilities_NilProvidersBecomesEmptyArray(t *testing.T) {
	h := Capabilities(false, true, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil)
	rec := httptest.NewRecorder()

	h(rec, req)

	// A nil provider slice must serialize as [] (not null) so clients can iterate.
	if !strings.Contains(rec.Body.String(), `"oauth_providers":[]`) {
		t.Fatalf("expected oauth_providers to be an empty array, got body: %s", rec.Body.String())
	}
}
