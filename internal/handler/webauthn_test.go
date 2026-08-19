package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// WebAuthnHandler helpers
// ---------------------------------------------------------------------------

func newWebAuthnHandler(wan *webauthn.WebAuthn, webauthnRepo *mocks.MockWebAuthnRepo, userRepo *mocks.MockUserRepo, cache *mocks.MockCache) *WebAuthnHandler {
	if webauthnRepo == nil {
		webauthnRepo = &mocks.MockWebAuthnRepo{}
	}
	if userRepo == nil {
		userRepo = &mocks.MockUserRepo{}
	}
	if cache == nil {
		cache = &mocks.MockCache{}
	}
	return NewWebAuthnHandler(webauthnRepo, userRepo, cache, wan, nil, false)
}

// ---------------------------------------------------------------------------
// nil WebAuthn (501 responses) tests
// ---------------------------------------------------------------------------

func TestWebAuthn_NotConfigured(t *testing.T) {
	h := newWebAuthnHandler(nil, nil, nil, nil)

	tests := []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"RegisterBegin", "/auth/2fa/webauthn/register/begin", h.RegisterBegin},
		{"RegisterFinish", "/auth/2fa/webauthn/register/finish", h.RegisterFinish},
		{"VerifyBegin", "/auth/2fa/webauthn/verify/begin", h.VerifyBegin},
		{"VerifyFinish", "/auth/2fa/webauthn/verify/finish", h.VerifyFinish},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req = setAuthContext(req, "user-123")
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("expected 501, got %d; body: %s", rec.Code, rec.Body.String())
			}

			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != "webauthn_not_configured" {
				t.Fatalf("expected error=webauthn_not_configured, got %q", result["error"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unauthorized (no claims) tests
// ---------------------------------------------------------------------------

func TestWebAuthn_Unauthorized(t *testing.T) {
	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, nil, nil)

	tests := []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"RegisterBegin", "/auth/2fa/webauthn/register/begin", h.RegisterBegin},
		{"RegisterFinish", "/auth/2fa/webauthn/register/finish", h.RegisterFinish},
		{"VerifyBegin", "/auth/2fa/webauthn/verify/begin", h.VerifyBegin},
		{"VerifyFinish", "/auth/2fa/webauthn/verify/finish", h.VerifyFinish},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			// No auth context
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
			}

			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != "unauthorized" {
				t.Fatalf("expected error=unauthorized, got %q", result["error"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// User not found tests
// ---------------------------------------------------------------------------

func TestWebAuthn_UserNotFound(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, nil
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, nil)

	tests := []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"RegisterBegin", "/auth/2fa/webauthn/register/begin", h.RegisterBegin},
		{"RegisterFinish", "/auth/2fa/webauthn/register/finish", h.RegisterFinish},
		{"VerifyBegin", "/auth/2fa/webauthn/verify/begin", h.VerifyBegin},
		{"VerifyFinish", "/auth/2fa/webauthn/verify/finish", h.VerifyFinish},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req = setAuthContext(req, "user-missing")
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
			}

			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != "unauthorized" {
				t.Fatalf("expected error=unauthorized, got %q", result["error"])
			}
		})
	}
}

func TestWebAuthn_RegisterBegin_UserRepoError(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, errors.New("db error")
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
	req = setAuthContext(req, "user-err")
	rec := httptest.NewRecorder()

	h.RegisterBegin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RegisterFinish: no pending registration in cache
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_NoPendingRegistration(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	cache := &mocks.MockCache{} // returns ErrNotFound by default

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, cache)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "no_pending_registration" {
		t.Fatalf("expected error=no_pending_registration, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// VerifyBegin: no credentials
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyBegin_NoCredentials(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	webauthnRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return nil, nil // no credentials
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, webauthnRepo, userRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.VerifyBegin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "no_webauthn_credentials" {
		t.Fatalf("expected error=no_webauthn_credentials, got %q", result["error"])
	}
}

func TestWebAuthn_VerifyBegin_ListByUserError(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	webauthnRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return nil, errors.New("db error")
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, webauthnRepo, userRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.VerifyBegin(rec, req)

	// A failed credential lookup is an internal fault, not a fact about the
	// account. Reporting it as no_webauthn_credentials tells a user mid-login
	// their passkey is gone when the database merely hiccuped, and a client that
	// trusts that answer drops to a weaker listed factor. Every other internal
	// failure in this handler returns 500; this one must too, and must not emit
	// the definitive "no credentials" claim it cannot stand behind.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on credential lookup error, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] == "no_webauthn_credentials" {
		t.Errorf("a database error was reported as no_webauthn_credentials, masking a transient fault as a definitive absence of the factor")
	}
}

// ---------------------------------------------------------------------------
// VerifyFinish: no pending verification
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_NoPendingVerification(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	cache := &mocks.MockCache{} // returns ErrNotFound by default

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, cache)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "no_pending_verification" {
		t.Fatalf("expected error=no_pending_verification, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// RegisterFinish: invalid cached session data
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_InvalidSessionData(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "not-valid-json{{{", nil
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, cache)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestWebAuthn_VerifyFinish_InvalidSessionData(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "{invalid-json}", nil
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, cache)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// modelCredsToWebAuthn tests
// ---------------------------------------------------------------------------

func TestModelCredsToWebAuthn_Empty(t *testing.T) {
	result := modelCredsToWebAuthn(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0 credentials, got %d", len(result))
	}
}

func TestModelCredsToWebAuthn_Multiple(t *testing.T) {
	creds := []*model.WebAuthnCredential{
		{
			ID:           "cred-1",
			UserID:       "user-1",
			CredentialID: []byte("cred-id-1"),
			PublicKey:    []byte("pubkey-1"),
			SignCount:    5,
		},
		{
			ID:           "cred-2",
			UserID:       "user-1",
			CredentialID: []byte("cred-id-2"),
			PublicKey:    []byte("pubkey-2"),
			SignCount:    10,
		},
	}

	result := modelCredsToWebAuthn(creds)
	if len(result) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(result))
	}
	if string(result[0].ID) != "cred-id-1" {
		t.Fatalf("expected credential ID = cred-id-1, got %q", string(result[0].ID))
	}
	if string(result[1].PublicKey) != "pubkey-2" {
		t.Fatalf("expected public key = pubkey-2, got %q", string(result[1].PublicKey))
	}
	if result[0].Authenticator.SignCount != 5 {
		t.Fatalf("expected sign count 5, got %d", result[0].Authenticator.SignCount)
	}
	if result[1].Authenticator.SignCount != 10 {
		t.Fatalf("expected sign count 10, got %d", result[1].Authenticator.SignCount)
	}
}

func TestModelCredsToWebAuthn_SingleCredential(t *testing.T) {
	creds := []*model.WebAuthnCredential{
		{
			ID:           "cred-only",
			UserID:       "user-1",
			CredentialID: []byte("the-cred-id"),
			PublicKey:    []byte("the-pubkey"),
			SignCount:    42,
		},
	}

	result := modelCredsToWebAuthn(creds)
	if len(result) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(result))
	}
	if result[0].Authenticator.SignCount != 42 {
		t.Fatalf("expected sign count 42, got %d", result[0].Authenticator.SignCount)
	}
}

func TestModelCredsToWebAuthn_ZeroSignCount(t *testing.T) {
	creds := []*model.WebAuthnCredential{
		{
			CredentialID: []byte("new-cred"),
			PublicKey:    []byte("pk"),
			SignCount:    0,
		},
	}

	result := modelCredsToWebAuthn(creds)
	if result[0].Authenticator.SignCount != 0 {
		t.Fatalf("expected sign count 0, got %d", result[0].Authenticator.SignCount)
	}
}
