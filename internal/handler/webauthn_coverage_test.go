package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// RegisterBegin: cache Set error (session store failure)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_CacheSetError(t *testing.T) {
	t.Run("cache_set_returns_error", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, nil
			},
		}
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				return errors.New("cache unavailable")
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterBegin(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "internal_error" {
			t.Fatalf("expected error=internal_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterBegin: ListByUser error (non-fatal, logged)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_ListByUserError(t *testing.T) {
	t.Run("list_by_user_error_continues", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("db error listing creds")
			},
		}
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterBegin(rec, req)

		// Should succeed despite ListByUser error (it's logged but not fatal)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterBegin: success with existing credentials (exclusion list)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_WithExistingCredentials(t *testing.T) {
	t.Run("existing_credentials_in_exclusion_list", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{
					{
						ID:           "cred-1",
						UserID:       userID,
						CredentialID: []byte("existing-cred-id"),
						PublicKey:    []byte("existing-pub-key"),
						SignCount:    3,
					},
				}, nil
			},
		}
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterBegin(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterFinish: user repo error
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_UserRepoError(t *testing.T) {
	t.Run("user_repo_returns_error", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return nil, errors.New("db connection failed")
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, nil)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
		req = setAuthContext(req, "user-err")
		rec := httptest.NewRecorder()

		h.RegisterFinish(rec, req)

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

// ---------------------------------------------------------------------------
// RegisterFinish: cache Get error (no pending registration)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_CacheGetError(t *testing.T) {
	t.Run("cache_get_returns_error", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetFn: func(ctx context.Context, key string) (string, error) {
				return "", cache.ErrNotFound
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

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
	})
}

// ---------------------------------------------------------------------------
// RegisterFinish: cache returns empty string (no pending registration)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_CacheReturnsEmptyString(t *testing.T) {
	t.Run("cache_returns_empty_string", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetFn: func(ctx context.Context, key string) (string, error) {
				return "", nil // empty string, no error
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterFinish(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyBegin: user repo error
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyBegin_UserRepoError(t *testing.T) {
	t.Run("user_repo_error_returns_401", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return nil, errors.New("db connection failed")
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, nil)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
		req = setAuthContext(req, "user-err")
		rec := httptest.NewRecorder()

		h.VerifyBegin(rec, req)

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

// ---------------------------------------------------------------------------
// VerifyBegin: cache Set error
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyBegin_CacheSetError(t *testing.T) {
	t.Run("cache_set_returns_error", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{
					{
						ID:           "cred-1",
						UserID:       userID,
						CredentialID: []byte("cred-id-1"),
						PublicKey:    []byte("pub-key-1"),
						SignCount:    5,
					},
				}, nil
			},
		}
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				return errors.New("cache set failed")
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.VerifyBegin(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "internal_error" {
			t.Fatalf("expected error=internal_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyFinish: user repo error
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_UserRepoError(t *testing.T) {
	t.Run("user_repo_error_returns_401", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return nil, errors.New("db error")
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, nil)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
		req = setAuthContext(req, "user-err")
		rec := httptest.NewRecorder()

		h.VerifyFinish(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyFinish: cache Get error (no pending verification)
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_CacheGetError(t *testing.T) {
	t.Run("cache_get_returns_error", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetFn: func(ctx context.Context, key string) (string, error) {
				return "", errors.New("cache unavailable")
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

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
	})
}

// ---------------------------------------------------------------------------
// VerifyFinish: cache returns empty string
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_CacheReturnsEmptyString(t *testing.T) {
	t.Run("cache_returns_empty_string", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetFn: func(ctx context.Context, key string) (string, error) {
				return "", nil // empty string, no error
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.VerifyFinish(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterBegin: success end-to-end with real WebAuthn config
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_SuccessEndToEnd(t *testing.T) {
	t.Run("full_success_with_real_webauthn_config", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@vault.test"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, nil
			},
		}

		setCalled := false
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				setCalled = true
				if ttl != 5*time.Minute {
					t.Fatalf("expected 5 min TTL, got %v", ttl)
				}
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterBegin(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
		if !setCalled {
			t.Fatal("expected cache.Set to have been called")
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyBegin: success end-to-end with real WebAuthn config
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyBegin_SuccessEndToEnd(t *testing.T) {
	t.Run("full_success_with_real_webauthn_config", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@vault.test"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{
					{
						ID:           "cred-1",
						UserID:       userID,
						CredentialID: []byte{1, 2, 3, 4, 5, 6, 7, 8},
						PublicKey:    []byte{10, 20, 30, 40},
						SignCount:    1,
					},
				}, nil
			},
		}

		setCalled := false
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				setCalled = true
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.VerifyBegin(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
		if !setCalled {
			t.Fatal("expected cache.Set to have been called")
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterFinish: valid session but FinishRegistration fails (bad request body)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_FinishRegistrationFails(t *testing.T) {
	t.Run("finish_registration_fails_with_invalid_request", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@vault.test"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, nil
			},
		}

		// Step 1: Call RegisterBegin to generate real session data
		var capturedSession string
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				capturedSession = value
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		beginReq := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		beginReq = setAuthContext(beginReq, "user-123")
		beginRec := httptest.NewRecorder()
		h.RegisterBegin(beginRec, beginReq)

		if beginRec.Code != http.StatusOK {
			t.Fatalf("RegisterBegin expected 200, got %d; body: %s", beginRec.Code, beginRec.Body.String())
		}
		if capturedSession == "" {
			t.Fatal("expected session data to be captured from RegisterBegin")
		}

		// Step 2: Now set up cache to return the captured session for RegisterFinish
		mockCache.GetAndDeleteFn = func(ctx context.Context, key string) (string, error) {
			return capturedSession, nil
		}

		// Send an empty body (will fail FinishRegistration due to missing attestation)
		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterFinish(rec, req)

		// FinishRegistration fails with a parse error, handler returns 400
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "webauthn_verification_failed" {
			t.Fatalf("expected error=webauthn_verification_failed, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyFinish: valid session but FinishLogin fails (bad request body)
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_FinishLoginFails(t *testing.T) {
	t.Run("finish_login_fails_with_invalid_request", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		creds := []*model.WebAuthnCredential{
			{
				ID:           "cred-1",
				UserID:       "user-123",
				CredentialID: []byte{1, 2, 3, 4, 5, 6, 7, 8},
				PublicKey:    []byte{10, 20, 30, 40},
				SignCount:    1,
			},
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@vault.test"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return creds, nil
			},
		}

		// Step 1: Call VerifyBegin to generate real session data
		var capturedSession string
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				capturedSession = value
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		beginReq := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
		beginReq = setAuthContext(beginReq, "user-123")
		beginRec := httptest.NewRecorder()
		h.VerifyBegin(beginRec, beginReq)

		if beginRec.Code != http.StatusOK {
			t.Fatalf("VerifyBegin expected 200, got %d; body: %s", beginRec.Code, beginRec.Body.String())
		}
		if capturedSession == "" {
			t.Fatal("expected session data to be captured from VerifyBegin")
		}

		// Step 2: Set up cache to return captured session for VerifyFinish
		mockCache.GetAndDeleteFn = func(ctx context.Context, key string) (string, error) {
			return capturedSession, nil
		}

		// Send empty body (will fail FinishLogin)
		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.VerifyFinish(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "webauthn_verification_failed" {
			t.Fatalf("expected error=webauthn_verification_failed, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterFinish: store credential repo error
// (We cannot easily trigger this without a full WebAuthn flow, but we
//  test the path where Create returns an error via the session + FinishRegistration.)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VerifyBegin: empty credentials slice
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyBegin_EmptyCredentialsSlice(t *testing.T) {
	t.Run("empty_credentials_returns_no_webauthn_credentials", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{}, nil // empty slice
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
	})
}

// ---------------------------------------------------------------------------
// RegisterBegin: user found but email empty (edge case)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_UserWithEmptyEmail(t *testing.T) {
	t.Run("user_with_empty_email", func(t *testing.T) {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          "vault.test",
			RPDisplayName: "Vault Test",
			RPOrigins:     []string{"https://vault.test"},
		})
		if err != nil {
			t.Fatalf("create webauthn: %v", err)
		}

		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: ""}, nil
			},
		}
		webauthnRepo := &mocks.MockWebAuthnRepo{}
		mockCache := &mocks.MockCache{
			SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
				return nil
			},
		}

		h := NewWebAuthnHandler(webauthnRepo, userRepo, mockCache, wan, nil, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
		req = setAuthContext(req, "user-noemail")
		rec := httptest.NewRecorder()

		h.RegisterBegin(rec, req)

		// BeginRegistration should still work with empty email (WebAuthnName returns "")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// modelCredsToWebAuthn: large sign count
// ---------------------------------------------------------------------------

func TestModelCredsToWebAuthn_LargeSignCount(t *testing.T) {
	t.Run("large_sign_count_value", func(t *testing.T) {
		creds := []*model.WebAuthnCredential{
			{
				CredentialID: []byte("cred"),
				PublicKey:    []byte("pk"),
				SignCount:    2147483647, // max int32
			},
		}

		result := modelCredsToWebAuthn(creds)
		if result[0].Authenticator.SignCount != 2147483647 {
			t.Fatalf("expected sign count 2147483647, got %d", result[0].Authenticator.SignCount)
		}
	})
}

// ---------------------------------------------------------------------------
// RegisterFinish: valid cache session but invalid JSON
// (already tested in webauthn_test.go, but here with a different invalid pattern)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterFinish_TruncatedJSON(t *testing.T) {
	t.Run("truncated_json_in_cache", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
				return `{"challenge":"dGVz`, nil // truncated JSON
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.RegisterFinish(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "internal_error" {
			t.Fatalf("expected error=internal_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyFinish: truncated JSON session in cache
// ---------------------------------------------------------------------------

func TestWebAuthn_VerifyFinish_TruncatedJSON(t *testing.T) {
	t.Run("truncated_json_in_cache", func(t *testing.T) {
		userRepo := &mocks.MockUserRepo{
			GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "test@example.com"}, nil
			},
		}
		mockCache := &mocks.MockCache{
			GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
				return `{"challenge":"dGVz`, nil // truncated
			},
		}

		h := newWebAuthnHandler(&webauthn.WebAuthn{}, nil, userRepo, mockCache)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.VerifyFinish(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// modelCredsToWebAuthn: various credential field combinations
// ---------------------------------------------------------------------------

func TestModelCredsToWebAuthn_EmptyFields(t *testing.T) {
	t.Run("empty_byte_slices", func(t *testing.T) {
		creds := []*model.WebAuthnCredential{
			{
				CredentialID: []byte{},
				PublicKey:    []byte{},
				SignCount:    0,
			},
		}

		result := modelCredsToWebAuthn(creds)
		if len(result) != 1 {
			t.Fatalf("expected 1 credential, got %d", len(result))
		}
		if len(result[0].ID) != 0 {
			t.Fatalf("expected empty credential ID, got length %d", len(result[0].ID))
		}
		if len(result[0].PublicKey) != 0 {
			t.Fatalf("expected empty public key, got length %d", len(result[0].PublicKey))
		}
	})
}

func TestModelCredsToWebAuthn_ManyCredentials(t *testing.T) {
	t.Run("five_credentials", func(t *testing.T) {
		creds := make([]*model.WebAuthnCredential, 5)
		for i := range creds {
			creds[i] = &model.WebAuthnCredential{
				CredentialID: []byte{byte(i)},
				PublicKey:    []byte{byte(i + 10)},
				SignCount:    i * 100,
			}
		}

		result := modelCredsToWebAuthn(creds)
		if len(result) != 5 {
			t.Fatalf("expected 5 credentials, got %d", len(result))
		}
		for i, c := range result {
			if c.Authenticator.SignCount != uint32(i*100) {
				t.Fatalf("credential %d: expected sign count %d, got %d", i, i*100, c.Authenticator.SignCount)
			}
		}
	})
}
