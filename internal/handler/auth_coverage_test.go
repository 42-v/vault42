package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Auth handler: Register error paths
// ---------------------------------------------------------------------------

func TestRegister_InvalidJSON(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_request" {
		t.Fatalf("expected error=invalid_request, got %q", result["error"])
	}
}

func TestRegister_EmptyEmail(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	body := jsonBody(t, map[string]string{
		"email":    "",
		"password": "aVeryStrongP@ssw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_EmptyPassword(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	body := jsonBody(t, map[string]string{
		"email":    "user@example.com",
		"password": "",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_RepoCreateError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil
		},
		CreateFn: func(ctx context.Context, user *model.User) error {
			return errors.New("db write failed")
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "newuser@example.com",
		"password": "aVeryStrongP@ssw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_GetByEmailError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, errors.New("db read failed")
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "error@example.com",
		"password": "aVeryStrongP@ssw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Auth handler: Login error paths
// ---------------------------------------------------------------------------

func TestLogin_InvalidJSON(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("{bad}"))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil // user not found
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "unknown@example.com",
		"password": "somepassword12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	// Should be identical to wrong-password response (enumeration prevention)
	if result["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials, got %q", result["error"])
	}
}

func TestLogin_EmailNotVerified(t *testing.T) {
	password := "validpassword123"
	hash, _ := vaultcrypto.HashPassword(password)

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{
				ID:            "user-unverified",
				Email:         email,
				PasswordHash:  hash,
				EmailVerified: false, // not verified
			}, nil
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "unverified@example.com",
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	// M-5 fix: unverified accounts now return 401 invalid_credentials (same as
	// wrong password) to prevent user enumeration / email verification state leakage.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials (anti-enumeration), got %q", result["error"])
	}
}

func TestLogin_RepoError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, errors.New("db connection lost")
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "error@example.com",
		"password": "somepassword12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Auth handler: Refresh tests
// ---------------------------------------------------------------------------

func TestRefresh_WithCookie_InvalidToken(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "invalid-token-xyz"})
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	// MockRefreshTokenRepo.GetByTokenHash returns nil by default -> ErrTokenInvalid
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_token" {
		t.Fatalf("expected error=invalid_token, got %q", result["error"])
	}
}

func TestRefresh_ReplayDetected(t *testing.T) {
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	mockTokens := &mocks.MockRefreshTokenRepo{
		GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID:              "rt-1",
				UserID:          "user-123",
				TokenHash:       hash,
				FamilyID:        "family-1",
				FingerprintHash: "",
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				Used:            true, // already used -> replay
			}, nil
		},
	}

	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, mockTokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "replayed-token"})
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "replay_detected" {
		t.Fatalf("expected error=replay_detected, got %q", result["error"])
	}

	// Verify refresh cookie was cleared
	found := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected refresh_token cookie to be cleared on replay detection")
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	mockTokens := &mocks.MockRefreshTokenRepo{
		GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID:        "rt-expired",
				UserID:    "user-123",
				FamilyID:  "family-2",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
			}, nil
		},
	}

	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, mockTokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "expired-token"})
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "token_expired" {
		t.Fatalf("expected error=token_expired, got %q", result["error"])
	}
}

func TestRefresh_RevokedToken(t *testing.T) {
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	mockTokens := &mocks.MockRefreshTokenRepo{
		GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID:       "rt-revoked",
				UserID:   "user-123",
				FamilyID: "family-3",
				Revoked:  true, // revoked
			}, nil
		},
	}

	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, mockTokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "revoked-token"})
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRefresh_SuccessfulRotation(t *testing.T) {
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:        "127.0.0.1",
		UserAgent: "TestAgent/1.0",
	})

	mockTokens := &mocks.MockRefreshTokenRepo{
		GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID:              "rt-valid",
				UserID:          "user-123",
				FamilyID:        "family-4",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(24 * time.Hour),
			}, nil
		},
		MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
			return true, nil // successfully marked as used
		},
	}

	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, mockTokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "valid-token"})
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("User-Agent", "TestAgent/1.0")
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token in response")
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
	}

	// Verify new refresh cookie was set
	found := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "__Host-refresh_token" && cookie.MaxAge > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected new refresh_token cookie to be set")
	}
}

// ---------------------------------------------------------------------------
// Auth handler: VerifyEmail tests
// ---------------------------------------------------------------------------

func TestVerifyEmail_MissingToken(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email", nil) // no token param
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_token" {
		t.Fatalf("expected error=missing_token, got %q", result["error"])
	}
}

func TestVerifyEmail_EmptyTokenParam(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token=", nil)
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyEmail_VerifyRepoError(t *testing.T) {
	token := "verify-repo-error-token"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "verify:" + tokenHash

	users := &mocks.MockUserRepo{
		VerifyEmailFn: func(ctx context.Context, id string) error {
			return errors.New("db error")
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-123", nil
			}
			return "", cache.ErrNotFound
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+token, nil)
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Auth handler: Logout tests
// ---------------------------------------------------------------------------

func TestLogout_ServiceError(t *testing.T) {
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	mockTokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(ctx context.Context, userID string) error {
			return errors.New("db error")
		},
	}

	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, mockTokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = setAuthContext(req, "user-123")
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// setRefreshCookie / clearRefreshCookie tests
// ---------------------------------------------------------------------------

func TestSetRefreshCookie_Secure(t *testing.T) {
	rec := httptest.NewRecorder()
	setRefreshCookie(rec, "test-token", true, 86400)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected at least one cookie")
	}

	c := cookies[0]
	if c.Name != "__Host-refresh_token" {
		t.Fatalf("expected cookie name=refresh_token, got %q", c.Name)
	}
	if c.Value != "test-token" {
		t.Fatalf("expected cookie value=test-token, got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Fatal("expected HttpOnly=true")
	}
	if !c.Secure {
		t.Fatal("expected Secure=true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected SameSite=Strict, got %d", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("expected Path=/, got %q", c.Path)
	}
	if c.MaxAge != 86400 {
		t.Fatalf("expected MaxAge=86400, got %d", c.MaxAge)
	}
}

func TestSetRefreshCookie_NotSecure(t *testing.T) {
	rec := httptest.NewRecorder()
	setRefreshCookie(rec, "test-token", false, 3600)

	cookies := rec.Result().Cookies()
	c := cookies[0]
	if c.Secure {
		t.Fatal("expected Secure=false")
	}
}

func TestClearRefreshCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	clearRefreshCookie(rec, true)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected at least one cookie")
	}

	c := cookies[0]
	if c.Name != "__Host-refresh_token" {
		t.Fatalf("expected cookie name=refresh_token, got %q", c.Name)
	}
	if c.Value != "" {
		t.Fatalf("expected empty cookie value, got %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Fatalf("expected MaxAge=-1, got %d", c.MaxAge)
	}
	if !c.Secure {
		t.Fatal("expected Secure=true")
	}
}

func TestClearRefreshCookie_NotSecure(t *testing.T) {
	rec := httptest.NewRecorder()
	clearRefreshCookie(rec, false)

	cookies := rec.Result().Cookies()
	c := cookies[0]
	if c.Secure {
		t.Fatal("expected Secure=false")
	}
}
