package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestRSAKey generates a small RSA key for testing (1024-bit for speed).
func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// newTestTokenService creates a TokenService suitable for unit tests.
func newTestTokenService(t *testing.T) (*service.TokenService, *rsa.PrivateKey) {
	t.Helper()
	key := newTestRSAKey(t)
	ts := service.NewTokenService(key, "test-kid-001", "vault-test", "test-audience",
		5*time.Minute, 24*time.Hour, 30*24*time.Hour)
	return ts, key
}

// newTestAuditLogger creates an audit logger backed by a no-op mock repo.
func newTestAuditLogger() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{}, 0)
}

// setAuthContext sets VaultClaims on the request context for authenticated endpoints.
func setAuthContext(req *http.Request, subject string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
	return req.WithContext(ctx)
}

// jsonBody encodes v as JSON and returns a *bytes.Reader.
func jsonBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON body: %v", err)
	}
	return bytes.NewReader(data)
}

// decodeResponse decodes the recorder body into dst.
func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder, dst interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 1-3: Health handler tests
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	Healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]string
	decodeResponse(t, rec, &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %q", body["status"])
	}
}

func TestReadyzHealthy(t *testing.T) {
	deps := &ReadyzDeps{
		PingDB:    func() error { return nil },
		PingCache: func() error { return nil },
	}
	handler := Readyz(deps)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]string
	decodeResponse(t, rec, &body)
	if body["status"] != "ready" {
		t.Fatalf("expected status=ready, got %q", body["status"])
	}
	if body["database"] != "up" {
		t.Fatalf("expected database=up, got %q", body["database"])
	}
	if body["cache"] != "up" {
		t.Fatalf("expected cache=up, got %q", body["cache"])
	}
}

func TestReadyzDBDown(t *testing.T) {
	deps := &ReadyzDeps{
		PingDB:    func() error { return errors.New("connection refused") },
		PingCache: func() error { return nil },
	}
	handler := Readyz(deps)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]string
	decodeResponse(t, rec, &body)
	if body["status"] != "not_ready" {
		t.Fatalf("expected status=not_ready, got %q", body["status"])
	}
	if body["database"] != "down" {
		t.Fatalf("expected database=down, got %q", body["database"])
	}
}

// ---------------------------------------------------------------------------
// 4-7: Response helper tests
// ---------------------------------------------------------------------------

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"key": "value"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	decodeResponse(t, rec, &body)
	if body["key"] != "value" {
		t.Fatalf("expected key=value, got %q", body["key"])
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "test_error")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var body map[string]string
	decodeResponse(t, rec, &body)
	if body["error"] != "test_error" {
		t.Fatalf("expected error=test_error, got %q", body["error"])
	}
}

func TestDecodeJSON(t *testing.T) {
	body := strings.NewReader(`{"email":"test@example.com","password":"secret123456789"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)

	var dst struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(req, &dst); err != nil {
		t.Fatalf("decodeJSON returned error: %v", err)
	}
	if dst.Email != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %q", dst.Email)
	}
	if dst.Password != "secret123456789" {
		t.Fatalf("expected password secret123456789, got %q", dst.Password)
	}
}

func TestDecodeJSONInvalid(t *testing.T) {
	body := strings.NewReader(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)

	var dst struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(req, &dst); err == nil {
		t.Fatal("expected error from decodeJSON on invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Auth handler tests (8-16)
// ---------------------------------------------------------------------------

// newTestAuthHandler wires up an AuthHandler with mock repos and a real service.
func newTestAuthHandler(t *testing.T, users *mocks.MockUserRepo) (*AuthHandler, *mocks.MockCache) {
	t.Helper()

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}
	mockTokens := &mocks.MockRefreshTokenRepo{}
	mockDevices := &mocks.MockDeviceRepo{}
	mockPwHistory := &mocks.MockPasswordHistoryRepo{}

	authSvc := service.NewAuthService(
		users,
		mockTokens,
		mockDevices,
		mockPwHistory,
		tokenSvc,
		nil, // mfaSvc — not needed for basic auth tests
		auditLog,
		nil, // hibp — disabled
		mockCache,
		nil, // emailSender — not needed
		"https://vault.test",
		"TestVault",
		"",    // pepper
		15,    // minPwLength
		false, // hibpEnabled
		nil,   // hmacSecret
	)

	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)
	return h, mockCache
}

func TestRegisterSuccess(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil // no existing user
		},
		CreateFn: func(ctx context.Context, user *model.User) error {
			return nil
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

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["status"] != "verification_email_sent" {
		t.Fatalf("expected status verification_email_sent, got %v", result["status"])
	}
	if result["user_id"] != nil {
		t.Fatal("response should not contain user_id (anti-enumeration)")
	}
}

func TestRegisterEmailTaken(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{ID: "existing-user", Email: email}, nil
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "taken@example.com",
		"password": "aVeryStrongP@ssw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	// Must return 201 to prevent user enumeration (identical to success)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "verification_email_sent" {
		t.Fatalf("expected status=verification_email_sent, got %q", result["status"])
	}
}

func TestRegisterPasswordTooShort(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "test@example.com",
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_too_short" {
		t.Fatalf("expected error=password_too_short, got %q", result["error"])
	}
}

func TestRegisterMissingFields(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	// Empty body
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader("{}"))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginSuccess(t *testing.T) {
	// Pre-hash a known password using the real Argon2id implementation.
	password := "validpassword123"
	hash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{
				ID:            "user-123",
				Email:         email,
				PasswordHash:  hash,
				EmailVerified: true,
			}, nil
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "user@example.com",
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Set("Accept-Language", "en-US")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token in response")
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correctpassword1")

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{
				ID:            "user-123",
				Email:         email,
				PasswordHash:  hash,
				EmailVerified: true,
			}, nil
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "user@example.com",
		"password": "wrongpassword12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials, got %q", result["error"])
	}
}

func TestLoginAccountLocked(t *testing.T) {
	lockedUntil := time.Now().Add(1 * time.Hour)
	hash, _ := vaultcrypto.HashPassword("validpassword123")

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{
				ID:            "user-locked",
				Email:         email,
				PasswordHash:  hash,
				EmailVerified: true,
				LockedUntil:   &lockedUntil,
			}, nil
		},
	}

	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "locked@example.com",
		"password": "validpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	// A locked account must be indistinguishable from a wrong password or an
	// unknown email at the login endpoint: only an existing account can reach the
	// locked state, so a distinct 403 account_locked leaks that the address is
	// registered (the login-lockout enumeration fix). The lockout still holds
	// server side; the caller just cannot observe it.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials, got %q", result["error"])
	}
}

// A login from a locked-out IP still answers 403 account_locked. The per-IP
// lockout is IP-scoped and reveals nothing about any specific account, so unlike
// the per-user lock it keeps its distinct status. It is now the only login path
// that reaches ErrAccountLocked at the handler, so this test is what covers that
// arm of the login error switch.
func TestLoginHandler_IPLockedReturns403(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}
	h, mockCache := newTestAuthHandler(t, users)
	// Every lockout counter, including lockout_ip:<ip>, reads over threshold, so
	// the IP lockout trips before any user lookup.
	mockCache.GetFn = func(_ context.Context, _ string) (string, error) { return "999", nil }

	body := jsonBody(t, map[string]string{"email": "whoever@example.com", "password": "x"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "203.0.113.7:5000"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "account_locked" {
		t.Fatalf("expected error=account_locked, got %q", result["error"])
	}
}

func TestRefreshMissingToken(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	// No refresh_token cookie set
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_refresh_token" {
		t.Fatalf("expected error=missing_refresh_token, got %q", result["error"])
	}
}

func TestLogout(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "logged_out" {
		t.Fatalf("expected status=logged_out, got %q", result["status"])
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
		t.Fatal("expected refresh_token cookie to be cleared")
	}
}

// ---------------------------------------------------------------------------
// User handler tests (17-22)
// ---------------------------------------------------------------------------

func TestProfileSuccess(t *testing.T) {
	now := time.Now()
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:            id,
				Email:         "profile@example.com",
				EmailVerified: true,
				DisplayName:   "Test User",
				Locale:        "en",
				CreatedAt:     now,
			}, nil
		},
	}

	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["id"] != "user-123" {
		t.Fatalf("expected id=user-123, got %v", result["id"])
	}
	if result["email"] != "profile@example.com" {
		t.Fatalf("expected email=profile@example.com, got %v", result["email"])
	}
	if result["display_name"] != "Test User" {
		t.Fatalf("expected display_name=Test User, got %v", result["display_name"])
	}
}

func TestProfileUnauthenticated(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	// No auth context set
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestSessionsList(t *testing.T) {
	now := time.Now()
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{
				{
					ID:          "device-1",
					UserID:      userID,
					IP:          "192.168.1.1",
					UserAgent:   "TestBrowser/1.0",
					Trusted:     true,
					LastSeenAt:  &now,
					FirstSeenAt: now,
				},
				{
					ID:          "device-2",
					UserID:      userID,
					IP:          "10.0.0.1",
					UserAgent:   "MobileApp/2.0",
					Trusted:     false,
					LastSeenAt:  &now,
					FirstSeenAt: now,
				},
			}, nil
		},
	}

	// One live family per device, because the listing is family-based: a device
	// with no family is not a session (TestSessionsListsFamiliesNotDevices).
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return []*repository.ActiveFamily{
				{FamilyID: "family-1", DeviceID: "device-1", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
				{FamilyID: "family-2", DeviceID: "device-2", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
			}, nil
		},
	}
	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/sessions", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Sessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	sessions, ok := result["sessions"].([]interface{})
	if !ok {
		t.Fatal("expected sessions array in response")
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestRevokeAllSessions(t *testing.T) {
	revoked := false
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(ctx context.Context, userID string) error {
			revoked = true
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.RevokeAllSessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "all_sessions_revoked" {
		t.Fatalf("expected status=all_sessions_revoked, got %q", result["status"])
	}
	if !revoked {
		t.Fatal("expected RevokeAllForUser to have been called")
	}
}

func TestDevicesList(t *testing.T) {
	now := time.Now()
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{
				{
					ID:              "device-1",
					UserID:          userID,
					FingerprintHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					FriendlyName:    "Laptop",
					Trusted:         true,
					IP:              "192.168.1.1",
					UserAgent:       "Chrome/120",
					LastSeenAt:      &now,
				},
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Devices(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	devs, ok := result["devices"].([]interface{})
	if !ok {
		t.Fatal("expected devices array in response")
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}

	d := devs[0].(map[string]interface{})
	if d["friendly_name"] != "Laptop" {
		t.Fatalf("expected friendly_name=Laptop, got %v", d["friendly_name"])
	}
	// fingerprint_hash should not be present in response (N-2 security fix)
	if _, exists := d["fingerprint_hash"]; exists {
		t.Fatal("fingerprint_hash should not be present in device response")
	}
}

func TestDeleteDeviceWrongOwner(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			// Device belongs to a different user
			return &model.Device{
				ID:     id,
				UserID: "other-user-999",
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	// Use Go 1.22+ path value pattern: we need to set the path value on the request.
	req := httptest.NewRequest(http.MethodDelete, "/user/devices/device-abc", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-abc")
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	// The handler returns 404 "device_not_found" when ownership check fails
	// (not 403, to avoid revealing device existence to non-owners).
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "device_not_found" {
		t.Fatalf("expected error=device_not_found, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// Password handler tests (23-26)
// ---------------------------------------------------------------------------

func newTestPasswordHandler(t *testing.T, users *mocks.MockUserRepo, pwHistory *mocks.MockPasswordHistoryRepo) *PasswordHandler {
	t.Helper()
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{
		SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
			return nil
		},
		GetFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound
		},
	}

	return NewPasswordHandler(
		users,
		pwHistory,
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		auditLog,
		mockCache,
		"https://vault.test",
		"TestVault",
		"",         // pepper
		15,         // minLength
		nil, false, // HIBP disabled
	)
}

func TestResetRequestSuccess(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-123", Email: email}, nil
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetRequest(rec, req)

	// Always 200 to prevent user enumeration
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] == "" {
		t.Fatal("expected non-empty status in response")
	}
}

func TestResetRequestNonexistentEmail(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil // no user found
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{"email": "nonexistent@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetRequest(rec, req)

	// Must still return 200 to prevent user enumeration
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// A deleted, banned or disabled account must not receive a reset link: the
// address exists, so the old code minted and mailed a token for it. The response
// stays an indistinguishable 200, but no token is stored and no mail is sent.
func TestResetRequest_IneligibleAccountsGetNoLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *model.User
	}{
		{name: "deleted", user: &model.User{ID: "u1", Email: "u@example.com", Deleted: true}},
		{name: "banned", user: &model.User{ID: "u1", Email: "u@example.com", Banned: true}},
		{name: "disabled", user: &model.User{ID: "u1", Email: "u@example.com", Disabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := &mocks.MockUserRepo{
				GetByEmailFn: func(context.Context, string) (*model.User, error) { return tc.user, nil },
			}
			storedResetKey := false
			cacheSpy := &mocks.MockCache{
				SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
					if strings.HasPrefix(key, "reset:") {
						storedResetKey = true
					}
					return nil
				},
				GetFn: func(context.Context, string) (string, error) { return "", cache.ErrNotFound },
			}
			mailed := false
			mailer := &mocks.MockEmailSender{
				SendFn: func(context.Context, string, string, string, string) error { mailed = true; return nil },
			}
			h := NewPasswordHandler(users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
				mailer, newTestAuditLogger(), cacheSpy, "https://vault.test", "TestVault", "", 15, nil, false)

			body := jsonBody(t, map[string]string{"email": "u@example.com"})
			req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
			req.RemoteAddr = "127.0.0.1:9999"
			rec := httptest.NewRecorder()
			h.ResetRequest(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: an ineligible account must not be distinguishable", rec.Code)
			}
			if storedResetKey {
				t.Errorf("a %s account had a reset token stored; ineligible accounts must not get a link", tc.name)
			}
			if mailed {
				t.Errorf("a %s account was mailed a reset link", tc.name)
			}
		})
	}
}

func TestChangePasswordSuccess(t *testing.T) {
	currentPassword := "myCurrentP@ssw0rd"
	currentHash, err := vaultcrypto.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: currentHash,
			}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, passwordHash string) error {
			return nil
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": currentPassword,
		"new_password":     "myNewP@ssw0rd!!!xyz",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-123")
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "password_changed" {
		t.Fatalf("expected status=password_changed, got %q", result["status"])
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	// Hash a password that is NOT what we will send
	realHash, _ := vaultcrypto.HashPassword("actualPassword123")

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:           id,
				Email:        "user@example.com",
				PasswordHash: realHash,
			}, nil
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": "wrongCurrentPass123",
		"new_password":     "brandNewPassword!!xyz",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_current_password" {
		t.Fatalf("expected error=invalid_current_password, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case subtests
// ---------------------------------------------------------------------------

func TestLogoutUnauthenticated(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// No auth context
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	users := &mocks.MockUserRepo{}
	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{
		"email":    "not-an-email",
		"password": "aVeryStrongP@ssw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionsUnauthenticated(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/sessions", nil)
	rec := httptest.NewRecorder()

	h.Sessions(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRevokeAllSessionsUnauthenticated(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions", nil)
	rec := httptest.NewRecorder()

	h.RevokeAllSessions(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestChangePasswordUnauthenticated(t *testing.T) {
	h := newTestPasswordHandler(t, &mocks.MockUserRepo{}, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": "anything12345678",
		"new_password":     "anything12345678x",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestChangePasswordTooShort(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("currentPassword1")
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: hash}, nil
		},
	}

	h := newTestPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{})

	body := jsonBody(t, map[string]string{
		"current_password": "currentPassword1",
		"new_password":     "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/user/password", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_too_short" {
		t.Fatalf("expected error=password_too_short, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// MFA, TOTP, Backup Code, WellKnown, VerifyEmail, ResetConfirm, utility tests
// ---------------------------------------------------------------------------

func TestMFAHandler_Status(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{}
	mockBackup := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{{ID: "bc-1"}, {ID: "bc-2"}}, nil
		},
	}

	mfaSvc := service.NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
	h := NewMFAHandler(mfaSvc)

	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Status(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["totp_enabled"] != true {
		t.Fatalf("expected totp_enabled=true, got %v", result["totp_enabled"])
	}
	backupRemaining, _ := result["backup_codes_remaining"].(float64)
	if backupRemaining != 2 {
		t.Fatalf("expected backup_codes_remaining=2, got %v", backupRemaining)
	}
}

func TestMFAHandler_Status_Unauthorized(t *testing.T) {
	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)
	h := NewMFAHandler(mfaSvc)

	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
	// No auth context
	rec := httptest.NewRecorder()

	h.Status(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestTOTPHandler_Setup(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil // no existing TOTP
		},
		CreateFn: func(ctx context.Context, secret *model.TOTPSecret) error {
			return nil
		},
	}
	mockCache := &mocks.MockCache{}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["secret"] == "" {
		t.Fatal("expected non-empty secret in response")
	}
	if result["otp_url"] == "" {
		t.Fatal("expected non-empty otp_url in response")
	}
	if !strings.Contains(result["otp_url"], "otpauth://") {
		t.Fatalf("expected otp_url to contain otpauth://, got %q", result["otp_url"])
	}
}

func TestTOTPHandler_Setup_AlreadyEnabled(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:       "totp-1",
				UserID:   userID,
				Verified: true,
			}, nil
		},
	}
	mockCache := &mocks.MockCache{}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "totp_already_setup" {
		t.Fatalf("expected error=totp_already_setup, got %q", result["error"])
	}
}

func TestTOTPHandler_Verify(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	// Generate a real TOTP secret and encrypt it
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}

	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte("user-123"))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}
	encHex := hex.EncodeToString(encrypted)

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-1",
				UserID:    userID,
				SecretEnc: encHex,
				Verified:  false,
			}, nil
		},
		MarkVerifiedFn: func(ctx context.Context, id string) error {
			return nil
		},
	}

	mockCache := &mocks.MockCache{
		ExistsFn: func(ctx context.Context, key string) (bool, error) {
			return false, nil // code not yet used
		},
		SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
			return nil
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, nil, false)

	// Generate a valid TOTP code for the current time
	code, err := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	body := jsonBody(t, map[string]string{"code": code})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["verified"] != true {
		t.Fatalf("expected verified=true, got %v", result["verified"])
	}
}

func TestTOTPHandler_Verify_InvalidCode(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}

	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte("user-123"))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}
	encHex := hex.EncodeToString(encrypted)

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-1",
				UserID:    userID,
				SecretEnc: encHex,
				Verified:  false,
			}, nil
		},
	}

	mockCache := &mocks.MockCache{
		ExistsFn: func(ctx context.Context, key string) (bool, error) {
			return false, nil
		},
	}

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, nil, false)

	body := jsonBody(t, map[string]string{"code": "000000"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_code" {
		t.Fatalf("expected error=invalid_code, got %q", result["error"])
	}
}

func TestBackupCodeHandler_Generate(t *testing.T) {
	mockBackup := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(ctx context.Context, userID string) error {
			return nil
		},
		CreateBatchFn: func(ctx context.Context, codes []*model.BackupCode) error {
			return nil
		},
	}

	h := NewBackupCodeHandler(mockBackup, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	codes, ok := result["codes"].([]interface{})
	if !ok {
		t.Fatal("expected codes array in response")
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 backup codes, got %d", len(codes))
	}
	if result["warning"] == nil || result["warning"] == "" {
		t.Fatal("expected warning message in response")
	}
}

func TestBackupCodeHandler_Generate_Unauthorized(t *testing.T) {
	h := NewBackupCodeHandler(&mocks.MockBackupCodeRepo{}, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	// No auth context
	rec := httptest.NewRecorder()

	h.Generate(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestVerifyEmail_Success(t *testing.T) {
	verifyEmailCalled := false
	users := &mocks.MockUserRepo{
		VerifyEmailFn: func(ctx context.Context, id string) error {
			verifyEmailCalled = true
			return nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()

	// We need to produce a token and its SHA256 hex for the cache key
	token := "test-verify-token-abc123"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "verify:" + tokenHash

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-123", nil
			}
			return "", cache.ErrNotFound
		},
	}

	mockTokens := &mocks.MockRefreshTokenRepo{}
	mockDevices := &mocks.MockDeviceRepo{}
	mockPwHistory := &mocks.MockPasswordHistoryRepo{}

	authSvc := service.NewAuthService(
		users, mockTokens, mockDevices, mockPwHistory,
		tokenSvc, nil, auditLog, nil, mockCache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+token, nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "email_verified" {
		t.Fatalf("expected status=email_verified, got %q", result["status"])
	}
	if !verifyEmailCalled {
		t.Fatal("expected VerifyEmail to have been called on the user repo")
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	users := &mocks.MockUserRepo{}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound
		},
	}

	mockTokens := &mocks.MockRefreshTokenRepo{}
	mockDevices := &mocks.MockDeviceRepo{}
	mockPwHistory := &mocks.MockPasswordHistoryRepo{}

	authSvc := service.NewAuthService(
		users, mockTokens, mockDevices, mockPwHistory,
		tokenSvc, nil, auditLog, nil, mockCache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token=bad-token", nil)
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_or_expired_token" {
		t.Fatalf("expected error=invalid_or_expired_token, got %q", result["error"])
	}
}

func TestResetConfirm_Success(t *testing.T) {
	token := "test-reset-token-abc123"
	tokenHash := vaultcrypto.SHA256Hex(token)
	cacheKey := "reset:" + tokenHash

	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		UpdatePasswordFn: func(ctx context.Context, id, passwordHash string) error {
			return nil
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == cacheKey {
				return "user-123", nil
			}
			return "", cache.ErrNotFound
		},
		SetFn: func(ctx context.Context, key string, value string, ttl time.Duration) error {
			return nil
		},
		GetFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound
		},
	}

	auditLog := newTestAuditLogger()

	h := NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		auditLog,
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    token,
		"password": "newStrongPassword123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "password_reset_complete" {
		t.Fatalf("expected status=password_reset_complete, got %q", result["status"])
	}
}

func TestResetConfirm_WeakPassword(t *testing.T) {
	users := &mocks.MockUserRepo{}

	mockCache := &mocks.MockCache{}

	h := NewPasswordHandler(
		users,
		&mocks.MockPasswordHistoryRepo{},
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{},
		newTestAuditLogger(),
		mockCache,
		"https://vault.test",
		"TestVault",
		"", // pepper
		15,
		nil, false, // HIBP disabled
	)

	body := jsonBody(t, map[string]string{
		"token":    "some-token",
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", body)
	rec := httptest.NewRecorder()

	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_too_short" {
		t.Fatalf("expected error=password_too_short, got %q", result["error"])
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain text", "John Doe", "John Doe"},
		{"HTML stripped", "<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"trimmed whitespace", "  Alice  ", "Alice"},
		{"max 100 chars", strings.Repeat("A", 150), strings.Repeat("A", 100)},
		{"empty string", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitize.String(tc.input, 100)
			if got != tc.expected {
				t.Fatalf("sanitize.String(%q, 100) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSanitizeAvatarURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"valid HTTPS", "https://example.com/avatar.png", "https://example.com/avatar.png"},
		{"HTTP rejected", "http://example.com/avatar.png", ""},
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"javascript rejected", "javascript:alert(1)", ""},
		{"too long", "https://example.com/" + strings.Repeat("a", 2040), ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitize.AvatarURL(tc.input)
			if got != tc.expected {
				t.Fatalf("sanitize.AvatarURL(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestIntersectScopes(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		allowed   []string
		expected  int // length of result
	}{
		{"empty requested", nil, []string{"read", "write"}, 0},
		{"empty allowed", []string{"read", "write"}, nil, 0},
		{"full overlap", []string{"read", "write"}, []string{"read", "write"}, 2},
		{"partial overlap", []string{"read", "write", "admin"}, []string{"read", "write"}, 2},
		{"disjoint", []string{"admin", "super"}, []string{"read", "write"}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := intersectScopes(tc.requested, tc.allowed)
			if len(result) != tc.expected {
				t.Fatalf("intersectScopes(%v, %v) len = %d, want %d", tc.requested, tc.allowed, len(result), tc.expected)
			}
		})
	}
}

func TestWellKnown_JWKS(t *testing.T) {
	key := newTestRSAKey(t)
	keys := map[string]*rsa.PublicKey{
		"test-kid-001": &key.PublicKey,
	}

	h := NewWellKnownHandler(keys, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	keysArr, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("expected keys array in JWKS response")
	}
	if len(keysArr) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(keysArr))
	}

	firstKey := keysArr[0].(map[string]interface{})
	if firstKey["kty"] != "RSA" {
		t.Fatalf("expected kty=RSA, got %v", firstKey["kty"])
	}
	if firstKey["kid"] != "test-kid-001" {
		t.Fatalf("expected kid=test-kid-001, got %v", firstKey["kid"])
	}
}

func TestWellKnown_OpenIDConfig(t *testing.T) {
	h := NewWellKnownHandler(nil, "https://vault.test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.OpenIDConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)

	if result["issuer"] != "https://vault.test" {
		t.Fatalf("expected issuer=https://vault.test, got %v", result["issuer"])
	}
	if result["jwks_uri"] != "https://vault.test/.well-known/jwks.json" {
		t.Fatalf("expected jwks_uri=https://vault.test/.well-known/jwks.json, got %v", result["jwks_uri"])
	}

	algValues, ok := result["access_token_signing_alg_values_supported"].([]interface{})
	if !ok || len(algValues) == 0 {
		t.Fatal("expected access_token_signing_alg_values_supported array")
	}
	if algValues[0] != "RS256" {
		t.Fatalf("expected RS256 in signing alg values, got %v", algValues[0])
	}
}

func TestRevokeSession_Success(t *testing.T) {
	deleted := false
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{
				ID:     id,
				UserID: "user-123",
			}, nil
		},
		DeleteFn: func(ctx context.Context, id, userID string) error {
			deleted = true
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/session-abc", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "session-abc")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "revoked" {
		t.Fatalf("expected status=revoked, got %q", result["status"])
	}
	if !deleted {
		t.Fatal("expected Delete to have been called on the device repo")
	}
}

func TestRevokeSession_Unauthorized(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/session-abc", nil)
	req.SetPathValue("id", "session-abc")
	// No auth context
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestRenameDevice_Success(t *testing.T) {
	updated := false
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{
				ID:     id,
				UserID: "user-123",
			}, nil
		},
		UpdateFriendlyNameFn: func(ctx context.Context, id string, name string) error {
			updated = true
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "My Laptop"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-abc", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-abc")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "updated" {
		t.Fatalf("expected status=updated, got %q", result["status"])
	}
	if result["friendly_name"] != "My Laptop" {
		t.Fatalf("expected friendly_name=My Laptop, got %q", result["friendly_name"])
	}
	if !updated {
		t.Fatal("expected UpdateFriendlyName to have been called")
	}
}

func TestRenameDevice_TooLong(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{
				ID:     id,
				UserID: "user-123",
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	longName := strings.Repeat("A", 101)
	body := jsonBody(t, map[string]string{"friendly_name": longName})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-abc", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-abc")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "name_too_long" {
		t.Fatalf("expected error=name_too_long, got %q", result["error"])
	}
}
