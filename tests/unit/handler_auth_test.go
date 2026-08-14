package unit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// testPassword is a 15+ character password used across tests.
const testPassword = "SuperSecurePass!123"

// testEmail is the canonical test email used across tests.
const testEmail = "test@example.com"

// authTestEnv bundles every object a handler-level auth test might need.
type authTestEnv struct {
	handler   *handler.AuthHandler
	userRepo  *mocks.MockUserRepo
	tokenRepo *mocks.MockRefreshTokenRepo
	key       *rsa.PrivateKey
	kid       string
}

func setupAuthHandler(t *testing.T) *authTestEnv {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("generate kid: %v", err)
	}

	userRepo := &mocks.MockUserRepo{
		// Refresh enforces account state (re-fetches the user); default to a live,
		// non-banned user unless a test overrides GetByIDFn.
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}
	tokenRepo := &mocks.MockRefreshTokenRepo{}
	deviceRepo := &mocks.MockDeviceRepo{}
	pwHistRepo := &mocks.MockPasswordHistoryRepo{}
	auditRepo := &mocks.MockAuditRepo{}
	auditLogger := audit.NewLogger(auditRepo, 0)

	tokenSvc := service.NewTokenService(
		key, kid,
		"https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour,
	)

	authSvc := service.NewAuthService(
		userRepo, tokenRepo, deviceRepo, pwHistRepo,
		tokenSvc, nil, auditLogger, service.NewHIBPClient(),
		nil, nil, "https://vault.test", "TestVault",
		"", 15, false, nil, // pepper="", minPwLength=15, hibpEnabled=false, hmacSecret=nil
	)

	h := handler.NewAuthHandler(authSvc, userRepo, nil, auditLogger, "", false)
	return &authTestEnv{
		handler:   h,
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		key:       key,
		kid:       kid,
	}
}

// postJSON builds a POST request with a JSON body and returns it together with
// a fresh httptest.ResponseRecorder.
func postJSON(path string, body interface{}) (*http.Request, *httptest.ResponseRecorder) {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req, httptest.NewRecorder()
}

// decodeResponse unmarshals the response body into a generic map.
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return result
}

// hashTestPassword returns an argon2id hash of testPassword.
func hashTestPassword(t *testing.T) string {
	t.Helper()
	h, err := vaultcrypto.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	return h
}

// makeTestUser returns a model.User suitable for login tests.
func makeTestUser(t *testing.T) *model.User {
	t.Helper()
	id, _ := vaultcrypto.RandomUUID()
	return &model.User{
		ID:            id,
		Email:         testEmail,
		PasswordHash:  hashTestPassword(t),
		EmailVerified: true,
		DisplayName:   "Test User",
		Locale:        "en",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Registration tests
// ---------------------------------------------------------------------------

func TestRegisterHandler_Valid(t *testing.T) {
	env := setupAuthHandler(t)

	var createCalled int
	env.userRepo.CreateFn = func(_ context.Context, _ *model.User) error {
		createCalled++
		return nil
	}

	req, w := postJSON("/auth/register", map[string]string{
		"email":        testEmail,
		"password":     testPassword,
		"display_name": "Tester",
	})

	env.handler.Register(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["status"] != "verification_email_sent" {
		t.Fatalf("expected status verification_email_sent, got %v", resp["status"])
	}
	if resp["user_id"] != nil {
		t.Fatal("response should not contain user_id (anti-enumeration)")
	}
	if createCalled != 1 {
		t.Fatalf("expected UserRepo.Create to be called once, got %d", createCalled)
	}
}

func TestRegisterHandler_MissingFields(t *testing.T) {
	env := setupAuthHandler(t)

	req, w := postJSON("/auth/register", map[string]string{})

	env.handler.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegisterHandler_ShortPassword(t *testing.T) {
	env := setupAuthHandler(t)

	req, w := postJSON("/auth/register", map[string]string{
		"email":    testEmail,
		"password": "short",
	})

	env.handler.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "password_too_short" {
		t.Fatalf("expected error %q, got %q", "password_too_short", resp["error"])
	}
}

func TestRegisterHandler_DuplicateEmail(t *testing.T) {
	env := setupAuthHandler(t)

	existing := makeTestUser(t)
	env.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
		if email == testEmail {
			return existing, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/register", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})

	env.handler.Register(w, req)

	// Must return 201 to prevent user enumeration (identical to success)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["status"] != "verification_email_sent" {
		t.Fatalf("expected status %q, got %q", "verification_email_sent", resp["status"])
	}
}

func TestRegisterHandler_InvalidEmail(t *testing.T) {
	env := setupAuthHandler(t)

	req, w := postJSON("/auth/register", map[string]string{
		"email":    "notanemail",
		"password": testPassword,
	})

	env.handler.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_input" {
		t.Fatalf("expected error %q, got %q", "invalid_input", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// Login tests
// ---------------------------------------------------------------------------

func TestLoginHandler_Valid(t *testing.T) {
	env := setupAuthHandler(t)

	user := makeTestUser(t)
	env.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
		if email == testEmail {
			return user, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/login", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept-Language", "en")

	env.handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if _, ok := resp["access_token"]; !ok {
		t.Fatal("response missing access_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", resp["token_type"])
	}

	// Verify refresh_token cookie is set
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "__Host-refresh_token" {
			found = true
			if !c.HttpOnly {
				t.Fatal("refresh_token cookie must be HttpOnly")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatal("refresh_token cookie must be SameSite=Strict")
			}
			break
		}
	}
	if !found {
		t.Fatal("refresh_token cookie not set")
	}
}

func TestLoginHandler_WrongPassword(t *testing.T) {
	env := setupAuthHandler(t)

	user := makeTestUser(t)
	env.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
		if email == testEmail {
			return user, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/login", map[string]string{
		"email":    testEmail,
		"password": "WrongPassword!1234",
	})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_credentials" {
		t.Fatalf("expected error %q, got %q", "invalid_credentials", resp["error"])
	}
}

func TestLoginHandler_NonExistentUser(t *testing.T) {
	env := setupAuthHandler(t)

	// Default mock returns nil, nil for GetByEmail — user not found.
	req, w := postJSON("/auth/login", map[string]string{
		"email":    "nobody@example.com",
		"password": testPassword,
	})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	// Must be identical to wrong password — no user enumeration.
	if resp["error"] != "invalid_credentials" {
		t.Fatalf("expected error %q, got %q", "invalid_credentials", resp["error"])
	}
}

func TestLoginHandler_LockedAccount(t *testing.T) {
	env := setupAuthHandler(t)

	locked := makeTestUser(t)
	future := time.Now().Add(1 * time.Hour)
	locked.LockedUntil = &future

	env.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
		if email == testEmail {
			return locked, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/login", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Login(w, req)

	// A locked account is answered like a wrong password or an unknown email:
	// only an existing account can reach the locked state, so a distinct 403
	// account_locked would leak that the address is registered.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_credentials" {
		t.Fatalf("expected error %q, got %q", "invalid_credentials", resp["error"])
	}
}

func TestLoginHandler_UnverifiedEmail(t *testing.T) {
	env := setupAuthHandler(t)

	user := makeTestUser(t)
	user.EmailVerified = false

	env.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
		if email == testEmail {
			return user, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/login", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Login(w, req)

	// M-5 fix: unverified email returns same response as invalid credentials
	// to prevent user enumeration
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_credentials" {
		t.Fatalf("expected error %q, got %q", "invalid_credentials", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// Refresh tests
// ---------------------------------------------------------------------------

func TestRefreshHandler_Valid(t *testing.T) {
	env := setupAuthHandler(t)

	rawToken := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	tokenHash := vaultcrypto.SHA256Hex(rawToken)
	userID, _ := vaultcrypto.RandomUUID()
	familyID, _ := vaultcrypto.RandomUUID()

	// Compute the fingerprint the handler will produce so the stored token
	// matches (IP from RemoteAddr, UA and Accept-Language from headers).
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "127.0.0.1",
		UserAgent:      "test-agent",
		AcceptLanguage: "en",
	})

	env.tokenRepo.GetByTokenHashFn = func(_ context.Context, hash string) (*model.RefreshToken, error) {
		if hash == tokenHash {
			return &model.RefreshToken{
				ID:              "rt-1",
				UserID:          userID,
				TokenHash:       tokenHash,
				FamilyID:        familyID,
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				Used:            false,
				Revoked:         false,
				CreatedAt:       time.Now(),
			}, nil
		}
		return nil, nil
	}

	var markUsedCalled, createCalled int
	env.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
		markUsedCalled++
		return true, nil
	}
	env.tokenRepo.CreateFn = func(_ context.Context, _ *model.RefreshToken) error {
		createCalled++
		return nil
	}

	req, w := postJSON("/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: rawToken})
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept-Language", "en")

	env.handler.Refresh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if _, ok := resp["access_token"]; !ok {
		t.Fatal("response missing access_token")
	}

	// Verify a new refresh_token cookie is set
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "__Host-refresh_token" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("new refresh_token cookie not set")
	}

	if markUsedCalled != 1 {
		t.Fatalf("expected MarkUsed to be called once, got %d", markUsedCalled)
	}
	if createCalled != 1 {
		t.Fatalf("expected Create (new refresh token) to be called once, got %d", createCalled)
	}
}

func TestRefreshHandler_MissingCookie(t *testing.T) {
	env := setupAuthHandler(t)

	req, w := postJSON("/auth/refresh", nil)

	env.handler.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "missing_refresh_token" {
		t.Fatalf("expected error %q, got %q", "missing_refresh_token", resp["error"])
	}
}

func TestRefreshHandler_InvalidToken(t *testing.T) {
	env := setupAuthHandler(t)

	// Default mock returns nil, nil — token not found.
	req, w := postJSON("/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "bogus-token"})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_token" {
		t.Fatalf("expected error %q, got %q", "invalid_token", resp["error"])
	}
}

func TestRefreshHandler_ReplayDetected(t *testing.T) {
	env := setupAuthHandler(t)

	rawToken := "replay0000000000000000000000000000000000000000000000000000000000"
	tokenHash := vaultcrypto.SHA256Hex(rawToken)
	familyID, _ := vaultcrypto.RandomUUID()

	env.tokenRepo.GetByTokenHashFn = func(_ context.Context, hash string) (*model.RefreshToken, error) {
		if hash == tokenHash {
			return &model.RefreshToken{
				ID:        "rt-replay",
				UserID:    "user-1",
				TokenHash: tokenHash,
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				Used:      true, // already used — replay
				Revoked:   false,
				CreatedAt: time.Now(),
			}, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: rawToken})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "replay_detected" {
		t.Fatalf("expected error %q, got %q", "replay_detected", resp["error"])
	}
}

func TestRefreshHandler_ExpiredToken(t *testing.T) {
	env := setupAuthHandler(t)

	rawToken := "expired000000000000000000000000000000000000000000000000000000000"
	tokenHash := vaultcrypto.SHA256Hex(rawToken)

	env.tokenRepo.GetByTokenHashFn = func(_ context.Context, hash string) (*model.RefreshToken, error) {
		if hash == tokenHash {
			return &model.RefreshToken{
				ID:        "rt-expired",
				UserID:    "user-1",
				TokenHash: tokenHash,
				FamilyID:  "fam-1",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
				Used:      false,
				Revoked:   false,
				CreatedAt: time.Now().Add(-25 * time.Hour),
			}, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: rawToken})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "token_expired" {
		t.Fatalf("expected error %q, got %q", "token_expired", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// Logout tests
// ---------------------------------------------------------------------------

func TestLogoutHandler_Valid(t *testing.T) {
	env := setupAuthHandler(t)

	// Build a valid JWT so the Auth middleware can parse it and inject claims.
	userID, _ := vaultcrypto.RandomUUID()
	now := time.Now()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "https://vault.test",
			Audience:  vjwt.ClaimStrings{"https://vault.test"},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "jti-test-logout",
		},
		Roles:     []string{"user"},
		Scopes:    []string{"read", "write"},
		TokenType: "Bearer",
	}

	tokenStr, err := vaultcrypto.SignToken(claims, env.key, env.kid)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// Wrap the handler with the Auth middleware so claims get injected.
	keys := map[string]*rsa.PublicKey{env.kid: &env.key.PublicKey}
	authMW := middleware.Auth(keys, "https://vault.test", "https://vault.test")
	wrapped := authMW(http.HandlerFunc(env.handler.Logout))

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["status"] != "logged_out" {
		t.Fatalf("expected status %q, got %q", "logged_out", resp["status"])
	}

	// Verify refresh_token cookie is cleared
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "__Host-refresh_token" {
			if c.MaxAge >= 0 {
				t.Fatalf("expected refresh_token cookie MaxAge < 0 (cleared), got %d", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("refresh_token clear cookie not set")
}

func TestLogoutHandler_Unauthenticated(t *testing.T) {
	env := setupAuthHandler(t)

	// Call handler directly — no middleware, so getClaims returns nil.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	env.handler.Logout(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "unauthorized" {
		t.Fatalf("expected error %q, got %q", "unauthorized", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	env := setupAuthHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	env.handler.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_request" {
		t.Fatalf("expected error %q, got %q", "invalid_request", resp["error"])
	}
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	env := setupAuthHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	env.handler.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_request" {
		t.Fatalf("expected error %q, got %q", "invalid_request", resp["error"])
	}
}

func TestRegisterHandler_ExactMinPassword(t *testing.T) {
	env := setupAuthHandler(t)

	// Exactly 15 characters — should succeed.
	exactMin := "Abcde12345!@#$%" // 15 chars

	req, w := postJSON("/auth/register", map[string]string{
		"email":    "exact@example.com",
		"password": exactMin,
	})

	env.handler.Register(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for exactly min-length password, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefreshHandler_RevokedToken(t *testing.T) {
	env := setupAuthHandler(t)

	rawToken := "revoked000000000000000000000000000000000000000000000000000000000"
	tokenHash := vaultcrypto.SHA256Hex(rawToken)

	env.tokenRepo.GetByTokenHashFn = func(_ context.Context, hash string) (*model.RefreshToken, error) {
		if hash == tokenHash {
			return &model.RefreshToken{
				ID:        "rt-revoked",
				UserID:    "user-1",
				TokenHash: tokenHash,
				FamilyID:  "fam-1",
				ExpiresAt: time.Now().Add(24 * time.Hour),
				Used:      false,
				Revoked:   true, // explicitly revoked
				CreatedAt: time.Now(),
			}, nil
		}
		return nil, nil
	}

	req, w := postJSON("/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: rawToken})
	req.RemoteAddr = "127.0.0.1:12345"

	env.handler.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["error"] != "invalid_token" {
		t.Fatalf("expected error %q, got %q", "invalid_token", resp["error"])
	}
}

func TestLoginHandler_EmptyBody(t *testing.T) {
	env := setupAuthHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	env.handler.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogoutHandler_ExpiredJWT(t *testing.T) {
	env := setupAuthHandler(t)

	// Build an expired JWT — Auth middleware should reject it.
	userID, _ := vaultcrypto.RandomUUID()
	now := time.Now()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "https://vault.test",
			Audience:  vjwt.ClaimStrings{"https://vault.test"},
			Subject:   userID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(-1 * time.Hour)), // expired
			NotBefore: vjwt.NewNumericDate(now.Add(-2 * time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ID:        "jti-expired",
		},
		TokenType: "Bearer",
	}

	tokenStr, err := vaultcrypto.SignToken(claims, env.key, env.kid)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	keys := map[string]*rsa.PublicKey{env.kid: &env.key.PublicKey}
	authMW := middleware.Auth(keys, "https://vault.test", "https://vault.test")
	wrapped := authMW(http.HandlerFunc(env.handler.Logout))

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired JWT, got %d: %s", w.Code, w.Body.String())
	}
}
