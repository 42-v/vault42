package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// testOAuthCSRFToken is the fixed CSRF token used by signedOAuthState +
// testOAuthCookie so a migrated callback test's browser-binding cookie (M3)
// matches the csrfHash embedded in its signed state.
const testOAuthCSRFToken = "test-csrf-token-fixed"

// signedOAuthState builds a 4-part browser-bound OAuth state (M3):
// provider.nonce.expiry.csrfHash + HMAC signature.
func signedOAuthState(provider, nonce, expiry string, hmacSecret []byte) string {
	csrfHash := vaultcrypto.SHA256Hex(testOAuthCSRFToken)
	payload := fmt.Sprintf("%s.%s.%s.%s", provider, nonce, expiry, csrfHash)
	return payload + "." + vaultcrypto.HMACSign([]byte(payload), hmacSecret)
}

// testOAuthCookie returns the browser-binding cookie matching signedOAuthState.
func testOAuthCookie() *http.Cookie {
	return &http.Cookie{Name: "__Host-oauth_state", Value: testOAuthCSRFToken}
}

// ---------------------------------------------------------------------------
// MockProvider implements oauth2.Provider for testing.
// ---------------------------------------------------------------------------

type mockProvider struct {
	name       string
	authURLFn  func(state, nonce, codeChallenge string) string
	exchangeFn func(ctx context.Context, code, codeVerifier string) (*oauth2.TokenResponse, error)
	userInfoFn func(ctx context.Context, accessToken string) (*oauth2.UserInfo, error)
}

func (p *mockProvider) Name() string { return p.name }

func (p *mockProvider) AuthURL(state, nonce, codeChallenge string) string {
	if p.authURLFn != nil {
		return p.authURLFn(state, nonce, codeChallenge)
	}
	return "https://provider.example.com/auth?state=" + state
}

func (p *mockProvider) Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.TokenResponse, error) {
	if p.exchangeFn != nil {
		return p.exchangeFn(ctx, code, codeVerifier)
	}
	return &oauth2.TokenResponse{AccessToken: "mock-access-token"}, nil
}

func (p *mockProvider) UserInfo(ctx context.Context, accessToken string) (*oauth2.UserInfo, error) {
	if p.userInfoFn != nil {
		return p.userInfoFn(ctx, accessToken)
	}
	return &oauth2.UserInfo{
		ID:            "provider-user-123",
		Email:         "oauth@example.com",
		EmailVerified: true,
		Name:          "OAuth User",
		AvatarURL:     "https://example.com/avatar.png",
	}, nil
}

// ---------------------------------------------------------------------------
// OAuthHandler helpers
// ---------------------------------------------------------------------------

func newTestOAuthHandler(t *testing.T, providers map[string]oauth2.Provider, opts ...func(*oauthSetup)) *OAuthHandler {
	t.Helper()
	setup := &oauthSetup{
		hmacSecret: []byte("test-hmac-secret-32-bytes-long!!"),
		origin:     "https://vault.test",
		cache:      &mocks.MockCache{},
		users:      &mocks.MockUserRepo{},
		social:     &mocks.MockSocialAccountRepo{},
		tokens:     &mocks.MockRefreshTokenRepo{},
		mfaSvc:     nil,
	}
	for _, opt := range opts {
		opt(setup)
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		setup.users, setup.tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, setup.cache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	return NewOAuthHandler(
		providers, setup.hmacSecret, setup.cache, setup.origin,
		setup.users, setup.social, setup.tokens,
		authSvc, tokenSvc, setup.mfaSvc, auditLog, false,
	)
}

type oauthSetup struct {
	hmacSecret []byte
	origin     string
	cache      *mocks.MockCache
	users      *mocks.MockUserRepo
	social     *mocks.MockSocialAccountRepo
	tokens     *mocks.MockRefreshTokenRepo
	mfaSvc     *service.MFAService
}

func withCache(c *mocks.MockCache) func(*oauthSetup) {
	return func(s *oauthSetup) { s.cache = c }
}

func withUsers(u *mocks.MockUserRepo) func(*oauthSetup) {
	return func(s *oauthSetup) { s.users = u }
}

func withSocial(sa *mocks.MockSocialAccountRepo) func(*oauthSetup) {
	return func(s *oauthSetup) { s.social = sa }
}

func withMFA(m *service.MFAService) func(*oauthSetup) {
	return func(s *oauthSetup) { s.mfaSvc = m }
}

// ---------------------------------------------------------------------------
// Authorize tests
// ---------------------------------------------------------------------------

func TestOAuth_Authorize_Success(t *testing.T) {
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header in redirect response")
	}
	if !strings.Contains(location, "provider.example.com") {
		t.Fatalf("expected redirect to provider, got %q", location)
	}
}

func TestOAuth_Authorize_UnknownProvider(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=facebook", nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unknown_provider" {
		t.Fatalf("expected error=unknown_provider, got %q", result["error"])
	}
}

func TestOAuth_Authorize_MissingProvider(t *testing.T) {
	h := newTestOAuthHandler(t, map[string]oauth2.Provider{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize", nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Authorize_NilAuditLog(t *testing.T) {
	provider := &mockProvider{name: "github"}
	providers := map[string]oauth2.Provider{"github": provider}

	tokenSvc, _ := newTestTokenService(t)
	mockCache := &mocks.MockCache{}

	h := NewOAuthHandler(
		providers, []byte("test-hmac-secret-32-bytes-long!!"), mockCache, "https://vault.test",
		&mocks.MockUserRepo{}, &mocks.MockSocialAccountRepo{}, &mocks.MockRefreshTokenRepo{},
		nil, tokenSvc, nil, nil, false, // nil audit log
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=github", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Callback tests
// ---------------------------------------------------------------------------

func TestOAuth_Callback_UnknownProvider(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/facebook", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "facebook")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unknown_provider" {
		t.Fatalf("expected error=unknown_provider, got %q", result["error"])
	}
}

func TestOAuth_Callback_MissingState(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_state" {
		t.Fatalf("expected error=missing_state, got %q", result["error"])
	}
}

func TestOAuth_Callback_InvalidState_NoSignature(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state=no-dots-in-state", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_InvalidState_BadHMAC(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	// State with dots but bad HMAC signature
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state=google.nonce.12345.badsignature", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_InvalidState_WrongProvider(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
		"github": &mockProvider{name: "github"},
	}

	// Create a valid state for 'github' but call callback with 'google'
	nonce := "testnonce123"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("github", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_ExpiredState(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	// Create state with expired timestamp
	nonce := "expired-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "state_expired" {
		t.Fatalf("expected error=state_expired, got %q", result["error"])
	}
}

func TestOAuth_Callback_InvalidOrReusedState(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	// Create valid state but cache.GetAndDelete returns empty (already consumed)
	nonce := "reused-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound // already consumed
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_or_reused_state" {
		t.Fatalf("expected error=invalid_or_reused_state, got %q", result["error"])
	}
}

func TestOAuth_Callback_MissingCode(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	nonce := "valid-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	// No code parameter
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state, nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_code" {
		t.Fatalf("expected error=missing_code, got %q", result["error"])
	}
}

func TestOAuth_Callback_ExchangeError(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{
		name: "google",
		exchangeFn: func(ctx context.Context, code, codeVerifier string) (*oauth2.TokenResponse, error) {
			return nil, errors.New("exchange failed")
		},
	}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "exchange-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "provider_error" {
		t.Fatalf("expected error=provider_error, got %q", result["error"])
	}
}

func TestOAuth_Callback_UserInfoError(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{
		name: "google",
		userInfoFn: func(ctx context.Context, accessToken string) (*oauth2.UserInfo, error) {
			return nil, errors.New("user info failed")
		},
	}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "userinfo-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_ExistingSocialAccount(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "existing-social-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{
				ID:     "social-1",
				UserID: "existing-user-123",
			}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "code=") {
		t.Fatalf("expected one-time code in redirect, got %q", location)
	}
}

func TestOAuth_Callback_ExistingEmailUser(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "existing-email-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return nil, nil // no existing social account
		},
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{ID: "email-user-456", Email: email, EmailVerified: true}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_NewUser(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "new-user-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil // no existing user
		},
		CreateFn: func(ctx context.Context, user *model.User) error {
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_UnableToIdentifyUser_NoEmail(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{
		name: "google",
		userInfoFn: func(ctx context.Context, accessToken string) (*oauth2.UserInfo, error) {
			return &oauth2.UserInfo{
				ID:    "no-email-user",
				Email: "", // no email
			}, nil
		},
	}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "no-email-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unable_to_identify_user" {
		t.Fatalf("expected error=unable_to_identify_user, got %q", result["error"])
	}
}

func TestOAuth_Callback_UserCreateError(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "create-error-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil
		},
		CreateFn: func(ctx context.Context, user *model.User) error {
			return errors.New("db insert failed")
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_ProviderInQueryParam(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "query-provider-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "user-qp"}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social))

	// Provider in query param instead of path value
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback?provider=google&state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_MFARequired(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "mfa-required-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "mfa-user-789"}, nil
		},
	}

	// Create MFA service that requires MFA
	mfaSvc := service.NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withMFA(mfaSvc))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "requires_2fa=true") {
		t.Fatalf("expected requires_2fa=true in redirect, got %q", location)
	}
	if !strings.Contains(location, "challenge_token=") {
		t.Fatalf("expected challenge_token in redirect, got %q", location)
	}
}

func TestOAuth_Callback_NilSocialRepo(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "nil-social-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-nosocial", Email: email, EmailVerified: true}, nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()

	h := NewOAuthHandler(
		providers, hmacSecret, mockCache, "https://vault.test",
		users, nil, &mocks.MockRefreshTokenRepo{}, // nil social repo
		nil, tokenSvc, nil, auditLog, false,
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Exchange tests
// ---------------------------------------------------------------------------

func TestOAuth_Exchange_Valid(t *testing.T) {
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if strings.HasPrefix(key, "oauth_code:") {
				return `{"access_token":"test-jwt","token_type":"Bearer","expires_in":900}`, nil
			}
			return "", cache.ErrNotFound
		},
	}

	h := newTestOAuthHandler(t, nil, withCache(mockCache))

	body := strings.NewReader(`{"code":"abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/exchange", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Exchange(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] != "test-jwt" {
		t.Fatalf("expected access_token=test-jwt, got %v", result["access_token"])
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
	}
}

func TestOAuth_Exchange_InvalidCode(t *testing.T) {
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound
		},
	}

	h := newTestOAuthHandler(t, nil, withCache(mockCache))

	body := strings.NewReader(`{"code":"bad-code"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/exchange", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Exchange(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_or_expired_code" {
		t.Fatalf("expected error=invalid_or_expired_code, got %q", result["error"])
	}
}

func TestOAuth_Exchange_MissingCode(t *testing.T) {
	h := newTestOAuthHandler(t, nil)

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/exchange", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Exchange(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// PKCE S256 enforcement tests
// ---------------------------------------------------------------------------

func TestOAuth_Authorize_PKCE_ChallengePassedToProvider(t *testing.T) {
	var capturedChallenge string
	provider := &mockProvider{
		name: "google",
		authURLFn: func(state, nonce, codeChallenge string) string {
			capturedChallenge = codeChallenge
			return "https://provider.example.com/auth?state=" + state
		},
	}
	providers := map[string]oauth2.Provider{"google": provider}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if capturedChallenge == "" {
		t.Fatal("PKCE: code_challenge was not passed to provider")
	}
	// S256 challenge is base64url(sha256(verifier)) — should be 43 chars
	if len(capturedChallenge) < 40 {
		t.Fatalf("PKCE: code_challenge too short (%d chars): %q", len(capturedChallenge), capturedChallenge)
	}
}

func TestOAuth_Callback_PKCE_VerifierPassedToExchange(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	var capturedVerifier string
	provider := &mockProvider{
		name: "google",
		exchangeFn: func(ctx context.Context, code, codeVerifier string) (*oauth2.TokenResponse, error) {
			capturedVerifier = codeVerifier
			return &oauth2.TokenResponse{AccessToken: "mock-token"}, nil
		},
	}
	providers := map[string]oauth2.Provider{"google": provider}

	storedVerifier := "test-pkce-verifier-64-hex-chars-abcdef1234567890abcdef1234567890"
	nonce := "pkce-verify-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == "oauth_state:"+nonce {
				return storedVerifier, nil
			}
			return "", cache.ErrNotFound
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "pkce-user"}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if capturedVerifier != storedVerifier {
		t.Fatalf("PKCE: code_verifier not passed to Exchange: got %q, want %q", capturedVerifier, storedVerifier)
	}
}

// ---------------------------------------------------------------------------
// Redirect URI safety tests
// ---------------------------------------------------------------------------

func TestOAuth_Callback_RedirectAlwaysToOrigin(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "redirect-safety-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "redirect-user"}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	// Redirect MUST go to the configured origin, never to a user-supplied URI
	if !strings.HasPrefix(location, "https://vault.test/oauth/callback") {
		t.Fatalf("redirect_uri safety: redirect went to %q, expected prefix %q", location, "https://vault.test/oauth/callback")
	}
}

// ---------------------------------------------------------------------------
// IdP token isolation tests (cross-provider token substitution)
// ---------------------------------------------------------------------------

func TestOAuth_Callback_CrossProviderStateRejected(t *testing.T) {
	// Prove that a state signed for provider A is rejected when used with provider B.
	// This is the IdP isolation mechanism — the state payload encodes the provider name
	// and the callback validates it matches the URL path provider.
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
		"github": &mockProvider{name: "github"},
	}

	// Create valid state for "github"
	nonce := "cross-provider-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("github", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	// Use github state on google callback — must be rejected
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-provider: expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_state" {
		t.Fatalf("cross-provider: expected error=invalid_state, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// Provider error response test
// ---------------------------------------------------------------------------

func TestOAuth_Callback_ProviderError(t *testing.T) {
	providers := map[string]oauth2.Provider{
		"google": &mockProvider{name: "google"},
	}

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?error=access_denied&error_description=user+denied", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "provider_denied" {
		t.Fatalf("expected error=provider_denied, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// GitHub provider PKCE test
// ---------------------------------------------------------------------------

func TestGitHubProvider_AuthURL_IncludesPKCE(t *testing.T) {
	p := oauth2.NewGitHubProvider("client-id", "client-secret", "https://vault.test/auth/oauth2/callback/github")

	authURL := p.AuthURL("test-state", "test-nonce", "test-challenge-hash")

	if !strings.Contains(authURL, "code_challenge=test-challenge-hash") {
		t.Fatalf("GitHub AuthURL missing code_challenge: %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("GitHub AuthURL missing code_challenge_method=S256: %s", authURL)
	}
}

// ---------------------------------------------------------------------------
// sanitizeDisplayName / sanitizeAvatarURL additional edge cases
// ---------------------------------------------------------------------------

func TestSanitizeDisplayName_Quotes(t *testing.T) {
	got := sanitize.String(`He said "hello"`, 100)
	if !strings.Contains(got, "&quot;") {
		t.Fatalf("expected quotes escaped, got %q", got)
	}
}

func TestSanitizeAvatarURL_ExactLimit(t *testing.T) {
	// URL of exactly 2048 bytes should be accepted
	url := "https://example.com/" + strings.Repeat("a", 2028)
	if len(url) != 2048 {
		t.Fatalf("test URL length should be 2048, got %d", len(url))
	}
	got := sanitize.AvatarURL(url)
	if got != url {
		t.Fatalf("expected URL to be accepted at exactly 2048 bytes")
	}
}

func TestSanitizeAvatarURL_Whitespace(t *testing.T) {
	got := sanitize.AvatarURL("  https://example.com/avatar.png  ")
	if got != "https://example.com/avatar.png" {
		t.Fatalf("expected trimmed URL, got %q", got)
	}
}
