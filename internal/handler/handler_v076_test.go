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
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// setAuthContextWithJTI sets VaultClaims carrying both Subject and JTI on the
// request — ConfirmPassword stores claims.ID in the confirmation cache entry.
func setAuthContextWithJTI(req *http.Request, subject, jti string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject, ID: jti},
	}
	ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
	return req.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// ConfirmPassword tests — error/denial branches
// ---------------------------------------------------------------------------

func TestConfirmPassword_MissingPassword(t *testing.T) {
	h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", strings.NewReader(`{}`))
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "password_required" {
		t.Fatalf("expected error=password_required, got %q", result["error"])
	}
}

func TestConfirmPassword_UserNotFound(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, nil // no such user
		},
	}
	h, _ := newTestAuthHandler(t, users)

	body := jsonBody(t, map[string]string{"password": "whatever12345678"})
	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestConfirmPassword_LockedOut(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correctP@ssw0rd!")
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: hash}, nil
		},
	}
	h, mockCache := newTestAuthHandler(t, users)
	// Lockout counter already at threshold.
	mockCache.GetFn = func(ctx context.Context, key string) (string, error) {
		if strings.HasPrefix(key, "confirm_lockout:") {
			return "5", nil
		}
		return "", cache.ErrNotFound
	}

	body := jsonBody(t, map[string]string{"password": "correctP@ssw0rd!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "too_many_attempts" {
		t.Fatalf("expected error=too_many_attempts, got %q", result["error"])
	}
}

func TestConfirmPassword_WrongPassword(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("realP@ssw0rd!!!")
	incremented := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: hash}, nil
		},
	}
	h, mockCache := newTestAuthHandler(t, users)
	mockCache.IncrementFn = func(ctx context.Context, key string, ttl time.Duration) (int64, error) {
		if strings.HasPrefix(key, "confirm_lockout:") {
			incremented = true
		}
		return 1, nil
	}

	body := jsonBody(t, map[string]string{"password": "wrongPassword999"})
	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", body)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_password" {
		t.Fatalf("expected error=invalid_password, got %q", result["error"])
	}
	if !incremented {
		t.Fatal("expected confirm lockout counter to be incremented on wrong password")
	}
}

func TestConfirmPassword_Success(t *testing.T) {
	password := "rightP@ssw0rd!!!"
	hash, _ := vaultcrypto.HashPassword(password)
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: hash}, nil
		},
	}
	h, mockCache := newTestAuthHandler(t, users)

	var storedJTI string
	mockCache.SetFn = func(ctx context.Context, key, value string, ttl time.Duration) error {
		if strings.HasPrefix(key, "confirm:") {
			storedJTI = value
		}
		return nil
	}

	body := jsonBody(t, map[string]string{"password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", body)
	req = setAuthContextWithJTI(req, "user-123", "jti-abc")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["confirmed"] != true {
		t.Fatalf("expected confirmed=true, got %v", result["confirmed"])
	}
	if storedJTI != "jti-abc" {
		t.Fatalf("expected confirmation window to store the JWT JTI, got %q", storedJTI)
	}
}

func TestConfirmPassword_CacheSetError(t *testing.T) {
	password := "rightP@ssw0rd!!!"
	hash, _ := vaultcrypto.HashPassword(password)
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, PasswordHash: hash}, nil
		},
	}
	h, mockCache := newTestAuthHandler(t, users)
	mockCache.SetFn = func(ctx context.Context, key, value string, ttl time.Duration) error {
		if strings.HasPrefix(key, "confirm:") {
			return errors.New("cache write failed")
		}
		return nil
	}

	body := jsonBody(t, map[string]string{"password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/confirm", body)
	req = setAuthContextWithJTI(req, "user-123", "jti-abc")
	rec := httptest.NewRecorder()

	h.ConfirmPassword(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// OAuth Authorize: PKCE verifier store failure
// ---------------------------------------------------------------------------

func TestOAuth_Authorize_CacheStoreError(t *testing.T) {
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	failCache := &mocks.MockCache{
		SetFn: func(ctx context.Context, key, value string, ttl time.Duration) error {
			return errors.New("cache unavailable")
		},
	}
	h := newTestOAuthHandler(t, providers, withCache(failCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "internal_error" {
		t.Fatalf("expected error=internal_error, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// OAuth Callback: additional branches
// ---------------------------------------------------------------------------

func validOAuthState(t *testing.T, provider, nonce string) string {
	t.Helper()
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	payload := fmt.Sprintf("%s.%s.%s", provider, nonce, expiry)
	sig := vaultcrypto.HMACSign([]byte(payload), hmacSecret)
	return payload + "." + sig
}

func TestOAuth_Callback_StateMalformedPayload(t *testing.T) {
	// Signed payload that has only two dot-separated parts after the sig is
	// stripped — SplitN yields < 3 parts → invalid_state.
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}

	payload := "google.only-two" // missing expiry segment
	sig := vaultcrypto.HMACSign([]byte(payload), hmacSecret)
	state := payload + "." + sig

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "verifier", nil
		},
	}
	h := newTestOAuthHandler(t, providers, withCache(mockCache))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_state" {
		t.Fatalf("expected error=invalid_state, got %q", result["error"])
	}
}

func TestOAuth_Callback_StateNonNumericExpiry(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}

	payload := "google.nonce123.not-a-number"
	sig := vaultcrypto.HMACSign([]byte(payload), hmacSecret)
	state := payload + "." + sig

	h := newTestOAuthHandler(t, providers)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
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

func TestOAuth_Callback_EmailLinkRefused_UnverifiedEmail(t *testing.T) {
	// OAuth email verified, but existing account email NOT verified → must refuse
	// to link to prevent account takeover (409 email_already_registered).
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "refuse-link-nonce"
	state := validOAuthState(t, "google", nonce)

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
			return &model.User{ID: "existing-456", Email: email, EmailVerified: false}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "email_already_registered" {
		t.Fatalf("expected error=email_already_registered, got %q", result["error"])
	}
}

func TestOAuth_Callback_SocialLinkError(t *testing.T) {
	// New user is created, but linking the social account fails → 500.
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "social-link-err-nonce"
	state := validOAuthState(t, "google", nonce)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(ctx context.Context, account *model.SocialAccount) error {
			return errors.New("social insert failed")
		},
	}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return nil, nil // no existing user → create path
		},
		CreateFn: func(ctx context.Context, user *model.User) error {
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_Callback_RefreshTokenStoreError(t *testing.T) {
	// Happy path up to the refresh-token persistence step, which fails → 500.
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "rt-store-err-nonce"
	state := validOAuthState(t, "google", nonce)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "existing-user"}, nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{
		CreateFn: func(ctx context.Context, token *model.RefreshToken) error {
			return errors.New("refresh token insert failed")
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	h := NewOAuthHandler(
		providers, []byte("test-hmac-secret-32-bytes-long!!"), mockCache, "https://vault.test",
		&mocks.MockUserRepo{}, social, tokens,
		nil, tokenSvc, nil, auditLog, false,
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EmailOTP Verify: success path (no challenge → verified response)
// ---------------------------------------------------------------------------

func TestEmailOTPVerify_Success(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-for-email-otp!!")
	code := "123456"
	sig := vaultcrypto.HMACSign([]byte(code), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			if key == "email_otp:user-1" {
				return sig, nil
			}
			return "", cache.ErrNotFound
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, mockCache, nil,
		"https://vault.test", "TestVault", "", 15, false, hmacSecret,
	)

	h := NewEmailOTPHandler(authSvc, &mocks.MockUserRepo{}, false)

	body := jsonBody(t, map[string]string{"code": code})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["verified"] != true {
		t.Fatalf("expected verified=true, got %v", result["verified"])
	}
}

func TestEmailOTPVerify_WrongCodeRejected(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-for-email-otp!!")
	sig := vaultcrypto.HMACSign([]byte("123456"), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return sig, nil
		},
	}
	tokenSvc, _ := newTestTokenService(t)
	authSvc := service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, newTestAuditLogger(), nil, mockCache, nil,
		"https://vault.test", "TestVault", "", 15, false, hmacSecret,
	)

	h := NewEmailOTPHandler(authSvc, &mocks.MockUserRepo{}, false)

	body := jsonBody(t, map[string]string{"code": "999999"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_code" {
		t.Fatalf("expected error=invalid_code, got %q", result["error"])
	}
}

