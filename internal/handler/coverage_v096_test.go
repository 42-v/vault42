package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// newFailingMFAService builds an MFAService whose primary lookups (TOTP and
// WebAuthn) both fail, which is the only state where GetStatus/RequiresMFA
// return an error (fail-closed contract).
func newFailingMFAService() *service.MFAService {
	return service.NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
				return nil, errors.New("totp db down")
			},
		},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("webauthn db down")
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)
}

// newLockoutAuthService builds an AuthService over the given cache so the
// per-account MFA lockout gate reads from it.
func newLockoutAuthService(t *testing.T, c *mocks.MockCache) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, newTestAuditLogger(),
		nil, c, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// ---------------------------------------------------------------------------
// OAuth Callback: indeterminate MFA status fails closed (oauth.go:420-425)
// ---------------------------------------------------------------------------

// When RequiresMFA errors, the callback must issue a 2FA challenge rather than
// full tokens. A fail-open regression here would let a DB outage silently
// bypass a user's second factor on the OAuth path.
func TestOAuth_Callback_MFAStatusErrorFailsClosed(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "mfa-error-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "test-verifier", nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "mfa-error-user"}, nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withMFA(newFailingMFAService()))

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
		t.Fatalf("indeterminate MFA status must fail closed with a 2FA challenge, got %q", location)
	}
	if !strings.Contains(location, "challenge_token=") {
		t.Fatalf("expected challenge_token in redirect, got %q", location)
	}
}

// ---------------------------------------------------------------------------
// OAuth Exchange: corrupt cache payload (oauth.go:545-548)
// ---------------------------------------------------------------------------

func TestOAuth_Exchange_CorruptCachePayload(t *testing.T) {
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			return "not-json", nil
		},
	}

	h := newTestOAuthHandler(t, nil, withCache(mockCache))

	body := strings.NewReader(`{"code":"abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/exchange", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Exchange(rec, req)

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
// OAuth Callback: OIDC id_token branch (oauth.go:277-283)
// ---------------------------------------------------------------------------

// newOIDCTestIssuer stands up a minimal OIDC issuer: discovery, a JWKS holding
// pub (kid "k1"), and a token endpoint returning a fixed access token plus the
// id_token currently pointed to by idToken. No userinfo endpoint is exposed,
// so a passing flow proves the profile came from the verified id_token.
func newOIDCTestIssuer(t *testing.T, pub *rsa.PublicKey, idToken *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "oidc-access-token",
			"id_token":     *idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

func TestOAuth_Callback_OIDCIDToken(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	// The JWKS loader enforces a 2048-bit minimum modulus.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	const stateNonce = "oidc-nonce-1"

	run := func(t *testing.T, tokenNonce string) *httptest.ResponseRecorder {
		t.Helper()
		var idToken string
		srv := newOIDCTestIssuer(t, &key.PublicKey, &idToken)
		provider := oauth2.NewOIDCProvider("okta", srv.URL, "client-1", "secret", "https://vault.test/cb", "")

		claims := vjwt.MapClaims{
			"iss": srv.URL, "aud": "client-1", "sub": "oidc-sub-1",
			"email": "oidc@example.com", "email_verified": true, "name": "OIDC User",
			"nonce": tokenNonce,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Add(-time.Minute).Unix(),
		}
		tok, signErr := vjwt.SignRS256WithHeader(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, claims, key)
		if signErr != nil {
			t.Fatalf("sign id token: %v", signErr)
		}
		idToken = tok

		mockCache := &mocks.MockCache{
			GetAndDeleteFn: func(ctx context.Context, cacheKey string) (string, error) {
				return "test-verifier", nil
			},
		}
		social := &mocks.MockSocialAccountRepo{
			GetByProviderAndIDFn: func(ctx context.Context, prov, provUserID string) (*model.SocialAccount, error) {
				return &model.SocialAccount{UserID: "user-oidc-1"}, nil
			},
		}

		h := newTestOAuthHandler(t, map[string]oauth2.Provider{"okta": provider}, withCache(mockCache), withSocial(social))

		expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
		state := signedOAuthState("okta", stateNonce, expiry, hmacSecret)
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/okta?state="+state+"&code=test-code", nil)
		req.AddCookie(testOAuthCookie())
		req.SetPathValue("provider", "okta")
		req.RemoteAddr = "10.0.0.1:5000"
		rec := httptest.NewRecorder()

		h.Callback(rec, req)
		return rec
	}

	t.Run("verified id_token supplies the profile", func(t *testing.T) {
		rec := run(t, stateNonce)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
		}
		location := rec.Header().Get("Location")
		if !strings.HasPrefix(location, "https://vault.test/oauth/callback#") {
			t.Fatalf("expected redirect to origin callback, got %q", location)
		}
		if !strings.Contains(location, "code=") {
			t.Fatalf("expected exchange code in redirect fragment, got %q", location)
		}
	})

	t.Run("nonce mismatch is rejected as provider_error", func(t *testing.T) {
		rec := run(t, "some-other-nonce")
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d; body: %s", rec.Code, rec.Body.String())
		}
		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "provider_error" {
			t.Fatalf("expected error=provider_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// WebAuthn: BeginRegistration/BeginLogin config errors (webauthn.go:65-69, 178-182)
// ---------------------------------------------------------------------------

func TestWebAuthn_RegisterBegin_BeginRegistrationError(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}

	// Zero-value config fails Config.validate (no RPOrigins) inside BeginRegistration.
	h := newWebAuthnHandler(&webauthn.WebAuthn{Config: &webauthn.Config{}}, nil, userRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.RegisterBegin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "webauthn_error" {
		t.Fatalf("expected error=webauthn_error, got %q", result["error"])
	}
}

func TestWebAuthn_VerifyBegin_BeginLoginError(t *testing.T) {
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "test@example.com"}, nil
		},
	}
	// One credential so the empty-credentials 400 guard passes and BeginLogin
	// reaches Config.validate, which fails on the zero-value config.
	webauthnRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{
				ID: "cred-1", UserID: userID,
				CredentialID: []byte("cred-id-1"), PublicKey: []byte("pk-1"),
			}}, nil
		},
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{Config: &webauthn.Config{}}, webauthnRepo, userRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/begin", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.VerifyBegin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "webauthn_error" {
		t.Fatalf("expected error=webauthn_error, got %q", result["error"])
	}
}

// ---------------------------------------------------------------------------
// TOTP Verify: per-account lockout gate + failure recording (totp.go:102-105, 137-139)
// ---------------------------------------------------------------------------

// A locked account must be refused before the TOTP secret is even fetched,
// otherwise the code stays brute-forceable from a rotating IP pool (audit H2).
func TestTOTPHandler_Verify_LockedAccount(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	fetched := false
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			fetched = true
			return nil, nil
		},
	}
	mockCache := &mocks.MockCache{
		GetFn: func(ctx context.Context, key string) (string, error) {
			if key == "lockout:user-1" {
				return "5", nil
			}
			return "", cache.ErrNotFound
		},
	}
	authSvc := newLockoutAuthService(t, mockCache)

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, authSvc, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "account_locked" {
		t.Fatalf("expected error=account_locked, got %q", result["error"])
	}
	if fetched {
		t.Fatal("the TOTP secret was fetched for a locked account")
	}
}

// A wrong code with a wired AuthService must count toward the shared
// per-account lockout, or TOTP failures never trip the gate above.
func TestTOTPHandler_Verify_WrongCodeRecordsMFAFailure(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}

	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte("user-1"))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID: "totp-1", UserID: userID,
				SecretEnc: hex.EncodeToString(encrypted), Verified: true,
			}, nil
		},
	}

	var incrementedKey string
	mockCache := &mocks.MockCache{
		GetFn: func(ctx context.Context, key string) (string, error) {
			return "", cache.ErrNotFound
		},
		IncrementFn: func(ctx context.Context, key string, ttl time.Duration) (int64, error) {
			incrementedKey = key
			return 1, nil
		},
	}
	authSvc := newLockoutAuthService(t, mockCache)

	h := NewTOTPHandler(mockTOTP, masterKey, "VaultTest", mockCache, authSvc, false)

	// Pick a code that cannot be valid: exclude the codes for every time step
	// the validator's skew window could reach during this test.
	valid := map[string]bool{}
	for _, dt := range []time.Duration{-30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		c, err := vaultcrypto.GenerateTOTPCode(secret, time.Now().Add(dt))
		if err != nil {
			t.Fatalf("generate TOTP code: %v", err)
		}
		valid[c] = true
	}
	wrongCode := ""
	for _, cand := range []string{"000000", "111111", "222222", "333333", "444444"} {
		if !valid[cand] {
			wrongCode = cand
			break
		}
	}

	body := jsonBody(t, map[string]string{"code": wrongCode})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", body)
	req = setAuthContext(req, "user-1")
	req.RemoteAddr = "10.0.0.1:5000"
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
	if incrementedKey != "lockout:user-1" {
		t.Fatalf("expected the failed attempt to increment lockout:user-1, got %q", incrementedKey)
	}
}

// ---------------------------------------------------------------------------
// Email OTP Verify: per-account lockout gate (email_otp.go:32-35)
// ---------------------------------------------------------------------------

func TestEmailOTPVerify_LockedAccount(t *testing.T) {
	otpFetched := false
	mockCache := &mocks.MockCache{
		GetFn: func(ctx context.Context, key string) (string, error) {
			if key == "lockout:user-1" {
				return "5", nil
			}
			return "", cache.ErrNotFound
		},
		GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
			otpFetched = true
			return "", cache.ErrNotFound
		},
	}
	authSvc := newLockoutAuthService(t, mockCache)

	h := NewEmailOTPHandler(authSvc, &mocks.MockUserRepo{}, false)

	body := jsonBody(t, map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify", body)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.Verify(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "account_locked" {
		t.Fatalf("expected error=account_locked, got %q", result["error"])
	}
	if otpFetched {
		t.Fatal("the email OTP was consumed for a locked account")
	}
}

// ---------------------------------------------------------------------------
// MFA Status: GetStatus error (mfa.go:29-32)
// ---------------------------------------------------------------------------

func TestMFAHandler_Status_GetStatusError(t *testing.T) {
	h := NewMFAHandler(newFailingMFAService())

	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Status(rec, req)

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
// KMS Unwrap: nil audit logger (kms.go:79-81)
// ---------------------------------------------------------------------------

func TestKMSUnwrap_NilAuditLogger(t *testing.T) {
	svc := newTestKMS(t, 0x66)
	h := NewKMSHandler(svc, nil)

	root := []byte("nil-audit-32-byte-datroot-abcdef")
	env, err := svc.Wrap("life42-root-kek", root)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	req := withKMSClaims(kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString(env)), []string{"kms:unwrap"})
	rec := httptest.NewRecorder()
	h.Unwrap(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp KMSUnwrapResponse
	decodeResponse(t, rec, &resp)
	got, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(got) != string(root) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, root)
	}
}

// ---------------------------------------------------------------------------
// Identity Unsubscribe: nil audit logger (identity.go:31-33)
// ---------------------------------------------------------------------------

func TestUnsubscribe_NilAuditLogger(t *testing.T) {
	var stored *model.IdentityProfile
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, nil
		},
		UpsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			stored = p
			return nil
		},
	}
	svc := service.NewIdentityService(repo, make([]byte, 32), []byte("test-hmac-secret"))
	h := NewIdentityHandler(svc, nil)

	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, socialAuthedRequest(http.MethodPost, "/user/marketing/unsubscribe", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "unsubscribed" {
		t.Fatalf("expected status=unsubscribed, got %q", result["status"])
	}
	if stored == nil {
		t.Fatal("withdrawal was not persisted with a nil audit logger")
	}
}

// ---------------------------------------------------------------------------
// Login: session cap (auth.go:101-102)
// ---------------------------------------------------------------------------

func TestLoginTooManySessions(t *testing.T) {
	password := "validpassword123"
	hash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
			return &model.User{
				ID: "user-capped", Email: email,
				PasswordHash: hash, EmailVerified: true,
			}, nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(ctx context.Context, userID string) (int, error) {
			return 1, nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}
	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, mockCache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	authSvc.SetMaxSessionsPerUser(1)

	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

	body := jsonBody(t, map[string]string{
		"email":    "capped@example.com",
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("User-Agent", "TestAgent/1.0")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "too_many_sessions" {
		t.Fatalf("expected error=too_many_sessions, got %q", result["error"])
	}
}
