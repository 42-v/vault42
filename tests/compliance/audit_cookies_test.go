package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// OWASP ASVS 5.0.0 — Cookie-based Session Management (V3.3.x)
//
// The compliance register previously marked V3.3.1–V3.3.4 "Not Applicable"
// on the premise that "vault42 ships no browser-facing application of its
// own". That premise is false: the login handler
// (internal/handler/auth.go, setRefreshCookie) issues a real
// __Host-refresh_token cookie. These tests drive a genuine login end to end
// through the exported AuthHandler and assert the attributes on the LIVE
// Set-Cookie header of the response — not merely that config can support
// them.
// =============================================================================

// auditCookiesDriveLogin constructs an AuthHandler exactly the way the
// internal/handler tests do (mocks + service.NewAuthService), with secure
// cookies ENABLED (the production posture behind TLS), performs a real
// successful password login, and returns the live __Host-refresh_token
// cookie that the handler emitted on the response.
func auditCookiesDriveLogin(t *testing.T) *http.Cookie {
	t.Helper()

	const password = "validpassword123"
	hash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{
				ID:            "user-cookie-audit",
				Email:         email,
				PasswordHash:  hash,
				EmailVerified: true,
			}, nil
		},
	}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "vault-test", "test-audience",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mockCache := &mocks.MockCache{}

	authSvc := service.NewAuthService(
		users,
		&mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{},
		tokenSvc,
		nil, // mfaSvc
		auditLog,
		nil, // hibp
		mockCache,
		nil, // emailSender
		"https://vault.test",
		"TestVault",
		"",    // pepper
		15,    // minPwLength
		false, // hibpEnabled
		nil,   // hmacSecret
	)

	// secureCookies = true: the production posture behind TLS.
	h := handler.NewAuthHandler(authSvc, users, mockCache, auditLog, "", true)

	bodyBytes, _ := json.Marshal(map[string]string{
		"email":    "cookie-audit@example.com",
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("User-Agent", "ComplianceAgent/1.0")
	req.Header.Set("Accept-Language", "en-US")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login did not succeed: status %d; body: %s", rec.Code, rec.Body.String())
	}

	var refresh *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-refresh_token" {
			refresh = c
		}
	}
	if refresh == nil {
		t.Fatalf("login response did not set a __Host-refresh_token cookie; cookies=%v", rec.Result().Cookies())
	}
	if refresh.Value == "" {
		t.Fatalf("__Host-refresh_token cookie value is empty on a successful login")
	}
	return refresh
}

// TestASVS_V3_3_1_LiveRefreshCookieIsSecure verifies V3.3.1 (Secure attribute)
// against the actual Set-Cookie emitted by a live login, not config.
func TestASVS_V3_3_1_LiveRefreshCookieIsSecure(t *testing.T) {
	c := auditCookiesDriveLogin(t)
	if !c.Secure {
		t.Fatalf("V3.3.1: live __Host-refresh_token cookie is not Secure: %+v", c)
	}
}

// TestASVS_V3_3_2_LiveRefreshCookieSameSiteStrict verifies V3.3.2 (SameSite)
// against the live Set-Cookie header.
func TestASVS_V3_3_2_LiveRefreshCookieSameSiteStrict(t *testing.T) {
	c := auditCookiesDriveLogin(t)
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("V3.3.2: live __Host-refresh_token cookie SameSite=%d, want Strict(%d)",
			c.SameSite, http.SameSiteStrictMode)
	}
}

// TestASVS_V3_3_3_LiveRefreshCookieHostPrefix verifies V3.3.3 (__Host- prefix)
// against the live Set-Cookie header. The __Host- prefix is only browser-valid
// when the cookie is also Secure, Path=/, and carries no Domain, so all three
// are asserted alongside the name.
func TestASVS_V3_3_3_LiveRefreshCookieHostPrefix(t *testing.T) {
	c := auditCookiesDriveLogin(t)
	if c.Name != "__Host-refresh_token" {
		t.Fatalf("V3.3.3: cookie name=%q, want __Host-refresh_token", c.Name)
	}
	// __Host- prefix contract (RFC 6265bis): Secure set, Path=/, no Domain.
	if !c.Secure {
		t.Fatalf("V3.3.3: __Host- prefixed cookie must be Secure; got %+v", c)
	}
	if c.Path != "/" {
		t.Fatalf("V3.3.3: __Host- prefixed cookie must have Path=/, got %q", c.Path)
	}
	if c.Domain != "" {
		t.Fatalf("V3.3.3: __Host- prefixed cookie must not set Domain, got %q", c.Domain)
	}
}

// TestASVS_V3_3_4_LiveRefreshCookieHttpOnly verifies V3.3.4 (HttpOnly)
// against the live Set-Cookie header.
func TestASVS_V3_3_4_LiveRefreshCookieHttpOnly(t *testing.T) {
	c := auditCookiesDriveLogin(t)
	if !c.HttpOnly {
		t.Fatalf("V3.3.4: live __Host-refresh_token cookie is not HttpOnly: %+v", c)
	}
}
