package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The concurrent-session cap is an account-level control, so a social login has
// to be subject to it for the same reason a password login is: this path writes
// a refresh-token family, and a cap that any one login route ignores is a cap an
// attacker with a linked provider account simply walks around.
//
// The MFA-completing OAuth path is already inside the cap because it finishes
// through CompleteMFALogin, and the client-credentials path is structurally
// exempt rather than missing, since it discards its refresh token and creates no
// family at all. This is the remaining one.

const oauthCapUserID = "9f3a5a1e-0000-4000-8000-0000000000aa"

// newOAuthCapHandler wires a callback that lands on an existing linked account,
// over a refresh-token store whose active-family count the test controls.
func newOAuthCapHandler(t *testing.T, activeFamilies, maxSessions int) (*OAuthHandler, *bool) {
	t.Helper()

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: oauthCapUserID}, nil
		},
	}
	familyWritten := false
	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(context.Context, string) (int, error) { return activeFamilies, nil },
		CreateFn: func(context.Context, *model.RefreshToken) error {
			familyWritten = true
			return nil
		},
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, cache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	authSvc.SetMaxSessionsPerUser(maxSessions)

	h := NewOAuthHandler(
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		[]byte("test-hmac-secret-32-bytes-long!!"), cache, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)
	return h, &familyWritten
}

func oauthCapCallback(t *testing.T, h *OAuthHandler, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, []byte("test-hmac-secret-32-bytes-long!!"))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.SetPathValue("provider", "google")
	req.AddCookie(testOAuthCookie())
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec
}

func TestOAuth_Callback_EnforcesTheConcurrentSessionCap(t *testing.T) {
	h, familyWritten := newOAuthCapHandler(t, 3, 3)

	rec := oauthCapCallback(t, h, "capped-nonce")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "session_limit_reached") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	// The refusal has to land before the family row, or the cap is advisory: the
	// session would exist and only the response would say otherwise.
	if *familyWritten {
		t.Fatal("a refresh-token family was written for a login the cap refused")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshTokenCookie && c.Value != "" {
			t.Fatal("a refresh cookie was set for a login the cap refused")
		}
	}
}

// The complement: under the cap the same request completes, so the test above
// is measuring the cap and not some unrelated rejection earlier in the flow.
func TestOAuth_Callback_ProceedsUnderTheConcurrentSessionCap(t *testing.T) {
	h, familyWritten := newOAuthCapHandler(t, 2, 3)

	rec := oauthCapCallback(t, h, "uncapped-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if !*familyWritten {
		t.Fatal("no refresh-token family was written for an accepted login")
	}
}

// A cap of zero is "unlimited", the documented off switch, and it must not turn
// into a cap of zero sessions that refuses every social login.
func TestOAuth_Callback_UnsetSessionCapDoesNotBlock(t *testing.T) {
	h, _ := newOAuthCapHandler(t, 500, 0)

	rec := oauthCapCallback(t, h, "unlimited-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
}
