package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository"
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

// CheckSessionLimit is a soft pre-check. The password path then inserts through
// CreateWithinCap under a per-user lock. The OAuth callback used to call Create
// instead, so N simultaneous social logins each counted the same pre-insert
// total, each saw a free slot, and all inserted — a cap of N admitted N+k.
//
// The barrier forces every goroutine through the pre-check before any insert,
// which is the interleaving a real concurrent burst produces. After the fix
// the insert itself must refuse the overshoot.
func TestOAuth_Callback_ConcurrentLoginsCannotExceedTheCap(t *testing.T) {
	const sessionCap = 3
	const goroutines = 12

	var mu sync.Mutex
	var admitted int
	var started sync.WaitGroup
	started.Add(goroutines)

	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(context.Context, string) (int, error) {
			started.Done()
			started.Wait()
			mu.Lock()
			defer mu.Unlock()
			return admitted, nil
		},
		CreateFn: func(context.Context, *model.RefreshToken) error {
			// The pre-fix insert path. If Callback still calls Create, every
			// racer lands here after the barrier and the cap is overshot.
			mu.Lock()
			defer mu.Unlock()
			admitted++
			return nil
		},
		CreateWithinCapFn: func(_ context.Context, _ *model.RefreshToken, maxFamilies int) error {
			mu.Lock()
			defer mu.Unlock()
			if maxFamilies > 0 && admitted >= maxFamilies {
				return repository.ErrSessionLimitReached
			}
			admitted++
			return nil
		},
	}

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
	authSvc.SetMaxSessionsPerUser(sessionCap)
	h := NewOAuthHandler(
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		[]byte("test-hmac-secret-32-bytes-long!!"), cache, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)

	var wg sync.WaitGroup
	codes := make(chan int, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := oauthCapCallback(t, h, fmt.Sprintf("race-nonce-%d", i))
			codes <- rec.Code
		}(i)
	}
	wg.Wait()
	close(codes)

	if admitted != sessionCap {
		t.Fatalf("admitted %d families, want the cap of %d; concurrent OAuth callbacks overshot the session cap", admitted, sessionCap)
	}
	var ok, limited int
	for code := range codes {
		switch code {
		case http.StatusFound:
			ok++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Errorf("callback status %d, want 302 or 429", code)
		}
	}
	if ok != sessionCap {
		t.Fatalf("accepted %d callbacks, want %d", ok, sessionCap)
	}
	if limited != goroutines-sessionCap {
		t.Fatalf("refused %d callbacks, want %d", limited, goroutines-sessionCap)
	}
}

// The pre-check can be stale: CountActiveFamilies says there is a slot, then
// a racer takes it. The insert must still surface as the same 429 the
// pre-check returns, not a 500 and not a minted family.
func TestOAuth_Callback_CreateWithinCapRejectionSurfacesAs429(t *testing.T) {
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
	wrote := false
	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(context.Context, string) (int, error) { return 0, nil },
		CreateFn: func(context.Context, *model.RefreshToken) error {
			wrote = true
			return nil
		},
		CreateWithinCapFn: func(context.Context, *model.RefreshToken, int) error {
			return repository.ErrSessionLimitReached
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
	authSvc.SetMaxSessionsPerUser(3)
	h := NewOAuthHandler(
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		[]byte("test-hmac-secret-32-bytes-long!!"), cache, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)

	rec := oauthCapCallback(t, h, "stale-count-nonce")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "session_limit_reached") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if wrote {
		t.Fatal("Create ran after CreateWithinCap refused the family")
	}
}
