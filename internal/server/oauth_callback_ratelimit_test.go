package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/oauth2"
)

// The social-login callback used to hang off loginRL, the credential-guessing
// bucket: 5 requests per 15 minutes, keyed on the client IP alone, fail-closed,
// and counted at triple weight for an address ipintel flags as VPN, hosting or
// Tor.
//
// The callback is not a guessing surface. Reaching its body already takes an
// HMAC-valid state, a matching __Host-oauth_state cookie, an unconsumed
// server-side PKCE verifier and a code the identity provider will honour, so
// there is nothing in it to brute-force and nothing that budget was protecting.
// Spending it had two costs. A user on a VPN got one login-or-callback per
// quarter hour across both endpoints — one mistyped password and their social
// login was dead for the rest of the window, and the reverse. And anyone
// sharing an egress IP with the victims, the same office, the same CGNAT pool,
// the same VPN exit, could spend the whole bucket with five garbage login
// bodies and take social login down for everyone behind that address.
//
// These tests assert the separation in both directions against the real mux.
// One endpoint's budget must not be spendable from the other.

// rlStubProvider is enough of an oauth2.Provider to make setupRoutes register
// the OAuth routes. No request in this file gets past the limiter and the state
// checks, so none of these methods is called.
type rlStubProvider struct{}

func (rlStubProvider) Name() string                  { return "stub" }
func (rlStubProvider) AuthURL(_, _, _ string) string { return "https://idp.test/authorize" }
func (rlStubProvider) Exchange(context.Context, string, string) (*oauth2.TokenResponse, error) {
	return nil, nil
}
func (rlStubProvider) UserInfo(context.Context, string) (*oauth2.UserInfo, error) { return nil, nil }

// rateLimitedMux builds the real route table with rate limiting on and one
// OAuth provider registered, over a cache of its own so each test starts with
// empty buckets.
func rateLimitedMux(t *testing.T) *http.ServeMux {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	deps := &Deps{
		Config: &config.Config{
			Origin:            "https://vault.localhost",
			AppName:           "Vault Test",
			PasswordMinLength: 15,
			RateLimitEnabled:  true,
		},
		Cache:          memCache,
		ReadyDeps:      &handler.ReadyzDeps{},
		OAuthProviders: map[string]oauth2.Provider{"stub": rlStubProvider{}},
	}
	return New(deps).setupRoutes()
}

// callFrom sends one request from the given address and returns the status.
func callFrom(t *testing.T, mux *http.ServeMux, method, path, addr string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, http.NoBody)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

// spendUntilLimited hits the route until it answers 429, and fails if it never
// does within max attempts — an endpoint with no bound at all is not the fix.
func spendUntilLimited(t *testing.T, mux *http.ServeMux, method, path, addr string, max int) int {
	t.Helper()
	for i := 1; i <= max; i++ {
		if callFrom(t, mux, method, path, addr) == http.StatusTooManyRequests {
			return i
		}
	}
	t.Fatalf("%s %s answered %d requests from one address without ever limiting", method, path, max)
	return 0
}

const rlCallbackPath = "/auth/oauth2/callback/stub"

// Five bad passwords must not take social login away from everyone behind the
// same egress address.
func TestOAuthCallback_ExhaustingTheLoginBudgetLeavesSocialLoginWorking(t *testing.T) {
	mux := rateLimitedMux(t)
	const addr = "203.0.113.10:5000"

	spendUntilLimited(t, mux, http.MethodPost, "/auth/login", addr, 50)

	if code := callFrom(t, mux, http.MethodGet, rlCallbackPath, addr); code == http.StatusTooManyRequests {
		t.Fatal("the social-login callback was refused because the credential-guessing bucket " +
			"was spent on /auth/login; anyone sharing this egress address can take social " +
			"login down with five garbage login bodies")
	}
}

// And the reverse: social logins must not spend the budget that exists to slow
// password guessing, or a busy shared address locks its own users out of the
// password form.
func TestOAuthCallback_ExhaustingTheCallbackBudgetLeavesPasswordLoginWorking(t *testing.T) {
	mux := rateLimitedMux(t)
	const addr = "203.0.113.11:5000"

	spendUntilLimited(t, mux, http.MethodGet, rlCallbackPath, addr, 200)

	if code := callFrom(t, mux, http.MethodPost, "/auth/login", addr); code == http.StatusTooManyRequests {
		t.Fatal("password login was refused because the callback spent its budget; the two " +
			"endpoints are still sharing one bucket")
	}
}

// The callback keeps a bound of its own. Separating the buckets must not turn
// into removing one: the route writes nothing, but it does drive an outbound
// token exchange to the identity provider on every hit.
func TestOAuthCallback_HasABoundOfItsOwn(t *testing.T) {
	mux := rateLimitedMux(t)
	const addr = "203.0.113.12:5000"

	at := spendUntilLimited(t, mux, http.MethodGet, rlCallbackPath, addr, 200)

	// A bound loose enough to be useless is the same as no bound. The point of
	// the number is that it is a real ceiling, not that it is any given value.
	if at > 60 {
		t.Errorf("the callback limiter only engaged after %d requests in one window, which is "+
			"not a meaningful ceiling", at)
	}
}
