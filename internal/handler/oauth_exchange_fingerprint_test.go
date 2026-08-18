package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// The social-login callback does not put the access token in the redirect
// fragment. It leaves the token in the cache behind a one-time code and puts
// only the code in the fragment, and the cache key is the code hash *plus the
// request fingerprint* — not the code hash alone.
//
// The fingerprint being part of the key, rather than a field inside the stored
// payload the handler compares afterwards, is what makes a redemption from the
// wrong browser indistinguishable from a redemption of a code that never
// existed: both are a cache miss, both answer 400 invalid_or_expired_code, and
// neither tells the caller which case it was. A payload-side comparison would
// need an error path of its own, and that path is an enumeration oracle: it
// separates "this code is real but you are not its owner" from "this code is
// not real", which is exactly the question an attacker holding a leaked
// fragment wants answered.
//
// The property held, and nothing pinned it. Every existing exchange test mocks
// the cache with strings.HasPrefix(key, "oauth_code:"), so the fingerprint half
// of the key is unread by the suite and a refactor that dropped it — moving the
// check into the payload, or "simplifying" the key — would pass green.
//
// These tests run both halves against a real cache and assert only observable
// behaviour: what a second browser gets, what the first browser still gets
// afterwards, and that the two failures are byte-identical. They do not assert
// the key format, so the guarantee survives a rewrite that keeps it and only
// a rewrite that loses it fails.

// exchangeFingerprintFlow drives one social login to its redirect and returns
// the handler, the shared cache and the one-time code from the fragment.
type exchangeFingerprintFlow struct {
	handler *OAuthHandler
	code    string
}

// callbackHeaders is one browser: the values ComputeFingerprint reads.
type callbackHeaders struct {
	remoteAddr     string
	userAgent      string
	acceptLanguage string
}

func (b callbackHeaders) apply(req *http.Request) *http.Request {
	req.RemoteAddr = b.remoteAddr
	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept-Language", b.acceptLanguage)
	return req
}

var (
	originalBrowser = callbackHeaders{"10.0.0.1:5000", "Mozilla/5.0 (original browser)", "en-GB"}
	otherBrowser    = callbackHeaders{"10.9.9.9:5000", "Mozilla/5.0 (other browser)", "de-DE"}
)

// runCallbackForCode completes a social login from the given browser against a
// real cache, and returns the one-time code the SPA would read out of the
// redirect fragment.
func runCallbackForCode(t *testing.T, browser callbackHeaders) *exchangeFingerprintFlow {
	t.Helper()

	shared := cache.NewMemoryCache()
	t.Cleanup(func() { shared.Close() })

	const nonce = "exchange-fingerprint-nonce"
	if err := shared.Set(context.Background(), "oauth_state:"+nonce, "test-verifier", 10*time.Minute); err != nil {
		t.Fatalf("seed pkce verifier: %v", err)
	}

	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-exchange", Email: email, EmailVerified: true}, nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	h := NewOAuthHandler(
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		hmacSecret, shared, "https://vault.test",
		users, &mocks.MockSocialAccountRepo{}, &mocks.MockRefreshTokenRepo{},
		nil, tokenSvc, nil, newTestAuditLogger(), false,
	)

	req := httptest.NewRequest(http.MethodGet,
		"/auth/oauth2/callback/google?state="+state+"&code=provider-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, browser.apply(req))

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	_, fragment, ok := strings.Cut(location, "#")
	if !ok {
		t.Fatalf("callback redirected to %q with no fragment to read the code from", location)
	}
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("parse redirect fragment %q: %v", fragment, err)
	}
	code := values.Get("code")
	if code == "" {
		t.Fatalf("callback fragment %q carried no exchange code", fragment)
	}

	return &exchangeFingerprintFlow{handler: h, code: code}
}

// exchange redeems the code as the given browser would.
func (f *exchangeFingerprintFlow) exchange(t *testing.T, browser callbackHeaders) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/exchange",
		strings.NewReader(`{"code":"`+f.code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.Exchange(rec, browser.apply(req))
	return rec
}

// A code that leaks — through a referrer, a shared screen, a browser history
// entry, a URL-logging extension — must be worthless to anyone but the browser
// that started the flow.
func TestOAuthExchange_ACodeIsBoundToTheBrowserThatStartedTheFlow(t *testing.T) {
	f := runCallbackForCode(t, originalBrowser)

	rec := f.exchange(t, otherBrowser)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — a second browser redeemed the one-time code; body: %s",
			rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatal("a foreign redemption was handed the access token")
	}
}

// The failure above must be the same failure a made-up code produces. If the
// fingerprint check ever moves out of the cache key and into a comparison over
// the fetched payload, it gains an error path of its own, and that path answers
// the one question the design refuses to answer: whether the code exists.
func TestOAuthExchange_AForeignRedemptionIsIndistinguishableFromAnUnknownCode(t *testing.T) {
	f := runCallbackForCode(t, originalBrowser)

	foreign := f.exchange(t, otherBrowser)

	unknown := &exchangeFingerprintFlow{handler: f.handler, code: "0123456789abcdef0123456789abcdef"}
	nonexistent := unknown.exchange(t, otherBrowser)

	if foreign.Code != nonexistent.Code {
		t.Errorf("status: foreign redemption %d, unknown code %d — the two cases are "+
			"distinguishable, which enumerates live codes", foreign.Code, nonexistent.Code)
	}
	if foreign.Body.String() != nonexistent.Body.String() {
		t.Errorf("body: foreign redemption %q, unknown code %q — the two cases are "+
			"distinguishable, which enumerates live codes",
			foreign.Body.String(), nonexistent.Body.String())
	}
}

// Binding must not become a denial of service. A foreign attempt looks up a key
// the owner's entry does not live under, so it cannot consume the owner's code:
// otherwise anyone holding a leaked fragment could burn the login rather than
// steal it, which trades one attack for another.
func TestOAuthExchange_AForeignAttemptDoesNotBurnTheOwnersCode(t *testing.T) {
	f := runCallbackForCode(t, originalBrowser)

	if rec := f.exchange(t, otherBrowser); rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign redemption status = %d, want 400", rec.Code)
	}

	rec := f.exchange(t, originalBrowser)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a foreign attempt consumed the owner's code; body: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("the owner's redemption returned no token; body: %s", rec.Body.String())
	}
}

// And the code stays one-time for the browser that owns it.
func TestOAuthExchange_TheOwnersCodeIsSpentOnFirstUse(t *testing.T) {
	f := runCallbackForCode(t, originalBrowser)

	if rec := f.exchange(t, originalBrowser); rec.Code != http.StatusOK {
		t.Fatalf("first redemption status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	rec := f.exchange(t, originalBrowser)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — the one-time code was redeemable twice; body: %s",
			rec.Code, rec.Body.String())
	}
}
