package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// M3: a valid, correctly-signed OAuth state must still be rejected at the
// callback unless the request carries the matching browser-binding cookie —
// otherwise an HMAC-valid state minted for one browser could be replayed into a
// victim's (session fixation). Authorize must also set that cookie.
func TestOAuth_Callback_CSRFCookieRequired(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	nonce := "csrf-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}

	newReq := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}, withCache(mockCache))
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
		req.SetPathValue("provider", "google")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		h.Callback(rec, req)
		return rec
	}

	if rec := newReq(nil); rec.Code != http.StatusBadRequest {
		t.Errorf("missing CSRF cookie must be rejected, got %d", rec.Code)
	}
	if rec := newReq(&http.Cookie{Name: "__Host-oauth_state", Value: "wrong-token"}); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong CSRF cookie must be rejected, got %d", rec.Code)
	}
	// Matching cookie passes state validation (proceeds past it — not a 400 invalid_state).
	if rec := newReq(testOAuthCookie()); rec.Code == http.StatusBadRequest {
		t.Errorf("matching CSRF cookie should pass state validation, got 400: %s", rec.Body.String())
	}
}

// Authorize must set the host-only browser-binding cookie.
func TestOAuth_Authorize_SetsCSRFCookie(t *testing.T) {
	h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": &mockProvider{name: "google"}})
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)

	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-oauth_state" && c.Value != "" && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Fatal("Authorize must set a non-empty HttpOnly __Host-oauth_state cookie")
	}
}
