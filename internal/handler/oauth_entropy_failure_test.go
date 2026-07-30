package handler

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// oauthgrpEntropy stands in for crypto/rand.Reader so a specific draw inside the
// OAuth flow can be made to fail. failOn is the 1-based index of the read that
// returns an error; every other read is served from the real reader. failOn <= 0
// never fails and only counts, which is how the fault-injection tests below
// calibrate which draw they need to kill.
type oauthgrpEntropy struct {
	mu     sync.Mutex
	real   io.Reader
	failOn int
	seen   int
}

func (e *oauthgrpEntropy) Read(p []byte) (int, error) {
	e.mu.Lock()
	e.seen++
	n := e.seen
	e.mu.Unlock()
	if e.failOn > 0 && n == e.failOn {
		return 0, errors.New("entropy source exhausted")
	}
	return e.real.Read(p)
}

func (e *oauthgrpEntropy) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seen
}

// oauthgrpStarveEntropy swaps crypto/rand.Reader for the duration of the test.
// Call it after every fixture that needs real entropy has been built, so the
// only draws it sees are the ones the handler makes.
func oauthgrpStarveEntropy(t *testing.T, failOn int) *oauthgrpEntropy {
	t.Helper()
	orig := rand.Reader
	e := &oauthgrpEntropy{real: orig, failOn: failOn}
	rand.Reader = e
	t.Cleanup(func() { rand.Reader = orig })
	return e
}

// /authorize mints the PKCE verifier, the state nonce and the browser-binding
// CSRF token. If any draw fails the endpoint must abort: redirecting anyway
// would send the user to the provider with a state the callback can never
// validate, and setting the binding cookie anyway would leave a stale
// __Host-oauth_state that a later flow could be matched against.
func TestOAuth_AuthorizeFailsClosedOnEntropyFailure(t *testing.T) {
	tests := []struct {
		name   string
		failOn int
	}{
		{"pkce verifier", 1},
		{"state nonce", 2},
		{"csrf token", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stored []string
			mockCache := &mocks.MockCache{
				SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
					stored = append(stored, key)
					return nil
				},
			}
			providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
			h := newTestOAuthHandler(t, providers, withCache(mockCache))

			oauthgrpStarveEntropy(t, tt.failOn)

			req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
			req.RemoteAddr = "10.0.0.1:5000"
			rec := httptest.NewRecorder()

			h.Authorize(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q despite failing to mint the flow secrets", loc)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == oauthStateCookie {
					t.Errorf("set %s despite aborting the flow", oauthStateCookie)
				}
			}
			if len(stored) != 0 {
				t.Errorf("cached %v for a flow that was never started", stored)
			}
			if body := rec.Body.String(); strings.Contains(body, "entropy") {
				t.Errorf("response body leaks the internal failure: %s", body)
			}
		})
	}
}

// The callback creates the local account for a first-time social login. A UUID
// draw that fails must stop the flow before the user row exists: a user created
// without the social link that follows it is an orphan nobody can sign in to,
// and a second attempt would collide on the email.
func TestOAuth_CallbackDoesNotCreateUserWhenIDGenerationFails(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := signedOAuthState("google", "entropy-newuser-nonce",
		fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}
	var userCreated, socialCreated bool
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn: func(context.Context, *model.User) error {
			userCreated = true
			return nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(context.Context, *model.SocialAccount) error {
			socialCreated = true
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withUsers(users), withSocial(social))
	oauthgrpStarveEntropy(t, 1)

	rec := oauthgrpDoCallback(h, state)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if userCreated {
		t.Error("persisted a user whose ID generation had failed")
	}
	if socialCreated {
		t.Error("linked a social account for a user that was never created")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q after aborting the flow", loc)
	}
}

// The social link is the bridge between the provider identity and the local
// account. Failing to mint its ID must fail the whole callback: signing the user
// in anyway would leave the provider identity unlinked, so the next login would
// look like a brand new user and fork the account.
func TestOAuth_CallbackDoesNotSignInWhenSocialLinkIDFails(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := signedOAuthState("google", "entropy-link-nonce",
		fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "existing-user-1", Email: email, EmailVerified: true}, nil
		},
	}
	var socialCreated bool
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(context.Context, *model.SocialAccount) error {
			socialCreated = true
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withUsers(users), withSocial(social))
	oauthgrpStarveEntropy(t, 1)

	rec := oauthgrpDoCallback(h, state)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if socialCreated {
		t.Error("wrote a social link with no generated ID")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q instead of denying", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshTokenCookie && c.Value != "" {
			t.Error("issued a refresh cookie for a flow that failed to link the identity")
		}
	}
}

// A user with a second factor must never be handed a session by the OAuth path.
// If the challenge token cannot be issued the callback has to deny; redirecting
// without one would drop the browser on the callback page with no proof of the
// first factor, and issuing the full pair instead would skip 2FA outright.
func TestOAuth_CallbackDeniesWhenChallengeTokenCannotBeIssued(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := signedOAuthState("google", "entropy-challenge-nonce",
		fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "mfa-user-1"}, nil
		},
	}
	mfaSvc := service.NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false,
	)

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withMFA(mfaSvc))
	oauthgrpStarveEntropy(t, 1)

	rec := oauthgrpDoCallback(h, state)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q without a challenge token", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshTokenCookie && c.Value != "" {
			t.Error("issued a refresh cookie to a user who never passed the second factor")
		}
	}
}

// If the token pair cannot be minted the callback must deny rather than redirect
// the browser to the SPA callback page, which would otherwise read as a
// successful login with no credentials attached.
func TestOAuth_CallbackDeniesWhenTokenPairCannotBeIssued(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := signedOAuthState("google", "entropy-pair-nonce",
		fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()), hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "pair-user-1"}, nil
		},
	}
	var tokenStored bool
	tokens := &mocks.MockRefreshTokenRepo{
		CreateFn: func(context.Context, *model.RefreshToken) error {
			tokenStored = true
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), oauthgrpWithTokens(tokens))
	oauthgrpStarveEntropy(t, 1)

	rec := oauthgrpDoCallback(h, state)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if tokenStored {
		t.Error("stored a refresh token although the pair was never issued")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q with no tokens issued", loc)
	}
}

// The refresh token is only usable once its hash is on record, and the record
// needs an ID. Losing that draw must abort before the refresh cookie is set:
// a cookie whose token has no row would authenticate nothing and, worse, the
// browser would hold a credential the server cannot revoke.
func TestOAuth_CallbackDeniesWhenRefreshTokenIDFails(t *testing.T) {
	atStore, _ := oauthgrpCallbackEntropyBudget(t)

	rec, calls := oauthgrpRunCallback(t, atStore)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if calls.tokenStored {
		t.Error("stored a refresh token whose ID generation had failed")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q after failing to persist the session", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshTokenCookie && c.Value != "" {
			t.Error("set a refresh cookie for a token that was never recorded")
		}
	}
}

// The access token leaves the server only behind a one-time exchange code. If
// that code cannot be minted the callback must fail rather than redirect: the
// SPA would land on the callback page with nothing to exchange, and any
// fallback that put the token in the fragment instead would put it in history.
func TestOAuth_CallbackDeniesWhenExchangeCodeCannotBeMinted(t *testing.T) {
	_, total := oauthgrpCallbackEntropyBudget(t)

	rec, calls := oauthgrpRunCallback(t, total)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q with no exchange code", loc)
	}
	for _, key := range calls.cacheSets {
		if strings.HasPrefix(key, "oauth_code:") {
			t.Errorf("cached exchange payload under %q after the code failed", key)
		}
	}
	if body := rec.Body.String(); strings.Contains(body, "eyJ") {
		t.Errorf("response body carries a token: %s", body)
	}
}

// oauthgrpCallbackObservations records what a callback run touched.
type oauthgrpCallbackObservations struct {
	tokenStored     bool
	entropyAtStore  int
	entropyConsumed int
	cacheSets       []string
}

// oauthgrpRunCallback drives one full callback for an already-linked social
// identity, failing the failOn-th entropy draw the handler makes (0 = none).
func oauthgrpRunCallback(t *testing.T, failOn int) (*httptest.ResponseRecorder, *oauthgrpCallbackObservations) {
	t.Helper()
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := signedOAuthState("google", "entropy-budget-nonce",
		fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()), hmacSecret)

	obs := &oauthgrpCallbackObservations{}
	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
		SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
			obs.cacheSets = append(obs.cacheSets, key)
			return nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: "budget-user-1"}, nil
		},
	}

	var entropy *oauthgrpEntropy
	tokens := &mocks.MockRefreshTokenRepo{
		CreateFn: func(context.Context, *model.RefreshToken) error {
			obs.tokenStored = true
			obs.entropyAtStore = entropy.count()
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), oauthgrpWithTokens(tokens))
	entropy = oauthgrpStarveEntropy(t, failOn)

	rec := oauthgrpDoCallback(h, state)
	obs.entropyConsumed = entropy.count()
	return rec, obs
}

// oauthgrpCallbackEntropyBudget runs the same callback to completion and reports
// which entropy draw produced the refresh token ID (the last one before the
// token is stored) and how many draws the whole flow makes (the last being the
// exchange code). Measuring instead of hardcoding keeps the fault injection
// pointed at the right draw if the flow gains or loses one.
func oauthgrpCallbackEntropyBudget(t *testing.T) (atStore, total int) {
	t.Helper()
	rec, obs := oauthgrpRunCallback(t, 0)
	if rec.Code != http.StatusFound {
		t.Fatalf("calibration run: status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}
	if !obs.tokenStored {
		t.Fatal("calibration run never stored a refresh token")
	}
	if obs.entropyAtStore == 0 || obs.entropyConsumed <= obs.entropyAtStore {
		t.Fatalf("calibration run drew %d entropy reads, %d at token store", obs.entropyConsumed, obs.entropyAtStore)
	}
	return obs.entropyAtStore, obs.entropyConsumed
}

func oauthgrpDoCallback(h *OAuthHandler, state string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec
}

func oauthgrpWithTokens(tr *mocks.MockRefreshTokenRepo) func(*oauthSetup) {
	return func(s *oauthSetup) { s.tokens = tr }
}
