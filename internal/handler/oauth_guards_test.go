package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// The authorize URL is built by the provider and handed straight back to the browser as
// a redirect. A provider that is misconfigured — or whose config an attacker has managed
// to influence — could return something that is not an https URL at all, and the server
// would be reflecting it to every user who clicks "sign in with…".
//
// That is an open redirect at best, and `javascript:` execution in the user's origin at
// worst. The guard refuses to redirect anywhere it does not trust; this is the test that
// it actually fires rather than passing the URL through.
func TestOAuthAuthorize_UnsafeProviderURLIsRefused(t *testing.T) {
	for _, unsafe := range []string{
		"javascript:alert(document.cookie)",
		"http://evil.example.com/steal",
		"data:text/html,<script>alert(1)</script>",
	} {
		t.Run(unsafe, func(t *testing.T) {
			providers := map[string]oauth2.Provider{
				"google": &mockProvider{
					name:      "google",
					authURLFn: func(string, string, string) string { return unsafe },
				},
			}
			h := newTestOAuthHandler(t, providers)

			req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
			rec := httptest.NewRecorder()

			h.Authorize(rec, req)

			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("the server redirected the user to %q", loc)
			}
			if rec.Code == http.StatusFound || rec.Code == http.StatusSeeOther {
				t.Fatalf("status = %d — an unsafe authorize URL was reflected to the browser", rec.Code)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rec.Code)
			}
		})
	}
}

// The token exchange and the userinfo call are the two points where the provider proves
// who the user is. If either fails and the flow carried on, the server would be minting a
// session for an identity it never actually verified.
func TestOAuthCallback_ProviderFailuresDoNotIssueTokens(t *testing.T) {
	boom := errors.New("provider unreachable")

	cases := []struct {
		name     string
		nonce    string
		provider *mockProvider
	}{
		{
			name:  "token exchange fails",
			nonce: "guard-nonce-exchange",
			provider: &mockProvider{
				name: "google",
				exchangeFn: func(context.Context, string, string) (*oauth2.TokenResponse, error) {
					return nil, boom
				},
			},
		},
		{
			name:  "userinfo fails",
			nonce: "guard-nonce-userinfo",
			provider: &mockProvider{
				name: "google",
				userInfoFn: func(context.Context, string) (*oauth2.UserInfo, error) {
					return nil, boom
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := validOAuthState(t, "google", tc.nonce)
			mockCache := &mocks.MockCache{
				GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
			}

			h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": tc.provider}, withCache(mockCache))

			req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
			req.AddCookie(testOAuthCookie())
			req.SetPathValue("provider", "google")
			rec := httptest.NewRecorder()

			h.Callback(rec, req)

			if rec.Code == http.StatusOK {
				t.Fatalf("the flow completed despite %s — a session for an unverified identity", tc.name)
			}
			if strings.Contains(rec.Body.String(), "access_token") {
				t.Error("tokens were issued for an identity the provider never confirmed")
			}
		})
	}
}

// An imported account claims itself on first OAuth login by clearing import_pending. If
// that write fails and the flow continued, the account would stay import_pending forever
// while the user was handed a working session — and every later login would take the
// import-claim path again, mailing out a fresh claim link each time.
func TestOAuthCallback_ImportClaimClearFailureFailsClosed(t *testing.T) {
	state := validOAuthState(t, "google", "import-clear-nonce")

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{ID: "sa-1", UserID: "user-import", Provider: "google"}, nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "imported@example.com", EmailVerified: true, ImportPending: true}, nil
		},
		ClearImportPendingFn: func(context.Context, string) error {
			return errors.New("db down")
		},
	}

	h := newTestOAuthHandler(t,
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		withCache(mockCache), withSocial(social), withUsers(users),
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — the account stays import_pending but the user got a session", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("tokens were issued even though the import claim never landed")
	}
}

// The social link is the bridge between the provider's identity and ours. If it fails to
// store after the user row was created, the flow must fail: otherwise the next login
// finds no link, creates *another* user for the same person, and the first one is
// orphaned — a duplicate account nobody can reach.
func TestOAuthCallback_SocialLinkFailurePreventsOrphanedUser(t *testing.T) {
	state := validOAuthState(t, "google", "orphan-nonce")

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil // no existing link
		},
		CreateFn: func(context.Context, *model.SocialAccount) error {
			return errors.New("db down")
		},
	}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn:     func(context.Context, *model.User) error { return nil },
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}

	h := newTestOAuthHandler(t,
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		withCache(mockCache), withSocial(social), withUsers(users),
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("the flow completed with no social link stored — the next login would create a duplicate user")
	}
}
