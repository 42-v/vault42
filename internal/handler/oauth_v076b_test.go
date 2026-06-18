package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
	"github.com/jackc/pgx/v5/pgconn"
)

// A concurrent-registration race (UNIQUE violation on Create) resolves by
// re-looking-up the user that won the race, then completing the OAuth flow.
func TestOAuth_Callback_CreateRaceResolved(t *testing.T) {
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := validOAuthState(t, "google", "race-ok-nonce")

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, _ string) (string, error) { return "verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(_ context.Context, _, _ string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}
	lookups := 0
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			lookups++
			if lookups == 1 {
				return nil, nil // absent at first check
			}
			return &model.User{ID: "race-winner", Email: email, EmailVerified: true}, nil
		},
		CreateFn: func(_ context.Context, _ *model.User) error {
			return &pgconn.PgError{Code: "23505"} // lost the race
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("resolved race should redirect (302), got %d: %s", rec.Code, rec.Body.String())
	}
}

// A UNIQUE violation whose re-lookup also fails surfaces as 500.
func TestOAuth_Callback_CreateRaceLookupFails(t *testing.T) {
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	state := validOAuthState(t, "google", "race-fail-nonce")

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, _ string) (string, error) { return "verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(_ context.Context, _, _ string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}
	lookups := 0
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			lookups++
			if lookups == 1 {
				return nil, nil
			}
			return nil, nil // race re-lookup finds nothing → cannot resolve
		},
		CreateFn: func(_ context.Context, _ *model.User) error {
			return &pgconn.PgError{Code: "23505"}
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unresolvable race should return 500, got %d: %s", rec.Code, rec.Body.String())
	}
}
