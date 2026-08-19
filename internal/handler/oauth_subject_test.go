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
	"github.com/42-v/vault42/tests/mocks"
)

// runOAuthCallbackWithSocial drives one callback against a caller-supplied
// social-account repository, so a test can seed the identity table.
func runOAuthCallbackWithSocial(t *testing.T, social *mocks.MockSocialAccountRepo, users *mocks.MockUserRepo, info *oauth2.UserInfo, nonce string) *httptest.ResponseRecorder {
	t.Helper()

	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	providers := map[string]oauth2.Provider{"google": &mockProvider{
		name:       "google",
		userInfoFn: func(context.Context, string) (*oauth2.UserInfo, error) { return info, nil },
	}}

	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)
	return rec
}

// TestOAuth_Callback_DoesNotSignInAsWhoeverHoldsTheEmptySubjectSlot is the join
// key's own precondition.
//
// (provider, provider_user_id) is the identity bridge and auth.social_accounts
// declares it UNIQUE, but provider_user_id is only NOT NULL, so the empty string
// is a perfectly storable value and there is exactly one row that can hold it
// per provider. Nothing checked that a subject arrived at all: an issuer that
// answers /userinfo without a sub, or a Graph response missing id, produced
// UserInfo.ID == "" and the callback looked that up as if it named somebody.
//
// In production that is a login as the wrong person. The first identity to reach
// this path without a subject takes the empty slot for that provider, and every
// later subject-less response from the same provider resolves to their user id
// and is handed that account's refresh-token family. Which direction it runs is
// not the attacker's to choose and does not need to be: an account the caller
// does not control is reachable without any credential belonging to it.
func TestOAuth_Callback_DoesNotSignInAsWhoeverHoldsTheEmptySubjectSlot(t *testing.T) {
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(_ context.Context, provider, providerUserID string) (*model.SocialAccount, error) {
			if provider == "google" && providerUserID == "" {
				return &model.SocialAccount{ID: "sa-1", UserID: "someone-elses-account", Provider: "google"}, nil
			}
			return nil, nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}

	rec := runOAuthCallbackWithSocial(t, social, users, &oauth2.UserInfo{
		ID:            "", // issuer returned no subject
		Email:         "stranger@example.com",
		EmailVerified: true,
		Provider:      "google",
	}, "empty-subject-lookup-nonce")

	if rec.Code == http.StatusFound {
		t.Fatalf("callback issued a session off an empty provider subject; " +
			"the redirect is a login as whoever already holds that slot")
	}
}

// TestOAuth_Callback_DoesNotClaimTheEmptySubjectSlotForANewAccount is the other
// direction of the same defect: not reading the empty slot, but filling it.
// Whoever writes the empty provider_user_id first becomes the account every
// later subject-less response for that provider lands in, and UNIQUE(provider,
// provider_user_id) makes that permanent because no second row can ever exist to
// contest it.
func TestOAuth_Callback_DoesNotClaimTheEmptySubjectSlotForANewAccount(t *testing.T) {
	var linked []*model.SocialAccount
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(_ context.Context, a *model.SocialAccount) error {
			linked = append(linked, a)
			return nil
		},
	}
	var created []*model.User
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn: func(_ context.Context, u *model.User) error {
			created = append(created, u)
			return nil
		},
	}

	rec := runOAuthCallbackWithSocial(t, social, users, &oauth2.UserInfo{
		ID:            "",
		Email:         "first-comer@example.com",
		EmailVerified: true,
		Provider:      "google",
	}, "empty-subject-claim-nonce")

	for _, a := range linked {
		if strings.TrimSpace(a.ProviderUserID) == "" {
			t.Errorf("linked an identity with provider_user_id %q; that row is the only one "+
				"UNIQUE(provider, provider_user_id) will ever allow for the empty subject",
				a.ProviderUserID)
		}
	}
	if len(created) != 0 {
		t.Errorf("created %d account(s) for an identity the provider never named", len(created))
	}
	if rec.Code == http.StatusFound {
		t.Fatalf("callback issued a session for an identity the provider never named")
	}
}
