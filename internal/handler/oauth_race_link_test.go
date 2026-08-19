package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// raceLinkOutcome records whether the callback attached the provider identity to
// the row that won the concurrent-registration race.
type raceLinkOutcome struct {
	rec    *httptest.ResponseRecorder
	linked bool
}

// runOAuthCreateRace drives the UNIQUE-violation branch: the first GetByEmail
// misses, Create loses to a concurrent INSERT with 23505, and the re-lookup
// returns raceWinner. providerVerified is what the IdP asserts about the email.
func runOAuthCreateRace(t *testing.T, nonce string, providerVerified bool, raceWinner *model.User) raceLinkOutcome {
	t.Helper()

	state := validOAuthState(t, "google", nonce)
	provider := &mockProvider{
		name: "google",
		userInfoFn: func(context.Context, string) (*oauth2.UserInfo, error) {
			return &oauth2.UserInfo{
				ID:            "attacker-idp-account",
				Email:         raceWinner.Email,
				EmailVerified: providerVerified,
				Name:          "Attacker",
			}, nil
		},
	}

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}
	out := raceLinkOutcome{}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(context.Context, *model.SocialAccount) error { out.linked = true; return nil },
	}
	lookups := 0
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) {
			lookups++
			if lookups == 1 {
				return nil, nil // absent when the callback checks
			}
			return raceWinner, nil // the concurrent INSERT landed in between
		},
		CreateFn: func(context.Context, *model.User) error {
			return &pgconn.PgError{Code: "23505"}
		},
		GetByIDFn: func(context.Context, string) (*model.User, error) { return raceWinner, nil },
	}

	h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": provider},
		withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.Callback(rec, req)

	out.rec = rec
	return out
}

// The 23505 fallback used to adopt whatever row won the race and link the
// provider identity to it, skipping the double-verified-email predicate that the
// ordinary lookup-hit path enforces two branches above. That is an account
// takeover with a race window, not a theoretical drift: a victim registers
// victim@ex.com (stored email_verified=false), an attacker completes a social
// login asserting the same address, the callback's GetByEmail misses, the
// victim's INSERT commits first, and the attacker's Create comes back 23505.
// The attacker then owned the victim's user id with their own IdP account bolted
// on, which is a permanent passwordless login as the victim.
//
// UNIQUE(provider, provider_user_id) does not help here. It stops one IdP
// account attaching twice; it says nothing about a new IdP account attaching to
// somebody else's user row.
func TestOAuth_Callback_CreateRaceRefusesUnverifiedWinner(t *testing.T) {
	out := runOAuthCreateRace(t, "race-unverified-winner", true,
		&model.User{ID: "victim", Email: "victim@ex.com", EmailVerified: false})

	if out.rec.Code != http.StatusConflict {
		t.Fatalf("SECURITY: race winner with an unverified email was adopted (got %d %s); "+
			"the 23505 path must re-apply the same predicate as the lookup-hit path",
			out.rec.Code, out.rec.Body.String())
	}
	if out.linked {
		t.Fatalf("SECURITY: a provider identity was linked to an unverified account through " +
			"the 23505 path; that link is a standing passwordless login as that user")
	}
}

// The other half of the same predicate: the IdP did not assert a verified email.
// An unverified provider assertion no longer reaches the create-or-race path at
// all — the callback refuses first-time sign-in from a provider that cannot prove
// address ownership before it looks the address up, closing both the enumeration
// oracle and this link-takeover. The refusal is the neutral verification-required
// redirect and links nothing, which is strictly stronger than the old 409 at the
// 23505 branch.
func TestOAuth_Callback_CreateRaceRefusesUnverifiedProviderEmail(t *testing.T) {
	out := runOAuthCreateRace(t, "race-unverified-provider", false,
		&model.User{ID: "victim2", Email: "victim2@ex.com", EmailVerified: true})

	if out.rec.Code != http.StatusFound {
		t.Fatalf("an unverified provider assertion must be refused with the neutral "+
			"verification-required redirect, got %d %s", out.rec.Code, out.rec.Body.String())
	}
	if loc := out.rec.Header().Get("Location"); loc != "https://vault.test/oauth/callback#error=verification_required" {
		t.Fatalf("refusal redirect %q, want the neutral verification-required outcome", loc)
	}
	if out.linked {
		t.Fatalf("SECURITY: a provider identity asserting an unverified email was linked to " +
			"an existing account")
	}
}

// The legitimate race still resolves: both sides verified, so the callback
// adopts the winner and completes. This pins that the fix refuses on the
// predicate rather than refusing the whole 23505 branch.
func TestOAuth_Callback_CreateRaceVerifiedBothSidesProceeds(t *testing.T) {
	out := runOAuthCreateRace(t, "race-both-verified", true,
		&model.User{ID: "race-winner", Email: "shared@ex.com", EmailVerified: true})

	if out.rec.Code != http.StatusFound {
		t.Fatalf("a doubly-verified race should still resolve to a redirect, got %d %s",
			out.rec.Code, out.rec.Body.String())
	}
	if !out.linked {
		t.Fatalf("a doubly-verified race should still link the social account")
	}
}
