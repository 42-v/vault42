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

// The callback resolves a user, attaches the provider identity to it, and only
// then asks whether that account is allowed to authenticate at all. Everything
// after the gate is suppressed on a refusal, which is what
// TestOAuth_Callback_AccountStateGate measures, but the identity write is ahead
// of it and survives.
//
// auth.social_accounts is the passwordless login table. A row there is a
// standing credential: the next callback finds it through
// GetByProviderAndID, never reaches the verified-email gate again, and is
// answered with that account's refresh-token family. So a refused callback
// leaves the account holding a credential it did not hold before, and
// "locked_until" is a timestamp, so the refusal expires while the row does not.
// The gate's own suite already states the rule this breaks: a locked row must
// come out of the callback in the state it went in, which is why the import
// claim was moved behind the gate. The identity table was not.
//
// The same holds for banned, disabled and deleted: the operator's answer to a
// suspected takeover is supposed to contain the account, and a callback it
// refuses still writes a new way in.

// runOAuthLinkGate drives one callback that must resolve an existing local
// account by address and would therefore write a social row. It returns the
// response plus every identity the callback tried to link.
func runOAuthLinkGate(t *testing.T, acct *model.User) (*httptest.ResponseRecorder, []*model.SocialAccount) {
	t.Helper()

	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", "link-gate-nonce", expiry, hmacSecret)

	var linked []*model.SocialAccount
	social := &mocks.MockSocialAccountRepo{
		// No identity is linked yet, so the callback takes the address path and
		// writes one.
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
		CreateFn: func(_ context.Context, a *model.SocialAccount) error {
			linked = append(linked, a)
			return nil
		},
	}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return acct, nil },
		GetByIDFn:    func(context.Context, string) (*model.User, error) { return acct, nil },
		CreateFn: func(context.Context, *model.User) error {
			t.Fatal("the fixture must resolve an existing account, not create one")
			return nil
		},
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}

	// The default mockProvider asserts a verified oauth@example.com, which is
	// what carries the callback past linkableToExistingAccount and into the link.
	providers := map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}
	h := newTestOAuthHandler(t, providers, withCache(cache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	req.AddCookie(testOAuthCookie())
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec, linked
}

func TestOAuth_Callback_RefusedAccountStateLinksNoNewIdentity(t *testing.T) {
	lockedUntil := time.Now().Add(time.Hour)

	states := []struct {
		name string
		user *model.User
		code string
	}{
		{"locked", &model.User{ID: "u-locked", EmailVerified: true, LockedUntil: &lockedUntil}, "account_locked"},
		{"banned", &model.User{ID: "u-banned", EmailVerified: true, Banned: true}, "account_banned"},
		{"disabled", &model.User{ID: "u-disabled", EmailVerified: true, Disabled: true}, "account_disabled"},
		{"deleted", &model.User{ID: "u-deleted", EmailVerified: true, Deleted: true}, "account_unavailable"},
	}

	for _, s := range states {
		t.Run(s.name, func(t *testing.T) {
			rec, linked := runOAuthLinkGate(t, s.user)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s account was not refused: %d %s", s.name, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, s.code) {
				t.Fatalf("%s account must answer %s, got %s", s.name, s.code, body)
			}
			if len(linked) != 0 {
				t.Fatalf("SECURITY: the callback linked %s/%s to the %s account %s before refusing it. "+
					"That row is a passwordless login: the next callback resolves it through "+
					"GetByProviderAndID without ever reaching the verified-email gate, and the "+
					"refusal that was supposed to contain the account expires while the row does not",
					linked[0].Provider, linked[0].ProviderUserID, s.name, s.user.ID)
			}
		})
	}
}
