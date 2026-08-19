package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// exactMatchUserStore models auth.users the way Postgres actually answers.
//
// GetByEmail is `WHERE email = $1` against a VARCHAR(255) UNIQUE column, so the
// comparison is byte-for-byte and two spellings of one mailbox are two rows. A
// mock that lowercases on the way in would hide the whole defect this file is
// about, so the store here does no folding of its own.
type exactMatchUserStore struct {
	rows    map[string]*model.User
	created []*model.User
}

func newExactMatchUserStore(seed ...*model.User) *exactMatchUserStore {
	s := &exactMatchUserStore{rows: map[string]*model.User{}}
	for _, u := range seed {
		s.rows[u.Email] = u
	}
	return s
}

func (s *exactMatchUserStore) repo() *mocks.MockUserRepo {
	return &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return s.rows[email], nil
		},
		CreateFn: func(_ context.Context, u *model.User) error {
			s.created = append(s.created, u)
			s.rows[u.Email] = u
			return nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			for _, u := range s.rows {
				if u.ID == id {
					return u, nil
				}
			}
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}
}

// oauthCallbackFor drives one callback with a provider asserting the given
// identity, and returns the recorder.
func oauthCallbackFor(t *testing.T, users *mocks.MockUserRepo, info *oauth2.UserInfo, nonce string) *httptest.ResponseRecorder {
	t.Helper()

	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{
		name:       "google",
		userInfoFn: func(context.Context, string) (*oauth2.UserInfo, error) { return info, nil },
	}
	providers := map[string]oauth2.Provider{"google": provider}

	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "test-verifier", nil },
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil // no identity linked yet
		},
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

// TestOAuth_Callback_RefusesAProviderEmailThatOnlyDiffersInCaseFromATakenAddress
// pins the lookup that feeds the both-sides-verified linking gate.
//
// linkableToExistingAccount is only ever consulted for an account GetByEmail
// found, and GetByEmail is an exact SQL comparison. Register and Login fold an
// address to lower case before they touch the repository; this path handed the
// provider's spelling straight through. So an identity asserting
// Victim@Example.com missed the row holding victim@example.com entirely, skipped
// the gate rather than failing it, and fell into the create branch.
//
// What that costs in production: the address of an account that has not verified
// itself yet is claimable by anyone whose IdP will assert a differently-cased
// spelling of it. They land on a second, fully verified vault42 account carrying
// the victim's mailbox in its email column, which is a standing identity for that
// address to every reader that folds case, while auth.users UNIQUE(email) never
// sees a conflict because the two strings differ.
func TestOAuth_Callback_RefusesAProviderEmailThatOnlyDiffersInCaseFromATakenAddress(t *testing.T) {
	store := newExactMatchUserStore(&model.User{
		ID:            "victim-id",
		Email:         "victim@example.com", // as Register stores it
		EmailVerified: false,                // signup mail still outstanding
	})

	rec := oauthCallbackFor(t, store.repo(), &oauth2.UserInfo{
		ID:            "attacker-provider-sub",
		Email:         "Victim@Example.com",
		EmailVerified: true,
		Provider:      "google",
	}, "case-shadow-nonce")

	if len(store.created) != 0 {
		t.Errorf("callback created %d extra account(s) for a mailbox that is already taken: %+v",
			len(store.created), store.created)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d email_already_registered; body: %s",
			rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestOAuth_Callback_WritesTheNormalizedAddressOnAnAccountItCreates is the other
// half. Matching on a folded address is worth nothing if the row this path
// writes keeps the provider's spelling: the account exists but Login,
// forgot-password and the admin import all fold before they query, so none of
// them can find it, and a later Register for the folded spelling inserts a
// second row for the same mailbox without tripping UNIQUE(email).
func TestOAuth_Callback_WritesTheNormalizedAddressOnAnAccountItCreates(t *testing.T) {
	store := newExactMatchUserStore()

	rec := oauthCallbackFor(t, store.repo(), &oauth2.UserInfo{
		ID:            "fresh-provider-sub",
		Email:         "New.User@Example.COM",
		EmailVerified: true,
		Provider:      "google",
	}, "normalized-write-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}
	if len(store.created) != 1 {
		t.Fatalf("created %d accounts, want 1", len(store.created))
	}
	if got := store.created[0].Email; got != "new.user@example.com" {
		t.Errorf("stored email = %q, want %q; every other auth path folds before it queries, "+
			"so this row is unreachable from all of them", got, "new.user@example.com")
	}
}

// TestOAuth_Callback_RefusesAnAddressTheRestOfTheSystemWouldNotAccept closes the
// third gap in the same handful of lines: the address was never validated here.
// Register runs sanitize.Email and refuses anything that is not a single
// well-formed mailbox; this path wrote whatever the provider said into a
// VARCHAR(255) column and passed the same string to the verification mailer as
// an envelope recipient. A hostile or compromised issuer therefore chose both.
func TestOAuth_Callback_RefusesAnAddressTheRestOfTheSystemWouldNotAccept(t *testing.T) {
	for _, tc := range []struct {
		name  string
		email string
	}{
		{"a header injection attempt", "victim@example.com\r\nBcc: attacker@evil.test"},
		{"two addresses in one field", "victim@example.com, attacker@evil.test"},
		{"no domain at all", "not-an-address"},
		{"longer than the email column", "a@" + repeatRune('b', 300) + ".test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newExactMatchUserStore()

			rec := oauthCallbackFor(t, store.repo(), &oauth2.UserInfo{
				ID:            "hostile-provider-sub",
				Email:         tc.email,
				EmailVerified: true,
				Provider:      "google",
			}, "malformed-address-nonce")

			if len(store.created) != 0 {
				t.Errorf("callback wrote an account with email %q", store.created[0].Email)
			}
			if rec.Code == http.StatusFound {
				t.Fatalf("callback issued a session for an address the rest of the system rejects")
			}
		})
	}
}

func repeatRune(r rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = r
	}
	return string(b)
}
