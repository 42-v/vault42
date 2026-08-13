package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The address the probe provider asserts. Nothing else in the package uses it,
// so a delivery to it can only have come from the OAuth signup path.
const oauthSignupEmail = "oauth-signup@example.com"

// sentMail is one delivery the mock sender observed.
type sentMail struct {
	to      string
	subject string
	text    string
}

// oauthMailProbe records what the OAuth signup path handed to the mailer, and
// which row it inserted.
type oauthMailProbe struct {
	mails chan sentMail
	// verifyKey is the cache key the verification token was stored under. It is
	// written on the delivery goroutine before the mail is pushed onto mails, so
	// a test that has received a mail may read it without a race.
	verifyKey string
	// created is the user row the callback inserted, or nil when it inserted none.
	created *model.User
}

// awaitMail returns the next delivery. The send is fire-and-forget on its own
// goroutine (matching the password-signup path), so the test has to wait for it.
func (p *oauthMailProbe) awaitMail(t *testing.T) sentMail {
	t.Helper()
	select {
	case m := <-p.mails:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no mail was sent by the OAuth signup path")
		return sentMail{}
	}
}

// expectNoMail fails when a delivery arrives.
func (p *oauthMailProbe) expectNoMail(t *testing.T) {
	t.Helper()
	select {
	case m := <-p.mails:
		t.Fatalf("an unexpected mail was sent to %q with subject %q", m.to, m.subject)
	case <-time.After(300 * time.Millisecond):
	}
}

// newOAuthSignupHandler wires a callback that creates a brand new account from a
// provider assertion, over a mailer whose deliveries the test observes.
// providerVerified is what the identity provider claims about the address;
// sendErr is what the mailer returns.
func newOAuthSignupHandler(t *testing.T, providerVerified bool, sendErr error) (*OAuthHandler, *oauthMailProbe) {
	t.Helper()

	probe := &oauthMailProbe{mails: make(chan sentMail, 4)}

	provider := &mockProvider{
		name: "facebook",
		userInfoFn: func(context.Context, string) (*oauth2.UserInfo, error) {
			return &oauth2.UserInfo{
				ID:            "idp-account-1",
				Email:         oauthSignupEmail,
				EmailVerified: providerVerified,
				Name:          "New User",
			}, nil
		},
	}

	c := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
		SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
			if strings.HasPrefix(key, "verify:") {
				probe.verifyKey = key
			}
			return nil
		},
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn: func(_ context.Context, u *model.User) error {
			probe.created = u
			return nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			if probe.created != nil {
				return probe.created, nil
			}
			return &model.User{ID: id}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{}
	sender := &mocks.MockEmailSender{
		SendFn: func(_ context.Context, to, subject, _, text string) error {
			probe.mails <- sentMail{to: to, subject: subject, text: text}
			return sendErr
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, c, sender,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)

	h := NewOAuthHandler(
		map[string]oauth2.Provider{"facebook": provider},
		[]byte("test-hmac-secret-32-bytes-long!!"), c, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)
	return h, probe
}

func oauthSignupCallback(t *testing.T, h *OAuthHandler, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	state := validOAuthState(t, "facebook", nonce)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/facebook?state="+state+"&code=c", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.SetPathValue("provider", "facebook")
	req.AddCookie(testOAuthCookie())
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec
}

// A provider that cannot vouch for the address creates an account with
// email_verified false, and until it also mails a verification link that account
// can never become verified: GET /auth/verify-email consumes a token the user
// never received, no resend route exists, and the address is now taken, so a
// later login through a provider that does verify it answers 409
// email_already_registered. The account is unreachable and the address is burned.
func TestOAuth_Callback_SignupWithAnUnverifiedProviderEmailSendsAVerificationMail(t *testing.T) {
	h, probe := newOAuthSignupHandler(t, false, nil)

	rec := oauthSignupCallback(t, h, "unverified-signup-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if probe.created == nil {
		t.Fatal("the callback inserted no user row, so this test is not exercising the signup path")
	}
	if probe.created.EmailVerified {
		t.Fatal("an account created from an unverified provider assertion must not be marked verified")
	}

	m := probe.awaitMail(t)
	if m.to != oauthSignupEmail {
		t.Fatalf("verification mail went to %q, want %q", m.to, oauthSignupEmail)
	}
	if !strings.Contains(m.subject, "Verify") {
		t.Fatalf("subject %q is not the verification template", m.subject)
	}
	if !strings.Contains(m.text, "https://vault.test/verify-email?token=") {
		t.Fatalf("mail body carries no verification link: %s", m.text)
	}
	// A link whose token was never stored verifies nothing, so the mail alone is
	// not the property: the token behind it has to be redeemable.
	if !strings.HasPrefix(probe.verifyKey, "verify:") {
		t.Fatalf("no verification token was stored (cache key %q), so the emailed link is dead on arrival", probe.verifyKey)
	}
}

// Delivery is best effort. A mailer outage must not turn a completed social
// login into an error response: the account exists either way, and failing the
// callback after the row is committed leaves the user with an account they were
// told they do not have.
func TestOAuth_Callback_AVerificationMailFailureDoesNotFailTheSignup(t *testing.T) {
	h, probe := newOAuthSignupHandler(t, false, errors.New("smtp unavailable"))

	rec := oauthSignupCallback(t, h, "mail-failure-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s); a mailer outage must not fail the signup", rec.Code, rec.Body.String())
	}
	probe.awaitMail(t)
	if probe.created == nil {
		t.Fatal("the account must still exist after a failed verification mail")
	}
}

// The trigger is the unverified flag, not "a signup happened". A provider that
// already proved ownership creates a verified account, and mailing a
// verification link to it would ask the user to redo work the IdP already did.
func TestOAuth_Callback_SignupWithAVerifiedProviderEmailSendsNoVerificationMail(t *testing.T) {
	h, probe := newOAuthSignupHandler(t, true, nil)

	rec := oauthSignupCallback(t, h, "verified-signup-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if probe.created == nil || !probe.created.EmailVerified {
		t.Fatal("a verified provider assertion must create a verified account")
	}
	probe.expectNoMail(t)
}
