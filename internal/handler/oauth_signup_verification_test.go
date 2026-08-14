package handler

import (
	"context"
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

// oauthSignupProbe records what the OAuth callback did with a provider assertion:
// whether it consulted the directory (emailLookups), which row it created, and
// any mail it sent.
type oauthSignupProbe struct {
	mails        chan sentMail
	created      *model.User
	emailLookups int
}

// expectNoMail fails when a delivery arrives.
func (p *oauthSignupProbe) expectNoMail(t *testing.T) {
	t.Helper()
	select {
	case m := <-p.mails:
		t.Fatalf("an unexpected mail was sent to %q with subject %q", m.to, m.subject)
	case <-time.After(300 * time.Millisecond):
	}
}

// newOAuthSignupHandler wires a facebook-style first-time callback over observable
// mocks. providerVerified is what the IdP asserts about the address; existingUser
// is what a lookup by that address would return (nil = a free address). The
// GetByEmail counter proves whether the handler consulted the directory at all.
func newOAuthSignupHandler(t *testing.T, providerVerified bool, existingUser *model.User) (*OAuthHandler, *oauthSignupProbe) {
	t.Helper()

	probe := &oauthSignupProbe{mails: make(chan sentMail, 4)}

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
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) {
			probe.emailLookups++
			return existingUser, nil
		},
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
	// If the callback ever mails on a first-time provider assertion it is a bug
	// (unverified providers no longer provision; verified ones need no mail), so
	// every delivery this sender sees is a test failure via expectNoMail.
	sender := &mocks.MockEmailSender{
		SendFn: func(_ context.Context, to, subject, _, text string) error {
			probe.mails <- sentMail{to: to, subject: subject, text: text}
			return nil
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

// A provider that cannot prove the caller owns the address (Facebook publishes no
// per-address verification signal; an OIDC issuer may answer email_verified:false)
// must not auto-provision an account on a first-time callback. The address is
// attacker-supplied, so creating on it squats a stranger's mailbox and mails them.
// The handler returns a neutral verification-required redirect, creates nothing,
// consults no directory, and sends no mail.
func TestOAuth_Callback_UnverifiedProviderDoesNotAutoProvision(t *testing.T) {
	h, probe := newOAuthSignupHandler(t, false, nil)

	rec := oauthSignupCallback(t, h, "unverified-signup-nonce")

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "/oauth/callback#error=verification_required") {
		t.Fatalf("redirect %q, want the neutral verification-required outcome", loc)
	}
	if probe.created != nil {
		t.Fatalf("an unverified provider assertion must not create an account, created %+v", probe.created)
	}
	if probe.emailLookups != 0 {
		t.Fatalf("the address was looked up %d time(s); the refusal must precede the existence check so it cannot leak registration", probe.emailLookups)
	}
	probe.expectNoMail(t)
}

// The refusal must be identical whether or not the address is registered, and it
// must not even consult the directory: the lookup is the enumeration oracle this
// closes. A registered address and a free one produce the same response and the
// same (absent) side effects. Red-first parity across the existence boundary.
func TestOAuth_Callback_UnverifiedProviderRefusalDoesNotLeakExistence(t *testing.T) {
	registered := &model.User{ID: "victim-1", Email: oauthSignupEmail, EmailVerified: true}

	run := func(t *testing.T, existing *model.User) (int, string, bool, int) {
		t.Helper()
		h, probe := newOAuthSignupHandler(t, false, existing)
		rec := oauthSignupCallback(t, h, "parity-nonce")
		probe.expectNoMail(t)
		return rec.Code, rec.Header().Get("Location"), probe.created != nil, probe.emailLookups
	}

	codeFree, locFree, createdFree, lookupsFree := run(t, nil)
	codeReg, locReg, createdReg, lookupsReg := run(t, registered)

	if codeFree != codeReg || locFree != locReg {
		t.Fatalf("registered vs free diverge: (%d %q) vs (%d %q) — an observable difference is an enumeration oracle", codeReg, locReg, codeFree, locFree)
	}
	if createdFree || createdReg {
		t.Fatalf("neither case may create an account (free=%v registered=%v)", createdFree, createdReg)
	}
	if lookupsFree != 0 || lookupsReg != 0 {
		t.Fatalf("the address was looked up (free=%d registered=%d); the refusal must not consult existence", lookupsFree, lookupsReg)
	}
}

// A provider that already proved ownership still creates a verified account and
// sends no verification mail: the guard only refuses UNVERIFIED first-time
// assertions.
func TestOAuth_Callback_VerifiedProviderCreatesVerifiedAccountNoMail(t *testing.T) {
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
