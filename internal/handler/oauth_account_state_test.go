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
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// oauthGateOutcome records everything the callback did with one account state,
// so a case can assert on the refusal AND on the side effects a refusal must
// suppress (import claim, 2FA challenge).
type oauthGateOutcome struct {
	rec           *httptest.ResponseRecorder
	cleared       bool
	clearedForced bool
	location      string
}

// oauthGateCase drives one account state through the callback. mfaSvc and the
// lockout counter are per-case because two of the states below are only
// reachable through them: a locked user who also has MFA, and the cache
// auto-lockout that password login consults alongside users.locked_until.
type oauthGateCase struct {
	user *model.User
	// lockoutCount, when non-empty, is what the cache returns for the
	// "lockout:<user>" key AuthService keeps its auto-lockout counter under.
	lockoutCount string
	mfaSvc       *service.MFAService
}

func runOAuthGate(t *testing.T, c oauthGateCase) oauthGateOutcome {
	t.Helper()

	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", "acct-nonce", expiry, hmacSecret)

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: c.user.ID}, nil
		},
	}
	out := oauthGateOutcome{}
	users := &mocks.MockUserRepo{
		GetByIDFn:            func(context.Context, string) (*model.User, error) { return c.user, nil },
		ClearImportPendingFn: func(context.Context, string) error { out.cleared = true; return nil },
		ClearMustResetPwFn:   func(context.Context, string) error { out.clearedForced = true; return nil },
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
		GetFn: func(_ context.Context, key string) (string, error) {
			// Prefix: the hard lock reads lockout:<user>|<source>, and the
			// account-wide counter it also consults is lockout:<user>.
			if c.lockoutCount != "" && strings.HasPrefix(key, "lockout:"+c.user.ID) {
				return c.lockoutCount, nil
			}
			return "", nil
		},
	}

	opts := []func(*oauthSetup){withCache(cache), withSocial(social), withUsers(users)}
	if c.mfaSvc != nil {
		opts = append(opts, withMFA(c.mfaSvc))
	}
	h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": &mockProvider{name: "google"}}, opts...)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.SetPathValue("provider", "google")
	req.AddCookie(testOAuthCookie())
	rec := httptest.NewRecorder()
	h.Callback(rec, req)

	out.rec = rec
	out.location = rec.Header().Get("Location")
	return out
}

// mfaRequiredService returns an MFAService that reports every user as having a
// verified second factor, so the callback takes its challenge-token branch.
func mfaRequiredService() *service.MFAService {
	return service.NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
}

// 2nd-pass review: the OAuth callback must enforce the same account-state gates
// as password login + refresh, so that OAuth is not a bypass for a banned,
// disabled, deleted or locked account, and must claim (not silently ignore) an
// import_pending account.
//
// The lock cases are the regression this file exists to prevent a second time.
// The gate here checked three of the four states and its comment claimed parity
// with password login, so POST /admin/users/{id}/lock, which internal/rbac
// documents as the first response to a suspected takeover, stopped password
// login and refresh and left the social path issuing brand new token families to
// the attacker whose linked identity was the reason for the lock.
func TestOAuth_Callback_AccountStateGate(t *testing.T) {
	lockedUntil := time.Now().Add(1 * time.Hour)
	staleLock := time.Now().Add(-1 * time.Hour)

	t.Run("banned -> 403", func(t *testing.T) {
		if out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u1", EmailVerified: true, Banned: true}}); out.rec.Code != http.StatusForbidden {
			t.Fatalf("banned must be 403, got %d", out.rec.Code)
		}
	})
	t.Run("disabled -> 403", func(t *testing.T) {
		if out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u2", EmailVerified: true, Disabled: true}}); out.rec.Code != http.StatusForbidden {
			t.Fatalf("disabled must be 403, got %d", out.rec.Code)
		}
	})
	t.Run("deleted -> 403", func(t *testing.T) {
		if out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u3", EmailVerified: true, Deleted: true}}); out.rec.Code != http.StatusForbidden {
			t.Fatalf("deleted must be 403, got %d", out.rec.Code)
		}
	})
	t.Run("import_pending claimed, not blocked", func(t *testing.T) {
		out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u4", EmailVerified: true, ImportPending: true}})
		if out.rec.Code == http.StatusForbidden {
			t.Fatalf("import_pending should be claimed + proceed, got 403: %s", out.rec.Body.String())
		}
		if !out.cleared {
			t.Fatalf("import_pending account should be claimed (ClearImportPending) on OAuth login")
		}
	})

	t.Run("admin lock -> 403 account_locked", func(t *testing.T) {
		out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u5", EmailVerified: true, LockedUntil: &lockedUntil}})
		if out.rec.Code != http.StatusForbidden {
			t.Fatalf("SECURITY: locked account completed OAuth login, got %d %s (Location=%q); "+
				"an operator's lock does not contain an attacker who holds a linked social identity",
				out.rec.Code, out.rec.Body.String(), out.location)
		}
		if body := out.rec.Body.String(); !strings.Contains(body, "account_locked") {
			t.Fatalf("locked account must answer account_locked like login/refresh/MFA, got %s", body)
		}
	})

	t.Run("cache auto-lockout -> 403 account_locked", func(t *testing.T) {
		// Password login refuses on either source: users.locked_until OR the
		// cache counter the failed-password path trips. Checking only the column
		// leaves the social path usable during an active password brute force.
		out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u6", EmailVerified: true}, lockoutCount: "9"})
		if out.rec.Code != http.StatusForbidden {
			t.Fatalf("SECURITY: auto-locked-out account completed OAuth login, got %d %s",
				out.rec.Code, out.rec.Body.String())
		}
		if body := out.rec.Body.String(); !strings.Contains(body, "account_locked") {
			t.Fatalf("auto-lockout must answer account_locked, got %s", body)
		}
	})

	t.Run("expired lock proceeds", func(t *testing.T) {
		// The refusal is bounded by the timestamp, exactly as in Login. A gate
		// that read LockedUntil without comparing it to now would lock users out
		// forever after their first lockout expired.
		out := runOAuthGate(t, oauthGateCase{user: &model.User{ID: "u7", EmailVerified: true, LockedUntil: &staleLock}})
		if out.rec.Code != http.StatusFound {
			t.Fatalf("an expired lock must not refuse, got %d %s", out.rec.Code, out.rec.Body.String())
		}
	})

	t.Run("locked user gets no 2FA challenge", func(t *testing.T) {
		// A challenge token is a bearer credential with its own TTL. Minting one
		// for a locked account hands the attacker a second window to finish in,
		// even though CompleteMFALogin would refuse: the refusal belongs here, at
		// the point where the callback decides the account may authenticate.
		out := runOAuthGate(t, oauthGateCase{
			user:   &model.User{ID: "u8", EmailVerified: true, LockedUntil: &lockedUntil},
			mfaSvc: mfaRequiredService(),
		})
		if out.rec.Code != http.StatusForbidden {
			t.Fatalf("SECURITY: locked MFA user was not refused, got %d (Location=%q)", out.rec.Code, out.location)
		}
		if strings.Contains(out.location, "challenge_token=") {
			t.Fatalf("SECURITY: locked account was issued a 2fa challenge token: %q", out.location)
		}
	})

	t.Run("locked import_pending is not claimed", func(t *testing.T) {
		// Claiming writes import_pending=false, which is the irreversible half of
		// the flow. A locked row must come out of the callback in the state it
		// went in, so the operator's lock still means something after it lifts.
		out := runOAuthGate(t, oauthGateCase{
			user: &model.User{ID: "u9", EmailVerified: true, ImportPending: true, LockedUntil: &lockedUntil},
		})
		if out.rec.Code != http.StatusForbidden {
			t.Fatalf("SECURITY: locked import_pending account completed OAuth login, got %d %s",
				out.rec.Code, out.rec.Body.String())
		}
		if out.cleared {
			t.Fatalf("SECURITY: ClearImportPending ran on a locked account; the lock was " +
				"supposed to stop the claim, not merely the session")
		}
	})
}

// A social login proves the person controls the linked provider account. It does
// not produce a new password, and it does not make the old one safe, so it must
// not lift a forced password reset.
//
// The asymmetry with import_pending directly above is deliberate and is the
// whole point. import_pending means there is no credential on the account at
// all, so claiming it through a provider costs nothing: nothing unsafe is left
// live afterwards. must_reset_password means there IS a stored password and it
// must not be used -- an unverifiable legacy hash, or one an operator has reason
// to distrust. Clearing it here would re-open the password path on the strength
// of a factor that says nothing about the password, which is the one thing the
// flag exists to prevent.
//
// The social login itself is not refused. The flag gates the password
// credential, not the account: a user with a working provider identity keeps it,
// and still has to complete a reset before password login works again.
func TestOAuth_Callback_DoesNotLiftAForcedPasswordReset(t *testing.T) {
	out := runOAuthGate(t, oauthGateCase{
		user: &model.User{ID: "u-forced", EmailVerified: true, MustResetPassword: true},
	})

	if out.rec.Code == http.StatusForbidden {
		t.Fatalf("the social login was refused (%d): the flag gates the password, not the "+
			"account: %s", out.rec.Code, out.rec.Body.String())
	}
	if out.clearedForced {
		t.Error("a social login lifted the forced password reset, so a hash vault42 was told not " +
			"to trust is live again without anyone setting a new password")
	}
}
