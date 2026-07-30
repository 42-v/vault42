package handler

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range API is defined over SHA-1; the test has to speak it
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// acctHIBPTransport stands in for api.pwnedpasswords.com. The HIBP client is built
// with a zero-value http.Client, so it dials through http.DefaultTransport and this
// is the seam. body is the k-anonymity range response; when err is set the request
// fails instead, which is how the outage case is reproduced.
type acctHIBPTransport struct {
	body string
	err  error
}

func (tr *acctHIBPTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if tr.err != nil {
		return nil, tr.err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(tr.body)),
		Header:     make(http.Header),
	}, nil
}

func acctInstallHIBP(t *testing.T, tr *acctHIBPTransport) {
	t.Helper()
	original := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = original })
}

// acctBreachedRange returns a range response that reports password as breached.
func acctBreachedRange(password string) string {
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- HIBP protocol is SHA-1
	full := fmt.Sprintf("%X", sum)
	return "0000000000000000000000000000000000:1\r\n" + full[5:] + ":49810"
}

func acctBreachPasswordHandler(t *testing.T, users *mocks.MockUserRepo, history *mocks.MockPasswordHistoryRepo, c *mocks.MockCache) *PasswordHandler {
	t.Helper()
	return NewPasswordHandler(
		users, history, &mocks.MockRefreshTokenRepo{}, &mocks.MockEmailSender{},
		newTestAuditLogger(), c, "https://vault.test", "TestVault", "", 15,
		service.NewHIBPClient(), true,
	)
}

// A password that is already in a breach corpus is not a password, it is a known
// credential. NIST SP 800-63B makes the breach check the one composition rule that
// survives, and vault42 runs it on every path that sets a password.
//
// The check has to run on the *new* password on all three of them: registration, the
// authenticated change, and the reset-link confirm. The reset path is the one that
// matters most — that is where a user who has just been told their password leaked
// goes to type it back in. Each case pins that the write never happens and that the
// caller is told why.
func TestSetPassword_BreachedPasswordIsRejectedOnEveryPath(t *testing.T) {
	const breached = "trustno1 trustno1 trustno1"
	acctInstallHIBP(t, &acctHIBPTransport{body: acctBreachedRange(breached)})

	t.Run("register", func(t *testing.T) {
		created := false
		users := &mocks.MockUserRepo{
			GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
			CreateFn: func(context.Context, *model.User) error {
				created = true
				return nil
			},
		}
		tokenSvc, _ := newTestTokenService(t)
		c := &mocks.MockCache{}
		svc := service.NewAuthService(
			users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, newTestAuditLogger(),
			service.NewHIBPClient(), c, nil, "https://vault.test", "TestVault", "", 15, true, nil,
		)
		h := NewAuthHandler(svc, users, c, newTestAuditLogger(), "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]string{
			"email": "newcomer@example.com", "password": breached,
		}))
		rec := httptest.NewRecorder()
		h.Register(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
		}
		if got := acctErrorCode(t, rec); got != "password_breached" {
			t.Errorf("error = %q, want password_breached", got)
		}
		if created {
			t.Error("an account was created with a password that is already in a breach corpus")
		}
	})

	t.Run("reset_confirm", func(t *testing.T) {
		written := false
		users := &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "reset@example.com"}, nil
			},
			UpdatePasswordFn: func(context.Context, string, string) error {
				written = true
				return nil
			},
		}
		c := &mocks.MockCache{
			GetAndDeleteFn: func(context.Context, string) (string, error) { return "user-reset", nil },
		}
		h := acctBreachPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{}, c)

		req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", jsonBody(t, map[string]string{
			"token": "a-live-reset-token", "password": breached,
		}))
		rec := httptest.NewRecorder()
		h.ResetConfirm(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
		}
		if got := acctErrorCode(t, rec); got != "password_breached" {
			t.Errorf("error = %q, want password_breached", got)
		}
		if written {
			t.Error("a reset stored a password that is already in a breach corpus")
		}
	})

	t.Run("change_password", func(t *testing.T) {
		const current = "an entirely unremarkable passphrase"
		hash, err := vaultcrypto.HashPassword(current)
		if err != nil {
			t.Fatalf("precompute password hash: %v", err)
		}
		written := false
		users := &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "change@example.com", PasswordHash: hash}, nil
			},
			UpdatePasswordFn: func(context.Context, string, string) error {
				written = true
				return nil
			},
		}
		h := acctBreachPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockCache{})

		req := httptest.NewRequest(http.MethodPost, "/user/password", jsonBody(t, map[string]string{
			"current_password": current, "new_password": breached,
		}))
		req = setAuthContext(req, "user-change")
		rec := httptest.NewRecorder()
		h.ChangePassword(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
		}
		if got := acctErrorCode(t, rec); got != "password_breached" {
			t.Errorf("error = %q, want password_breached", got)
		}
		if written {
			t.Error("a change stored a password that is already in a breach corpus")
		}
	})
}

// The breach check is deliberately fail-open: HIBP being unreachable must not stop
// people setting a password. That is a documented accepted tradeoff, not an accident,
// and it is worth pinning in both directions — a change that made an api.pwnedpasswords.com
// outage start rejecting every password reset would take the whole recovery flow down
// with it, and nobody would notice until the outage happened.
func TestSetPassword_BreachCheckOutageFailsOpen(t *testing.T) {
	acctInstallHIBP(t, &acctHIBPTransport{err: errors.New("dial tcp: no route to host")})

	written := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "reset@example.com"}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error {
			written = true
			return nil
		},
	}
	c := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "user-reset", nil },
	}
	h := acctBreachPasswordHandler(t, users, &mocks.MockPasswordHistoryRepo{}, c)

	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", jsonBody(t, map[string]string{
		"token": "a-live-reset-token", "password": "a perfectly fine new passphrase",
	}))
	rec := httptest.NewRecorder()
	h.ResetConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an HIBP outage blocked a password reset; body: %s", rec.Code, rec.Body.String())
	}
	if !written {
		t.Error("the new password was never stored")
	}
}

// Password history exists so that "change your password" cannot be satisfied by
// changing it to the same one. The comparison is an Argon2id verify against the
// stored history hashes, and it has to reject before anything is written.
func TestChangePassword_RecentlyUsedPasswordIsRejected(t *testing.T) {
	const current = "an entirely unremarkable passphrase"
	const reused = "the passphrase from two changes ago"

	currentHash, err := vaultcrypto.HashPassword(current)
	if err != nil {
		t.Fatalf("precompute current hash: %v", err)
	}
	reusedHash, err := vaultcrypto.HashPassword(reused)
	if err != nil {
		t.Fatalf("precompute history hash: %v", err)
	}

	written := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "change@example.com", PasswordHash: currentHash}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error {
			written = true
			return nil
		},
	}
	history := &mocks.MockPasswordHistoryRepo{
		GetRecentByUserFn: func(context.Context, string, int) ([]*model.PasswordHistory, error) {
			return []*model.PasswordHistory{{ID: "ph-1", UserID: "user-change", PasswordHash: reusedHash}}, nil
		},
	}
	h := newTestPasswordHandler(t, users, history)

	req := httptest.NewRequest(http.MethodPost, "/user/password", jsonBody(t, map[string]string{
		"current_password": current, "new_password": reused,
	}))
	req = setAuthContext(req, "user-change")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if got := acctErrorCode(t, rec); got != "password_recently_used" {
		t.Errorf("error = %q, want password_recently_used", got)
	}
	if written {
		t.Error("a password already in the user's history was stored again")
	}
}
