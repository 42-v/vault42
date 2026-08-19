package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The reset-from-email escape has to actually escape, from every address.
//
// The account lockout is keyed on (account, source address), and there is one
// counter per address with no way to enumerate them: the cache interface has no
// scan. The reset path used to delete the account-wide key and nothing else, so
// a user who locked themselves out and reset their password was still refused
// from the machine they were sitting at, for up to fifteen minutes, behind
// ErrInvalidCredentials — the same answer as a wrong password. The obvious
// conclusion is that the reset did not work, and the obvious next step is to
// reset again, which changes nothing.
//
// The address the reset link is opened on is usually not the address that got
// locked out. Someone locked out on their laptop opens the email on their phone.
// So clearing the requesting source would not fix the journey people actually
// take; the clear has to reach every source at once.

// resetLockoutFixture is one cache and one user table shared by a real
// AuthService and a real PasswordHandler, which is the coupling under test: the
// handler writes the state the service reads.
type resetLockoutFixture struct {
	svc   *service.AuthService
	h     *PasswordHandler
	cache cache.Cache
	uid   string
	email string
}

func newResetLockoutFixture(t *testing.T, oldPassword string) *resetLockoutFixture {
	t.Helper()

	const (
		email = "locked-out@example.com"
		uid   = "user-locked-out"
	)
	hash, err := vaultcrypto.HashPassword(oldPassword, "")
	if err != nil {
		t.Fatalf("hash the fixture password: %v", err)
	}

	var mu sync.Mutex
	user := &model.User{ID: uid, Email: email, PasswordHash: hash, EmailVerified: true}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, e string) (*model.User, error) {
			mu.Lock()
			defer mu.Unlock()
			if e != email {
				return nil, nil
			}
			c := *user
			return &c, nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			mu.Lock()
			defer mu.Unlock()
			if id != uid {
				return nil, nil
			}
			c := *user
			return &c, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, h string) error {
			mu.Lock()
			defer mu.Unlock()
			user.PasswordHash = h
			return nil
		},
		IncrementFailedLoginFn: func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()
			user.FailedLoginCount++
			return nil
		},
		ResetFailedLoginFn: func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()
			user.FailedLoginCount = 0
			return nil
		},
	}

	mem := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mem.Close() })

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate the fixture signing key: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("generate the fixture kid: %v", err)
	}
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)

	svc := service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, audit.NewLogger(&mocks.MockAuditRepo{}, 0), service.NewHIBPClient(),
		mem, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 12, false, nil,
	)

	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), mem,
		"https://vault.test", "TestVault", "", 12, nil, false,
	)

	return &resetLockoutFixture{svc: svc, h: h, cache: mem, uid: uid, email: email}
}

func (f *resetLockoutFixture) login(password, ip string) error {
	_, err := f.svc.Login(context.Background(),
		service.LoginInput{Email: f.email, Password: password}, ip, "TestAgent")
	return err
}

// lockedTo reports the lockout decision for one source without side effects.
// MFAVerifyLocked is the exported read-only view of the same isAccountLocked
// call the login path makes, so this asks the production predicate directly
// rather than spending an Argon2 hash and a progressive-delay sleep on a login
// whose answer is already known.
func (f *resetLockoutFixture) lockedTo(ip string) bool {
	return f.svc.MFAVerifyLocked(httputil.WithClientIP(context.Background(), ip), f.uid)
}

// resetPassword drives the real reset-confirm handler with a freshly minted
// token, from an address of its own — the phone, in the journey this test is
// about.
func (f *resetLockoutFixture) resetPassword(t *testing.T, newPassword, fromIP string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		t.Fatalf("mint a reset token: %v", err)
	}
	if err := f.cache.Set(context.Background(), "reset:"+vaultcrypto.SHA256Hex(token), f.uid, time.Hour); err != nil {
		t.Fatalf("seed the reset token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset-confirm",
		jsonBody(t, map[string]string{"token": token, "password": newPassword}))
	req.RemoteAddr = fromIP + ":54321"
	rec := httptest.NewRecorder()
	f.h.ResetConfirm(rec, req)
	return rec
}

func TestResetConfirm_ClearsTheLockoutOnEverySource(t *testing.T) {
	const (
		oldPassword = "correct-horse-battery-staple"
		newPassword = "a-brand-new-passphrase-entirely"
		laptopIP    = "203.0.113.10"
		deskIP      = "203.0.113.11"
		phoneIP     = "198.51.100.77"
		cafeIP      = "192.0.2.50"
	)
	f := newResetLockoutFixture(t, oldPassword)

	// Lock two of the user's own addresses. Five wrong passwords each, which is
	// what mistyping a password on two machines looks like.
	for _, ip := range []string{laptopIP, deskIP} {
		for i := 0; i < 5; i++ {
			_ = f.login("wrong-password", ip)
		}
		if !f.lockedTo(ip) {
			t.Fatalf("five wrong passwords from %s did not lock that source; the test has no lockout to clear", ip)
		}
	}
	// Observed once through the login path proper, so the precondition is not
	// resting entirely on the read-only view.
	if err := f.login(oldPassword, laptopIP); err == nil {
		t.Fatal("the correct password still worked from the locked laptop; there is no lockout to clear")
	}

	// The reset link is opened on the phone, which is neither of the locked
	// addresses. This is the ordinary case, not the awkward one.
	if rec := f.resetPassword(t, newPassword, phoneIP); rec.Code != http.StatusOK {
		t.Fatalf("reset-confirm returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// The whole point: the user goes back to the machine they were locked out
	// on and logs in with the password they just chose.
	for _, ip := range []string{laptopIP, deskIP, phoneIP, cafeIP} {
		if f.lockedTo(ip) {
			t.Errorf("%s is still locked out after a completed password reset", ip)
		}
	}
	if err := f.login(newPassword, laptopIP); err != nil {
		t.Errorf("the user reset their password and still could not log in from %s, the machine they "+
			"were locked out on: %v. The refusal is masked as a wrong password, so they will conclude "+
			"the reset failed and reset again, which clears nothing.", laptopIP, err)
	}
	if err := f.login(newPassword, deskIP); err != nil {
		t.Errorf("still locked out from the second source %s after a completed reset: %v", deskIP, err)
	}
}

// lockoutClearFailsCache is a cache that answers everything except the
// generation advance, which is the write ClearAccountLockout needs to retire the
// per-source counters.
type lockoutClearFailsCache struct {
	cache.Cache
}

func (c lockoutClearFailsCache) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("cache refused the counter")
}

// A reset whose lockout clear fails must still reset the password.
//
// The clear is best-effort by design: the user has proven ownership of the
// mailbox and chosen a new credential, and refusing to store it because a cache
// write failed would turn a degraded cache into an account nobody can recover.
// The failure is logged rather than swallowed, so an operator can see that these
// users are still serving out their lockout.
func TestResetConfirm_SucceedsWhenTheLockoutClearFails(t *testing.T) {
	f := newResetLockoutFixture(t, "the-old-passphrase-42")
	f.h.cache = lockoutClearFailsCache{Cache: f.cache}

	rec := f.resetPassword(t, "an-entirely-new-passphrase-42", "203.0.113.99")

	if rec.Code != http.StatusOK {
		t.Fatalf("reset-confirm status = %d with a cache that refuses the generation advance, "+
			"want 200: the credential is stored and the clear is best-effort", rec.Code)
	}
}
