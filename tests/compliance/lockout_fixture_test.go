package compliance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// The brute-force evidence drives the login path that ships.
//
// Until this fixture, every account-lockout row in the register rested on
// middleware.CheckAccountLockout: an exported helper with one flat counter, a
// caller-supplied threshold, and zero callers outside these suites. The tests
// passed a threshold of 5, or 10, or 100 — whichever the assertion wanted —
// incremented the helper's own key, and asserted the helper counted. Nothing
// about a request was involved, and after the lockout was rekeyed on the source
// address the helper did not even model the same scheme. A control present,
// tested, and not on the path it claims to protect.
//
// The helper is gone. These suites now build a real service.AuthService and
// drive service.AuthService.Login, which is the one function every password
// login in the deployment goes through, plus the exported MFA gate the four
// second-factor handlers call. Thresholds are DISCOVERED by attempting logins
// until the answer changes, never read from a constant and never supplied by
// the test: an assertion that hands the code the number it then checks is an
// assertion about the test.
// =============================================================================

// lockoutPassword is the one password the fixture's accounts accept.
const lockoutPassword = "correct-horse-battery-staple"

// nistConsecutiveFailureCeiling is the bound NIST SP 800-63B 5.2.2 places on
// consecutive failed authentication attempts against a single account when the
// verifier also throttles: no more than 100.
const nistConsecutiveFailureCeiling = 100

// perSourceSearchCeiling bounds the searches that have to restart from a clean
// service for every candidate, and are therefore quadratic in the answer.
//
// It is not a compliance number, it is a stopping condition. It sits just above
// the per-address limit, because a single address that gets more attempts at one
// account than it gets across all accounts is already the finding the search
// would report; running on to 100 would only make the report slower.
const perSourceSearchCeiling = 25

// lockoutFixture is a real AuthService over an in-memory cache and an in-memory
// user table, wired the way NewAuthService wires production.
type lockoutFixture struct {
	svc   *service.AuthService
	users *memUserRepo
	hash  string
}

// memUserRepo is the smallest user table Login needs: lookup by address and by
// id, and a durable failed-login counter, since that column is what the lockout
// falls back to when the cache cannot answer.
type memUserRepo struct {
	mu      sync.Mutex
	byID    map[string]*model.User
	byEmail map[string]*model.User
}

func (r *memUserRepo) add(u *model.User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[u.ID] = u
	r.byEmail[u.Email] = u
}

// newLockoutFixture builds the service. Every account it serves accepts
// lockoutPassword and nothing else.
func newLockoutFixture(t *testing.T) *lockoutFixture {
	t.Helper()
	return newLockoutFixtureWithCache(t, cache.NewMemoryCache())
}

// newLockoutFixtureWithCache is newLockoutFixture with the cache substituted,
// so a test can drive the code path taken when the counter store is down.
func newLockoutFixtureWithCache(t *testing.T, c cache.Cache) *lockoutFixture {
	t.Helper()

	hash, err := vaultcrypto.HashPassword(lockoutPassword)
	if err != nil {
		t.Fatalf("hash the fixture password: %v", err)
	}

	users := &memUserRepo{
		byID:    make(map[string]*model.User),
		byEmail: make(map[string]*model.User),
	}
	repo := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			users.mu.Lock()
			defer users.mu.Unlock()
			u, ok := users.byEmail[email]
			if !ok {
				return nil, nil
			}
			copied := *u
			return &copied, nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			users.mu.Lock()
			defer users.mu.Unlock()
			u, ok := users.byID[id]
			if !ok {
				return nil, nil
			}
			copied := *u
			return &copied, nil
		},
		IncrementFailedLoginFn: func(_ context.Context, id string) error {
			users.mu.Lock()
			defer users.mu.Unlock()
			if u, ok := users.byID[id]; ok {
				u.FailedLoginCount++
			}
			return nil
		},
		ResetFailedLoginFn: func(_ context.Context, id string) error {
			users.mu.Lock()
			defer users.mu.Unlock()
			if u, ok := users.byID[id]; ok {
				u.FailedLoginCount = 0
			}
			return nil
		},
	}

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
		repo, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, audit.NewLogger(&mocks.MockAuditRepo{}, 0), service.NewHIBPClient(),
		c, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)

	t.Cleanup(func() { _ = c.Close() })
	return &lockoutFixture{svc: svc, users: users, hash: hash}
}

// account registers an address the fixture will authenticate, and returns its
// user id.
func (f *lockoutFixture) account(email string) string {
	id := "user-" + email
	f.users.add(&model.User{
		ID: id, Email: email,
		PasswordHash:  f.hash,
		EmailVerified: true,
	})
	return id
}

// login runs the real login path from a source address.
func (f *lockoutFixture) login(email, password, ip string) error {
	_, err := f.svc.Login(context.Background(),
		service.LoginInput{Email: email, Password: password}, ip, "TestAgent")
	return err
}

// fail runs one wrong-password login, and reports nothing: the caller is
// building up state, not making an assertion.
func (f *lockoutFixture) fail(email, ip string) {
	_ = f.login(email, "wrong-password", ip)
}

// loginOutcome is what the login path answered, at the granularity the caller
// can actually observe.
type loginOutcome int

const (
	// loginAccepted: the correct password was accepted. No lock is in force for
	// this (account, source).
	loginAccepted loginOutcome = iota
	// loginMaskedRefusal: ErrInvalidCredentials. This is what a locked account
	// answers, deliberately identical to a wrong password and to an unknown
	// address, so that a lock cannot be read as "this address is registered".
	loginMaskedRefusal
	// loginSourceLocked: ErrAccountLocked. Only the per-source-address lockout
	// answers this, and it answers it before the account is even looked up, so
	// it says nothing about any account.
	loginSourceLocked
)

// probe asks whether the correct password is currently accepted from a source.
//
// A credential that would otherwise work is the only instrument available: a
// locked account is masked as ErrInvalidCredentials on purpose, so "is it
// locked?" cannot be asked with a wrong password.
func (f *lockoutFixture) probe(t *testing.T, email, ip string) loginOutcome {
	t.Helper()
	err := f.login(email, lockoutPassword, ip)
	switch {
	case err == nil:
		return loginAccepted
	case errors.Is(err, service.ErrAccountLocked):
		return loginSourceLocked
	case errors.Is(err, service.ErrInvalidCredentials):
		return loginMaskedRefusal
	default:
		t.Fatalf("login with the correct password from %s returned an unexpected error: %v", ip, err)
		return loginAccepted
	}
}

// perSourceAttemptLimit returns how many consecutive wrong passwords ONE source
// may submit against ONE account before that source stops being able to log in
// with the correct password.
//
// It counts rather than comparing against a constant. A test that is handed the
// threshold and then checks the code agrees with it is an assertion about the
// test; this one reports what the shipped code enforces, and the caller decides
// whether that number is acceptable.
//
// Each trial runs against a fresh fixture, so the account-wide counter and the
// per-source-address counter left behind by earlier trials cannot be what ends
// the search. A trial that is refused with ErrAccountLocked means the per-source
// ADDRESS lockout got there first and the per-source ACCOUNT lockout was never
// demonstrated: that is reported as a failure, not returned as the limit.
func perSourceAttemptLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const (
		email = "limit-probe@example.com"
		ip    = "198.51.100.11"
	)
	for n := 1; n <= ceiling; n++ {
		f := newLockoutFixture(t)
		f.account(email)
		for i := 0; i < n; i++ {
			f.fail(email, ip)
		}
		switch f.probe(t, email, ip) {
		case loginAccepted:
			continue
		case loginSourceLocked:
			t.Fatalf("after %d failures against one account, %s was refused by the per-source ADDRESS "+
				"lockout before the per-account one engaged. The per-account limit for a single source "+
				"is therefore unmeasured and at least %d.", n, ip, n)
		case loginMaskedRefusal:
			return n
		}
	}
	t.Fatalf("one source submitted %d consecutive wrong passwords against one account and the correct "+
		"password was still accepted: there is no per-source attempt limit", ceiling)
	return 0
}

// accountWideAttemptLimit returns how many failures spread across DISTINCT
// sources one account absorbs before every source is refused, including sources
// that have never failed against it.
//
// Each failure comes from its own address, so no address approaches the
// per-source limit and only the account-wide counter can be what trips. After
// each failure a fresh, unused address offers the correct password: success
// there proves the account is still open, and it neither advances the
// account-wide counter (only failures do) nor clears it (only its TTL does).
func accountWideAttemptLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const email = "distributed-probe@example.com"
	f := newLockoutFixture(t)
	f.account(email)

	for n := 1; n <= ceiling; n++ {
		f.fail(email, fmt.Sprintf("198.51.%d.%d", 100+n/250, n%250))
		switch f.probe(t, email, fmt.Sprintf("203.0.%d.%d", 113+n/250, n%250)) {
		case loginAccepted:
			continue
		case loginSourceLocked:
			t.Fatalf("the probing address was itself refused after %d attempts; it should have been a "+
				"fresh address with no failures against it", n)
		case loginMaskedRefusal:
			return n
		}
	}
	t.Fatalf("%d failures from %d distinct addresses did not lock the account: rotating the source "+
		"address buys an attacker unlimited guesses", ceiling, ceiling)
	return 0
}

// sourceAddressAttemptLimit returns how many failed logins one address may
// submit across DIFFERENT accounts before the address itself is refused.
//
// This is the control that answers password spraying, where no single account
// ever reaches its own limit. Every attempt targets a different account, so the
// per-account counters stay at one and only the per-address counter can trip.
func sourceAddressAttemptLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const ip = "198.51.100.22"
	f := newLockoutFixture(t)

	for n := 1; n <= ceiling; n++ {
		email := fmt.Sprintf("sprayed-%d@example.com", n)
		f.account(email)
		f.fail(email, ip)

		// A brand-new account, never attacked, asked from the spraying address.
		fresh := fmt.Sprintf("bystander-%d@example.com", n)
		f.account(fresh)
		switch f.probe(t, fresh, ip) {
		case loginAccepted:
			continue
		case loginSourceLocked:
			return n
		case loginMaskedRefusal:
			t.Fatalf("a never-attacked account was refused from %s after %d attempts against OTHER "+
				"accounts: the per-address limit is leaking into per-account state", ip, n)
		}
	}
	t.Fatalf("one address submitted %d failed logins across %d different accounts and was never "+
		"refused: password spraying from a single address is unbounded", ceiling, ceiling)
	return 0
}

// unreadableCache is a cache whose reads fail the way a refused connection or a
// timeout fails: with a real error, not with ErrNotFound.
//
// The distinction is the whole point. Every backend reports a missing key as
// ErrNotFound, and a missing key is what an account with no recent failures
// looks like — the overwhelming majority of logins. Only a genuine read fault
// may fall back to the durable counter. Writes still succeed here, so the test
// exercises the read path being broken rather than the counter never being
// written.
type unreadableCache struct{ cache.Cache }

func (unreadableCache) Get(context.Context, string) (string, error) {
	return "", errors.New("cache: connection refused")
}
