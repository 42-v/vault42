package attack

import (
	"context"
	"errors"
	"fmt"
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
// The brute-force attack suite drives the login path that ships.
//
// Every lockout test in this package used to call middleware.CheckAccountLockout
// — an exported helper implementing one flat counter at a threshold the test
// supplied itself, with no callers anywhere in the binary. The tests picked a
// threshold of 5, or 3, or 100, incremented the helper's own cache key, and
// asserted the helper had counted. No request, no service, no decision: the
// password-spray test could not have noticed if spraying worked.
//
// The helper is deleted. These tests now build a real service.AuthService and
// attack service.AuthService.Login, which is where every password login in the
// deployment goes, and service.AuthService.RecordMFAFailure /
// MFAVerifyLocked, which is the gate the four second-factor handlers call.
//
// Production runs three counters, and an attack suite has to know which one it
// is defeating:
//
//   - (account, source address) — the ordinary brute-force lock. Low limit.
//     Locks only the address that earned it, so it cannot be aimed at a victim.
//   - account, all sources — the distributed lock. Ten times higher, reachable
//     only by rotating addresses, and the reason rotation is not a bypass.
//   - source address, all accounts — the spray lock. Answers the attack where
//     no account ever reaches its own limit.
// =============================================================================

const attackPassword = "correct-horse-battery-staple"

// atkSearchCeiling bounds the searches that restart from a clean service for
// every candidate and are therefore quadratic in the answer. It is a stopping
// condition, not a compliance number: an address that gets more attempts at one
// account than it gets across every account is already the finding, and running
// on would only make the report slower.
const atkSearchCeiling = 25

// atkLockout is a real AuthService over an in-memory cache and the stub user
// table already used by this package.
type atkLockout struct {
	svc   *service.AuthService
	users *stubUserRepo
	hash  string
}

func newAtkLockout(t *testing.T) *atkLockout {
	t.Helper()
	return newAtkLockoutWithCache(t, cache.NewMemoryCache())
}

// newAtkLockoutWithCache substitutes the cache, so a test can attack the
// deployment as it behaves while the counter store is down.
func newAtkLockoutWithCache(t *testing.T, c cache.Cache) *atkLockout {
	t.Helper()

	hash, err := vaultcrypto.HashPassword(attackPassword)
	if err != nil {
		t.Fatalf("hash the fixture password: %v", err)
	}
	users := newStubUserRepo()

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
		c, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)

	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return &atkLockout{svc: svc, users: users, hash: hash}
}

// account registers an address the fixture will authenticate, returning its
// user id.
func (a *atkLockout) account(email string) string {
	id := "user-" + email
	_ = a.users.Create(context.Background(), &model.User{
		ID: id, Email: email,
		PasswordHash:  a.hash,
		EmailVerified: true,
	})
	return id
}

func (a *atkLockout) login(email, password, ip string) error {
	_, err := a.svc.Login(context.Background(),
		service.LoginInput{Email: email, Password: password}, ip, "AttackAgent")
	return err
}

// guess submits one wrong password, the way an attacker's loop does.
func (a *atkLockout) guess(email, ip string) {
	_ = a.login(email, "wrong-password", ip)
}

// atkOutcome is what the login path answered, at the granularity an attacker
// can observe from outside.
type atkOutcome int

const (
	// atkAdmitted: the correct password was accepted. No lock is in force for
	// this (account, source).
	atkAdmitted atkOutcome = iota
	// atkMasked: ErrInvalidCredentials — what a locked account answers, made
	// deliberately identical to a wrong password and to an unknown address.
	atkMasked
	// atkAddressLocked: ErrAccountLocked — only the per-address lockout answers
	// this, and it answers before any account is looked up.
	atkAddressLocked
)

// canReach asks whether a source can still authenticate an account, using the
// correct password because that is the only instrument: a locked account is
// masked as a wrong password on purpose.
func (a *atkLockout) canReach(t *testing.T, email, ip string) atkOutcome {
	t.Helper()
	err := a.login(email, attackPassword, ip)
	switch {
	case err == nil:
		return atkAdmitted
	case errors.Is(err, service.ErrAccountLocked):
		return atkAddressLocked
	case errors.Is(err, service.ErrInvalidCredentials):
		return atkMasked
	default:
		t.Fatalf("login with the correct password from %s returned an unexpected error: %v", ip, err)
		return atkAdmitted
	}
}

// atkPerSourceLimit is how many wrong passwords one address may submit against
// one account before that address loses it, measured against a throwaway
// service so nothing an earlier test did can be what ends the search.
func atkPerSourceLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const (
		email = "atk-limit-probe@example.com"
		ip    = "198.51.100.101"
	)
	for n := 1; n <= ceiling; n++ {
		a := newAtkLockout(t)
		a.account(email)
		for i := 0; i < n; i++ {
			a.guess(email, ip)
		}
		switch a.canReach(t, email, ip) {
		case atkAdmitted:
			continue
		case atkAddressLocked:
			t.Fatalf("the per-ADDRESS lockout cut %s off after %d attempts, before the per-account one "+
				"engaged; the per-account limit for one source is unmeasured", ip, n)
		case atkMasked:
			return n
		}
	}
	t.Fatalf("one address submitted %d wrong passwords against one account and still got in with the "+
		"correct one: there is no per-source brute-force limit", ceiling)
	return 0
}

// atkDurableLimit is the same measurement as atkPerSourceLimit taken while the
// cache cannot be read, so the count comes from the durable failed_login_count
// column instead of the cache counter.
func atkDurableLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const (
		email = "atk-durable-probe@example.com"
		ip    = "198.51.100.111"
	)
	for n := 1; n <= ceiling; n++ {
		a := newAtkLockoutWithCache(t, atkUnreadableCache{cache.NewMemoryCache()})
		a.account(email)
		for i := 0; i < n; i++ {
			a.guess(email, ip)
		}
		switch a.canReach(t, email, ip) {
		case atkAdmitted:
			continue
		case atkAddressLocked:
			t.Fatalf("the per-address lockout answered at %d attempts with the cache unreadable; it "+
				"has nowhere to keep a counter and should be inert", n)
		case atkMasked:
			return n
		}
	}
	t.Fatalf("%d wrong passwords with the lockout cache unreadable never locked the account: the "+
		"durable fallback does not enforce a limit", ceiling)
	return 0
}

// atkSprayLimit is how many failed logins one address may submit across
// DIFFERENT accounts before the address itself is refused. No account ever
// approaches its own limit, so only the per-address counter can trip.
func atkSprayLimit(t *testing.T, ceiling int) int {
	t.Helper()
	const ip = "198.51.100.202"
	a := newAtkLockout(t)

	for n := 1; n <= ceiling; n++ {
		email := fmt.Sprintf("spray-victim-%d@example.com", n)
		a.account(email)
		a.guess(email, ip)

		bystander := fmt.Sprintf("spray-bystander-%d@example.com", n)
		a.account(bystander)
		switch a.canReach(t, bystander, ip) {
		case atkAdmitted:
			continue
		case atkAddressLocked:
			return n
		case atkMasked:
			t.Fatalf("a never-attacked account was refused from %s after %d attempts against OTHER "+
				"accounts: per-address state is leaking into per-account state", ip, n)
		}
	}
	t.Fatalf("one address failed %d logins across %d different accounts and was never refused: "+
		"password spraying from a single address is unbounded", ceiling, ceiling)
	return 0
}

// atkUnreadableCache fails reads the way a refused connection fails: with a real
// error, not with ErrNotFound. A missing key is a successful read of zero — it
// is what an account with no recent failures looks like — so only a genuine
// fault may reach the durable counter.
type atkUnreadableCache struct{ cache.Cache }

func (atkUnreadableCache) Get(context.Context, string) (string, error) {
	return "", errors.New("cache: connection refused")
}
