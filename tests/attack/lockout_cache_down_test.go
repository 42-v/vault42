package attack

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// stubUserRepo implements repository.UserRepository for lockout degradation tests.
// It tracks failed login counts in memory to simulate DB-level lockout fallback.
type stubUserRepo struct {
	users map[string]*model.User
}

func newStubUserRepo() *stubUserRepo {
	return &stubUserRepo{users: make(map[string]*model.User)}
}

func (r *stubUserRepo) Create(_ context.Context, user *model.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *stubUserRepo) GetByID(_ context.Context, id string) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (r *stubUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (r *stubUserRepo) Update(_ context.Context, user *model.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *stubUserRepo) UpdatePassword(_ context.Context, id, hash string) error {
	if u, ok := r.users[id]; ok {
		u.PasswordHash = hash
	}
	return nil
}

func (r *stubUserRepo) IncrementFailedLogin(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.FailedLoginCount++
	}
	return nil
}

func (r *stubUserRepo) ResetFailedLogin(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.FailedLoginCount = 0
	}
	return nil
}

func (r *stubUserRepo) LockUntil(_ context.Context, id string, until time.Time) error {
	if u, ok := r.users[id]; ok {
		u.LockedUntil = &until
	}
	return nil
}

func (r *stubUserRepo) Unlock(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.LockedUntil = nil
		u.FailedLoginCount = 0
	}
	return nil
}

func (r *stubUserRepo) VerifyEmail(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.EmailVerified = true
	}
	return nil
}

func (r *stubUserRepo) SetLastLogin(_ context.Context, _ string) error        { return nil }
func (r *stubUserRepo) CreateImported(_ context.Context, _ *model.User) error { return nil }
func (r *stubUserRepo) ClearImportPending(_ context.Context, _ string) error  { return nil }
func (r *stubUserRepo) SoftDeleteScrub(_ context.Context, _, _ string) error  { return nil }

// Verify interface compliance at compile time.
var _ repository.UserRepository = (*stubUserRepo)(nil)

// togglableCache is a cache that can be taken down and brought back up, so an
// attack can be run across the outage rather than either side of it.
//
// Down means every operation fails, which is what a refused connection does —
// not just reads. A test that only broke reads would leave the counters being
// written throughout the outage, and would therefore prove nothing about what
// survives one.
type togglableCache struct {
	cache.Cache
	down bool
}

var errCacheDown = errors.New("cache: connection refused")

func (c *togglableCache) Get(ctx context.Context, key string) (string, error) {
	if c.down {
		return "", errCacheDown
	}
	return c.Cache.Get(ctx, key)
}

func (c *togglableCache) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if c.down {
		return 0, errCacheDown
	}
	return c.Cache.Increment(ctx, key, ttl)
}

func (c *togglableCache) SetIfNotExists(ctx context.Context, key, val string, ttl time.Duration) (bool, error) {
	if c.down {
		return false, errCacheDown
	}
	return c.Cache.SetIfNotExists(ctx, key, val, ttl)
}

// TestLockoutCacheDown_DBFallbackEnforcesLockout runs a brute-force attack with
// the lockout cache unreadable, which is when an attacker would most like the
// limit to be gone.
//
// The old body did not attack anything. It created a stub repository, called
// IncrementFailedLogin on it five times, and asserted the field it had just
// incremented held five — arithmetic on the test's own struct, with the comment
// "the DB fallback in isAccountLocked WOULD return true" standing in for
// actually asking isAccountLocked. Deleting the fallback from production left
// this test green.
func TestLockoutCacheDown_DBFallbackEnforcesLockout(t *testing.T) {
	limit := atkPerSourceLimit(t, atkSearchCeiling)

	const (
		email      = "cache-down@example.com"
		attackerIP = "198.51.100.70"
	)
	a := newAtkLockoutWithCache(t, atkUnreadableCache{cache.NewMemoryCache()})
	a.account(email)

	// The fallback must not be a blanket refusal: an untouched account still
	// logs in while the cache is down, or a cache outage is an auth outage.
	if a.canReach(t, email, attackerIP) != atkAdmitted {
		t.Fatal("an account with no failures could not log in while the cache was unreadable; " +
			"the fallback is refusing everyone rather than enforcing a limit")
	}

	for i := 0; i < limit; i++ {
		a.guess(email, attackerIP)
	}
	if a.canReach(t, email, attackerIP) == atkAdmitted {
		t.Errorf("%d wrong passwords with the lockout cache unreadable left the account open. The "+
			"counter lives in the cache, so without the durable failed_login_count fallback an "+
			"attacker gets unlimited guesses by waiting for — or causing — a cache outage.", limit)
	}
}

// TestLockoutCacheDown_IPLockoutDisabledWithoutCache records a real degradation
// rather than asserting it away.
//
// With no cache and no rate-limit repository there is nowhere to keep a per-
// address counter, so spraying from one address is not stopped by the address
// lock. What must still hold is the per-account limit, which falls back to the
// durable column. The old body asserted neither: it incremented its own stub's
// integer field and checked the integer.
func TestLockoutCacheDown_IPLockoutDisabledWithoutCache(t *testing.T) {
	limit := atkPerSourceLimit(t, atkSearchCeiling)

	const sprayerIP = "198.51.100.80"
	a := newAtkLockoutWithCache(t, nil)

	// The degradation: one address fails a login against many accounts and is
	// never cut off, because the counter that would cut it off has nowhere to
	// live. Documented in the register rather than hidden.
	for n := 1; n <= 40; n++ {
		email := fmt.Sprintf("nocache-spray-%d@example.com", n)
		a.account(email)
		a.guess(email, sprayerIP)
	}
	const bystander = "nocache-bystander@example.com"
	a.account(bystander)
	if got := a.canReach(t, bystander, sprayerIP); got != atkAdmitted {
		t.Errorf("with no cache the per-address lockout answered %v; this degradation is documented as "+
			"absent, so an answer here means the code and the register disagree", got)
	}

	// The control that must survive: the per-account limit, enforced from the
	// durable count.
	const target = "nocache-target@example.com"
	a.account(target)
	for i := 0; i < limit; i++ {
		a.guess(target, sprayerIP)
	}
	if a.canReach(t, target, sprayerIP) == atkAdmitted {
		t.Errorf("%d failures with no cache at all left the account open; the durable per-account "+
			"limit is the only brute-force control left in this configuration", limit)
	}
}

// TestLockoutCacheDown_CacheRecovery pins what happens when the cache comes
// back, which is the part of an outage nobody writes down.
//
// The old body incremented a MemoryCache key five times, read back "5", deleted
// it, and read back "". That is a test of MemoryCache. It says nothing about
// recovery, because no lockout decision was ever taken.
//
// The real behaviour is worth pinning in both directions. During the outage the
// durable count holds the lock. After recovery the cache counters are empty —
// every increment during the outage failed — and the durable count is only ever
// consulted when the cache cannot answer, so the account is open again. That is
// deliberate: the cache counter carries the fifteen-minute TTL, and a durable
// column that is never consulted while the cache is healthy cannot pin an
// account shut forever after one bad afternoon. It also means an attacker gains
// nothing from an outage they can end, and loses the failures they spent during
// one.
func TestLockoutCacheDown_CacheRecovery(t *testing.T) {
	limit := atkPerSourceLimit(t, atkSearchCeiling)

	const (
		email      = "recovery@example.com"
		attackerIP = "198.51.100.90"
	)
	c := &togglableCache{Cache: cache.NewMemoryCache(), down: true}
	a := newAtkLockoutWithCache(t, c)
	a.account(email)

	for i := 0; i < limit; i++ {
		a.guess(email, attackerIP)
	}
	if a.canReach(t, email, attackerIP) == atkAdmitted {
		t.Fatalf("%d failures during the outage did not lock the account; the rest of this test "+
			"has nothing to observe", limit)
	}

	c.down = false

	// A successful login here also resets the durable count, so assert before
	// doing anything else that would.
	if a.canReach(t, email, attackerIP) != atkAdmitted {
		t.Errorf("the account was still locked after the cache recovered. Nothing expires the durable " +
			"count, so a lock that outlives the outage outlives it permanently, and every account " +
			"that failed a login during an incident stays shut until an operator intervenes.")
	}

	// And the control is back on its normal footing: the recovered cache
	// enforces the same limit it did before.
	for i := 0; i < limit; i++ {
		a.guess(email, attackerIP)
	}
	if a.canReach(t, email, attackerIP) == atkAdmitted {
		t.Errorf("after recovery, %d failures no longer locked the account; the outage left the "+
			"lockout permanently disabled", limit)
	}
}
