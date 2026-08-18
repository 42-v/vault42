package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
)

// The memory cache refuses a NEW key once it holds memoryMaxEntries, and every
// key in it is attacker-chosen in practice: the rate limiter writes
// rl:<ns>:ip:<addr> on every request including the ones it rejects, and an IPv6
// source has a /64 to spend. So the cap is reachable, and it is reachable
// exactly when the cache is also the only backend — the embedded profile, or a
// production pod during a Redis outage.
//
// At the cap, Increment on a key that does not yet exist returns ErrCacheFull
// and creates nothing. The read that follows is then a clean ErrNotFound, which
// cachedCount reports as answered-zero. Nothing distinguishes "this account has
// never failed" from "the counter could not be written", so the account never
// locks however many times the password is wrong. The counter that the durable
// failed_login_count fallback exists to cover was never missing on a read; it
// was missing because a write was refused.

// fillCacheToCap writes distinct keys into a real production cache until it
// refuses one, and returns how many it took. The keys are shaped like the
// limiter's, because that is what fills it in production.
func fillCacheToCap(t *testing.T, mc *cache.MemoryCache) int {
	t.Helper()
	ctx := context.Background()
	for i := 0; ; i++ {
		if err := mc.Set(ctx, fmt.Sprintf("rl:login:ip:2001:db8::%x", i), "1", time.Hour); err != nil {
			return i
		}
		if i > 1_000_000 {
			t.Fatal("the memory cache accepted a million keys: the entry cap is gone")
		}
	}
}

// lockoutCapSvc wires an auth service onto a real memory cache with a durable
// failure count already past the threshold, which is the state 20 rejected
// logins leave behind: recordLoginFailure calls IncrementFailedLogin on every
// one of them, so the column is maintained whatever the cache does.
func lockoutCapSvc(t *testing.T, mc *cache.MemoryCache, storedFailures int) *AuthService {
	t.Helper()
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Roles: []string{"user"}, FailedLoginCount: storedFailures}, nil
		}
		o.cache.GetFn = mc.Get
		o.cache.SetFn = mc.Set
		o.cache.DeleteFn = mc.Delete
		o.cache.GetAndDeleteFn = mc.GetAndDelete
		o.cache.SetIfNotExistsFn = mc.SetIfNotExists
		o.cache.IncrementFn = mc.Increment
		o.cache.ExistsFn = mc.Exists
	})
	return svc
}

// TestLockoutHoldsWhenTheCacheIsAtItsEntryCap is the regression. A saturated
// cache must not be a lockout bypass.
func TestLockoutHoldsWhenTheCacheIsAtItsEntryCap(t *testing.T) {
	const (
		userID = "user-capped"
		ip     = "203.0.113.7"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })
	filled := fillCacheToCap(t, mc)
	if filled == 0 {
		t.Fatal("the cache refused its first key; the fixture proves nothing")
	}

	svc := lockoutCapSvc(t, mc, lockoutThreshold*2)
	for i := 0; i < 4*lockoutThreshold; i++ {
		svc.recordFailedAttempt(ctx, userID, ip)
	}

	if !svc.isAccountLocked(ctx, userID, ip) {
		t.Fatalf("with the cache at its %d-entry cap and failed_login_count=%d, the account is not "+
			"locked after %d failures: the refused counter reads as zero failures, so a full cache "+
			"switches account lockout off",
			filled, lockoutThreshold*2, 4*lockoutThreshold)
	}
}

// The control. The same failures against a cache with room lock through the
// cache counter alone, with the durable count below the threshold — so the test
// above is measuring the cap and not a fallback that fires unconditionally.
func TestLockoutHoldsThroughTheCacheCounterWhenItHasRoom(t *testing.T) {
	const (
		userID = "user-roomy"
		ip     = "203.0.113.8"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	svc := lockoutCapSvc(t, mc, 0)
	for i := 0; i < lockoutThreshold; i++ {
		svc.recordFailedAttempt(ctx, userID, ip)
	}

	if !svc.isAccountLocked(ctx, userID, ip) {
		t.Fatal("an uncapped cache did not lock after the threshold was reached")
	}
}

// The other direction, and the reason the fallback is gated on a refusal rather
// than applied to every zero: an account with no failures must still log in
// while the cache is saturated. Falling back on every zero would put a GetByID
// in front of nearly every login, which is what cachedCount's contract exists to
// avoid, and this asserts the outcome that matters — the healthy account is not
// locked.
func TestACleanAccountIsNotLockedByASaturatedCache(t *testing.T) {
	const (
		userID = "user-clean"
		ip     = "203.0.113.9"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })
	fillCacheToCap(t, mc)

	svc := lockoutCapSvc(t, mc, 0)
	svc.recordFailedAttempt(ctx, userID, ip)

	if svc.isAccountLocked(ctx, userID, ip) {
		t.Fatal("a saturated cache locked an account whose durable failure count is zero")
	}
}

// The mirror image, and the case that shows the per-source arm carries its own
// weight rather than riding on the account-wide one: the account has failed
// before, so its account-wide key is in the map and the cap still admits its
// updates, while a new source address gets a key that is refused. The
// account-wide count is then honest and nowhere near the distributed threshold,
// and the per-source count — the one the hard lock is actually enforced from —
// is the zero that means nothing.
func TestThePerSourceCounterAlsoFallsBackWhenItCouldNotBeWritten(t *testing.T) {
	const (
		userID   = "user-newsource"
		freshIP  = "203.0.113.14"
		failures = 3
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	// Present before the flood, so the cap admits its updates. This is what an
	// account with earlier failures from another address looks like.
	if err := mc.Set(ctx, accountLockoutKey(userID), "0", lockoutDuration); err != nil {
		t.Fatalf("seed the account-wide counter: %v", err)
	}
	fillCacheToCap(t, mc)

	svc := lockoutCapSvc(t, mc, lockoutThreshold*2)
	for i := 0; i < failures; i++ {
		svc.recordFailedAttempt(ctx, userID, freshIP)
	}

	if n, ok := svc.cachedCount(ctx, accountLockoutKey(userID)); !ok || n == 0 || n >= distributedLockoutThreshold {
		t.Fatalf("account-wide counter = %d (answered=%v); the fixture must leave it non-zero and "+
			"below the distributed threshold or the per-source arm is never reached", n, ok)
	}
	if !svc.isAccountLocked(ctx, userID, freshIP) {
		t.Fatal("the per-source counter was refused and read back as zero, and the account did not " +
			"lock: the hard lock is comparing against a count that was never written")
	}
}

// The account-wide counter needs its own arm, and this is the case that reaches
// it: an attacker hammering one address has a per-source counter already in the
// map, which the cap still lets them update, while the account-wide key for the
// same user is new and refused. The per-source count is then honest and below
// its threshold, and the account-wide one is the zero that means nothing.
func TestTheAccountWideCounterAlsoFallsBackWhenItCouldNotBeWritten(t *testing.T) {
	const (
		userID = "user-partial"
		ip     = "203.0.113.11"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	// Present before the flood, so the cap admits its updates.
	if err := mc.Set(ctx, sourceLockoutKey(userID, ip), "0", lockoutDuration); err != nil {
		t.Fatalf("seed the per-source counter: %v", err)
	}
	fillCacheToCap(t, mc)

	svc := lockoutCapSvc(t, mc, lockoutThreshold*2)
	for i := 0; i < lockoutThreshold-2; i++ {
		svc.recordFailedAttempt(ctx, userID, ip)
	}

	if n, ok := svc.cachedCount(ctx, sourceLockoutKey(userID, ip)); !ok || n >= lockoutThreshold {
		t.Fatalf("per-source counter = %d (answered=%v); the fixture must leave it below the "+
			"threshold or the account-wide arm is never reached", n, ok)
	}
	if !svc.isAccountLocked(ctx, userID, ip) {
		t.Fatal("the account-wide counter was refused and read back as zero, and the account did " +
			"not lock: the distributed threshold is comparing against a count that was never written")
	}
}

// The fallback must cost nothing while the cache is healthy. cachedCount's
// contract is that an absent key is a successful read of zero precisely so the
// login path does not carry a database read, and falling back on every zero
// would undo that for nearly every login.
func TestAHealthyLockoutCheckNeverReadsTheDurableCount(t *testing.T) {
	const (
		userID = "user-healthy"
		ip     = "203.0.113.12"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	var durableReads int
	svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
		o.cache.GetFn = mc.Get
		o.cache.SetFn = mc.Set
		o.cache.DeleteFn = mc.Delete
		o.cache.GetAndDeleteFn = mc.GetAndDelete
		o.cache.SetIfNotExistsFn = mc.SetIfNotExists
		o.cache.IncrementFn = mc.Increment
		o.cache.ExistsFn = mc.Exists
	})
	o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		durableReads++
		return &model.User{ID: id, Roles: []string{"user"}}, nil
	}

	svc.recordFailedAttempt(ctx, userID, ip)
	if svc.isAccountLocked(ctx, userID, ip) {
		t.Fatal("one failure locked the account")
	}
	if durableReads != 0 {
		t.Fatalf("a lockout check against a healthy cache read the users table %d times; the "+
			"fallback must be gated on a refusal, not applied to every zero", durableReads)
	}
}

// The latch heals. A cache that was full at some point must not put a database
// read in front of every login for the rest of the process's life, so the
// fallback expires with the counters it stands in for.
func TestTheRefusalLatchExpiresWithTheLockoutWindow(t *testing.T) {
	const (
		userID = "user-healed"
		ip     = "203.0.113.13"
	)
	ctx := context.Background()

	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })

	svc := lockoutCapSvc(t, mc, lockoutThreshold*2)
	svc.noteLockoutCounterRefused()
	if !svc.isAccountLocked(ctx, userID, ip) {
		t.Fatal("a fresh refusal did not engage the durable fallback")
	}

	svc.lockoutCounterRefusedAt.Store(time.Now().Add(-2 * lockoutDuration).UnixNano())
	if svc.isAccountLocked(ctx, userID, ip) {
		t.Fatalf("a refusal older than the %s lockout window still forces the durable fallback; "+
			"the counter it stood in for expired long ago", lockoutDuration)
	}
}
