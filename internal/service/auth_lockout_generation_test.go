package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/tests/mocks"
)

// The per-source lockout counters are one cache key per address and the cache
// interface has no scan, so nothing can find them all to delete them. A
// completed password reset still has to clear all of them at once, because the
// address that opens the reset link is usually not the address that got locked
// out. The generation is how: advance it, and every old key stops being
// addressed.

func newGenerationLockoutSvc(t *testing.T) (*AuthService, cache.Cache) {
	t.Helper()
	mem := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mem.Close() })
	return &AuthService{cache: mem, users: &mocks.MockUserRepo{}}, mem
}

// TestClearAccountLockoutRetiresEverySource is the reported journey: locked on
// several addresses, reset from none of them, back in on all of them.
func TestClearAccountLockoutRetiresEverySource(t *testing.T) {
	svc, mem := newGenerationLockoutSvc(t)
	ctx := context.Background()
	const uid = "user-reset"
	sources := []string{"203.0.113.10", "203.0.113.11", "198.51.100.9"}

	for _, ip := range sources {
		for i := 0; i < lockoutThreshold; i++ {
			svc.recordFailedAttempt(ctx, uid, ip)
		}
		if !svc.isAccountLocked(ctx, uid, ip) {
			t.Fatalf("%d failures from %s did not lock that source", lockoutThreshold, ip)
		}
	}

	if err := ClearAccountLockout(ctx, mem, uid); err != nil {
		t.Fatalf("ClearAccountLockout: %v", err)
	}

	for _, ip := range sources {
		if svc.isAccountLocked(ctx, uid, ip) {
			t.Errorf("%s is still locked after the reset cleared the account. A reset that clears only "+
				"the requesting address leaves the common journey broken: the link is opened on a "+
				"phone and the lockout is on a laptop.", ip)
		}
	}

	// The account-wide counter goes too. It is the one key that can simply be
	// deleted, and leaving it behind would mean a reset does not clear a
	// distributed lock.
	if n, ok := svc.cachedCount(ctx, accountLockoutKey(uid)); !ok || n != 0 {
		t.Errorf("the account-wide counter reads %d (readable=%v) after a reset, want 0", n, ok)
	}
}

// TestLockoutStillBindsAfterAReset is the half that matters more. A reset must
// clear the lockout, not disable it: if the generation bump left the account
// permanently unlockable, "reset the password" would be a way to switch the
// brute-force control off for any account whose mailbox an attacker reached.
func TestLockoutStillBindsAfterAReset(t *testing.T) {
	svc, mem := newGenerationLockoutSvc(t)
	ctx := context.Background()
	const (
		uid = "user-reset-then-attacked"
		ip  = "198.51.100.44"
	)

	for i := 0; i < lockoutThreshold; i++ {
		svc.recordFailedAttempt(ctx, uid, ip)
	}
	if err := ClearAccountLockout(ctx, mem, uid); err != nil {
		t.Fatalf("ClearAccountLockout: %v", err)
	}
	if svc.isAccountLocked(ctx, uid, ip) {
		t.Fatal("still locked immediately after the reset")
	}

	for i := 0; i < lockoutThreshold; i++ {
		svc.recordFailedAttempt(ctx, uid, ip)
	}
	if !svc.isAccountLocked(ctx, uid, ip) {
		t.Errorf("%d fresh failures after a reset did not lock the source. The reset retired the old "+
			"counters and the new ones are not being written or not being read, so a password reset "+
			"turns the lockout off for that account rather than clearing it.", lockoutThreshold)
	}

	// And a second reset works the same way, so the mechanism is not one-shot.
	if err := ClearAccountLockout(ctx, mem, uid); err != nil {
		t.Fatalf("second ClearAccountLockout: %v", err)
	}
	if svc.isAccountLocked(ctx, uid, ip) {
		t.Error("a second reset did not clear the lockout; the generation only advances once")
	}
}

// TestSourceLockoutKeyAtGenerationZeroIsUnchanged pins the property that keeps
// this change contained.
//
// Every account is at generation zero until its first password reset, so if
// generation zero renders the key exactly as it was rendered before generations
// existed, deploying this changes no key for anyone. Rendering it differently
// would zero every live per-source counter in the fleet at rollout and hand
// every in-flight attacker a fresh lockoutThreshold guesses — the same objection
// that rules out renaming accountLockoutKey.
func TestSourceLockoutKeyAtGenerationZeroIsUnchanged(t *testing.T) {
	const (
		uid = "user-1"
		ip  = "203.0.113.7"
	)
	if got, want := sourceLockoutKey(uid, ip, 0), fmt.Sprintf("lockout:%s|%s", uid, ip); got != want {
		t.Errorf("generation zero renders %q, want %q. Changing the key shape for accounts that have "+
			"never reset resets every live per-source counter at rollout.", got, want)
	}
	// And a non-zero generation must not collide with it, or advancing the
	// generation would not retire anything.
	if sourceLockoutKey(uid, ip, 1) == sourceLockoutKey(uid, ip, 0) {
		t.Error("generation 1 renders the same key as generation 0, so a reset retires nothing")
	}
	if sourceLockoutKey(uid, ip, 1) == sourceLockoutKey(uid, ip, 2) {
		t.Error("generations 1 and 2 collide, so a second reset retires nothing")
	}
}

// TestClearAccountLockoutReportsARefusedAdvance keeps the failure visible.
//
// The generation advance is the whole mechanism. Swallowing its error would
// restore the original bug silently: the caller logs nothing, the user is told
// the reset completed, and they are still locked out on their own machine.
func TestClearAccountLockoutReportsARefusedAdvance(t *testing.T) {
	ctx := context.Background()

	t.Run("a refused advance is an error", func(t *testing.T) {
		c := &mocks.MockCache{
			DeleteFn: func(context.Context, string) error { return nil },
			IncrementFn: func(context.Context, string, time.Duration) (int64, error) {
				return 0, errors.New("cache: entry cap reached")
			},
		}
		if err := ClearAccountLockout(ctx, c, "user-1"); err == nil {
			t.Error("the generation could not be advanced and ClearAccountLockout reported success. " +
				"The per-source counters keep their keys, so the user stays locked out with nothing " +
				"logged and a 200 in their browser.")
		}
	})

	t.Run("a refused delete is an error", func(t *testing.T) {
		c := &mocks.MockCache{
			DeleteFn: func(context.Context, string) error { return errors.New("cache: connection refused") },
			IncrementFn: func(context.Context, string, time.Duration) (int64, error) {
				return 1, nil
			},
		}
		if err := ClearAccountLockout(ctx, c, "user-1"); err == nil {
			t.Error("the account-wide counter could not be deleted and ClearAccountLockout reported success")
		}
	})

	t.Run("no cache is not an error", func(t *testing.T) {
		if err := ClearAccountLockout(ctx, nil, "user-1"); err != nil {
			t.Errorf("a deployment with no cache has no lockout counters to clear, got %v", err)
		}
	})
}
