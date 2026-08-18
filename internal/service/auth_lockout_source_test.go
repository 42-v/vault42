package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
)

// The account lockout used to be a weapon pointed at the account. Five wrong
// passwords from one address, and any account whose email the caller knew was
// denied logins for fifteen minutes — no credential, five HTTP requests, and
// the attacker was not even told they had succeeded, because a locked account
// answers exactly like a wrong password.
//
// These tests hold both halves of the fix at once: an attacker still cannot
// brute-force from their own address, and a victim on a different address is
// untouched.

// lockoutSvc builds an auth service whose Login accepts
// "correct-horse-battery-staple" for one known address, backed by a real
// in-memory cache so the counters accumulate and expire like production.
func lockoutSvc(t *testing.T, email, userID string) *AuthService {
	t.Helper()
	hash := validPasswordHash(t)
	mem := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mem.Close() })

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, e string) (*model.User, error) {
			if e != email {
				return nil, nil
			}
			return &model.User{
				ID: userID, Email: email,
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.cache.GetFn = mem.Get
		o.cache.SetFn = mem.Set
		o.cache.DeleteFn = mem.Delete
		o.cache.GetAndDeleteFn = mem.GetAndDelete
		o.cache.SetIfNotExistsFn = mem.SetIfNotExists
		o.cache.IncrementFn = mem.Increment
		o.cache.ExistsFn = mem.Exists
	})
	return svc
}

// shrinkLoginThrottle scales the progressive delay down for the duration of a
// test that drives many failures through the real Login path.
func shrinkLoginThrottle(t *testing.T) {
	t.Helper()
	prevBase, prevMax := loginThrottleBase, loginThrottleMax
	loginThrottleBase, loginThrottleMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { loginThrottleBase, loginThrottleMax = prevBase, prevMax })
}

func loginFrom(t *testing.T, svc *AuthService, email, password, ip string) error {
	t.Helper()
	ctx := httputil.WithClientIP(context.Background(), ip)
	_, err := svc.Login(ctx, LoginInput{Email: email, Password: password}, ip, "TestAgent")
	return err
}

// TestLockoutFromOneSourceDoesNotDenyTheVictim is the regression for the
// lockout-as-weapon finding: the attacker burns the threshold from their own
// address, and the account owner still gets in from theirs.
func TestLockoutFromOneSourceDoesNotDenyTheVictim(t *testing.T) {
	const (
		email      = "victim@example.com"
		attackerIP = "198.51.100.66"
		victimIP   = "203.0.113.10"
	)
	svc := lockoutSvc(t, email, "user-victim")

	for i := 0; i < lockoutThreshold+2; i++ {
		if err := loginFrom(t, svc, email, "wrong-password", attackerIP); err == nil {
			t.Fatalf("attempt %d with a wrong password succeeded", i+1)
		}
	}

	// The attacker's own path is shut.
	if err := loginFrom(t, svc, email, "correct-horse-battery-staple", attackerIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the attacking source is not locked out: correct password from %s returned %v", attackerIP, err)
	}

	// The victim's is not.
	if err := loginFrom(t, svc, email, "correct-horse-battery-staple", victimIP); err != nil {
		t.Fatalf("the victim was locked out of their own account from %s by %d failures at %s: %v",
			victimIP, lockoutThreshold+2, attackerIP, err)
	}
}

// TestLockoutStillStopsBruteForceFromOneSource is the other half: the control
// this change must not weaken. One address gets exactly lockoutThreshold
// guesses, as before.
func TestLockoutStillStopsBruteForceFromOneSource(t *testing.T) {
	const (
		email      = "target@example.com"
		attackerIP = "198.51.100.77"
	)
	svc := lockoutSvc(t, email, "user-target")

	for i := 0; i < lockoutThreshold-1; i++ {
		_ = loginFrom(t, svc, email, "wrong-password", attackerIP)
	}
	// One short of the threshold the account is still open to this source.
	if err := loginFrom(t, svc, email, "correct-horse-battery-staple", attackerIP); err != nil {
		t.Fatalf("locked one attempt early (%d failures): %v", lockoutThreshold-1, err)
	}

	// A successful login clears this source, so burn the full threshold again.
	for i := 0; i < lockoutThreshold; i++ {
		_ = loginFrom(t, svc, email, "wrong-password", attackerIP)
	}
	if err := loginFrom(t, svc, email, "correct-horse-battery-staple", attackerIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("%d failures from one source did not lock it out; brute-force protection was traded away, got %v",
			lockoutThreshold, err)
	}
}

// TestDistributedBruteForceStillLocksTheAccount holds the containment the
// per-source key alone would not give: an attacker who rotates addresses to
// stay under the per-source threshold still runs into the account-wide one.
func TestDistributedBruteForceStillLocksTheAccount(t *testing.T) {
	const email = "spray@example.com"
	// The throttle is doing its job here — fifty real failures against one
	// account is a minute and a half of deliberate delay. Shrink it so the test
	// measures the lock, not the sleep.
	shrinkLoginThrottle(t)
	svc := lockoutSvc(t, email, "user-spray")

	// distributedLockoutThreshold failures spread over enough sources that no
	// single one reaches lockoutThreshold.
	perSource := lockoutThreshold - 1
	sources := (distributedLockoutThreshold + perSource - 1) / perSource
	for s := 0; s < sources; s++ {
		ip := fmt.Sprintf("203.0.113.%d", s+1)
		for i := 0; i < perSource; i++ {
			_ = loginFrom(t, svc, email, "wrong-password", ip)
		}
	}

	// A source that has never failed against this account is now refused too:
	// the account itself is locked, which is the correct answer to a genuine
	// distributed attack.
	if err := loginFrom(t, svc, email, "correct-horse-battery-staple", "192.0.2.200"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("%d failures across %d sources did not lock the account, got %v",
			sources*perSource, sources, err)
	}
}

// TestLoginThrottleIsProgressiveAndCapped pins the delay schedule. Zero up to
// the threshold, then doubling, then flat — a delay that grew without a ceiling
// would be the hard lock again, wearing a different hat and holding a goroutine.
func TestLoginThrottleIsProgressiveAndCapped(t *testing.T) {
	if d := loginThrottleDelay(lockoutThreshold); d != 0 {
		t.Errorf("delay at the threshold = %v, want 0", d)
	}
	if d := loginThrottleDelay(lockoutThreshold + 1); d != loginThrottleBase {
		t.Errorf("first delay = %v, want %v", d, loginThrottleBase)
	}
	if d := loginThrottleDelay(lockoutThreshold + 2); d != 2*loginThrottleBase {
		t.Errorf("second delay = %v, want %v", d, 2*loginThrottleBase)
	}
	prev := time.Duration(0)
	for n := lockoutThreshold; n < lockoutThreshold+40; n++ {
		d := loginThrottleDelay(n)
		if d < prev {
			t.Fatalf("delay went backwards at %d failures: %v after %v", n, d, prev)
		}
		if d > loginThrottleMax {
			t.Fatalf("delay at %d failures = %v, over the %v cap", n, d, loginThrottleMax)
		}
		prev = d
	}
	if prev != loginThrottleMax {
		t.Errorf("delay never reached the cap: %v, want %v", prev, loginThrottleMax)
	}
}

// TestLoginThrottleAppliesToUnknownAddressesToo is the anti-enumeration half of
// the throttle. A delay only registered addresses paid would answer "does this
// account exist?" in wall-clock time, which is the question every other branch
// of Login is written to refuse.
func TestLoginThrottleAppliesToUnknownAddressesToo(t *testing.T) {
	svc := lockoutSvc(t, "known@example.com", "user-known")
	ctx := context.Background()

	const unknown = "nobody@example.com"
	for i := 0; i < lockoutThreshold+1; i++ {
		_ = loginFrom(t, svc, unknown, "wrong-password", "198.51.100.9")
	}

	n, ok := svc.cachedCount(ctx, svc.identityThrottleKey(unknown))
	if !ok {
		t.Fatal("throttle counter unreadable")
	}
	if n < lockoutThreshold+1 {
		t.Fatalf("an address with no account accrued %d failures, want at least %d — "+
			"an unknown address that does not accrue the throttle is an enumeration oracle",
			n, lockoutThreshold+1)
	}
	if d := loginThrottleDelay(n); d <= 0 {
		t.Fatalf("no delay owed after %d failures against an unknown address", n)
	}
}

// TestThrottleStopsAtTheContextDeadline keeps the throttle from becoming its own
// resource问题: a client that hangs up must free the goroutine immediately.
func TestThrottleStopsAtTheContextDeadline(t *testing.T) {
	svc := lockoutSvc(t, "known@example.com", "user-known")
	ctx := context.Background()
	key := svc.identityThrottleKey("known@example.com")
	for i := 0; i < lockoutThreshold+10; i++ {
		svc.cache.Increment(ctx, key, lockoutDuration) // #nosec G104 -- test setup
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	start := time.Now()
	svc.throttleLogin(canceled, "known@example.com")
	if elapsed := time.Since(start); elapsed > loginThrottleBase {
		t.Fatalf("throttle slept %v on a canceled context; it must return at once", elapsed)
	}
}

// TestLockoutFallsBackWhenTheAccountCounterCannotBeRead covers the second cache
// read: a per-source counter that answers and an account-wide counter that does
// not still has to reach the durable count rather than answer "not locked".
func TestLockoutFallsBackWhenTheAccountCounterCannotBeRead(t *testing.T) {
	svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, FailedLoginCount: lockoutThreshold}, nil
		}
	})
	o.cache.GetFn = func(_ context.Context, key string) (string, error) {
		if key == accountLockoutKey("user-1") {
			return "", errors.New("redis: connection refused")
		}
		return "", nil
	}

	if !svc.isAccountLocked(context.Background(), "user-1", "203.0.113.9") {
		t.Error("an unreadable account-wide counter answered not-locked without consulting " +
			"users.FailedLoginCount, so a cache outage unlocks every account again")
	}
}
