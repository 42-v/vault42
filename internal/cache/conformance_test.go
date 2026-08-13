package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The three backends are chosen by one config string and are otherwise
// interchangeable to every caller: the same key holds the account-lockout
// counter, the TOTP replay marker and the password-reset token whichever one is
// running. A behavior that differs between them is a difference in security
// posture that no caller can see, so the properties below are asserted against
// each backend from one table rather than backend by backend.
//
// The Postgres backend is absent from this table: its behavior lives in SQL and
// can only be judged by a real server, which this environment cannot start. See
// the audit notes for what was checked by reading instead.
func forEachBackend(t *testing.T, run func(t *testing.T, c Cache)) {
	t.Helper()

	t.Run("memory", func(t *testing.T) {
		c := NewMemoryCache()
		defer c.Close() //nolint:errcheck // teardown
		run(t, c)
	})

	t.Run("redis", func(t *testing.T) {
		f := newFakeRedis(t)
		c, err := NewRedisCache(f.addr(), "", 0)
		if err != nil {
			t.Fatalf("NewRedisCache: %v", err)
		}
		defer c.Close() //nolint:errcheck // teardown
		run(t, c)
	})
}

// A missing key must be reported as ErrNotFound and never as an empty value
// with a nil error. isAccountLocked in the auth service branches on exactly
// this: a nil error means "the cache answered, this account has no failures",
// while an error sends it to the durable failed_login_count. A backend that
// answered ("", nil) for a key it does not hold would report every account
// unlocked and never consult the fallback.
func TestEveryBackendReportsAMissingKeyAsNotFound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get on a missing key = %v, want ErrNotFound", err)
		}
		if _, err := c.GetAndDelete(ctx, "absent"); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetAndDelete on a missing key = %v, want ErrNotFound", err)
		}
		ok, err := c.Exists(ctx, "absent")
		if err != nil {
			t.Errorf("Exists on a missing key: %v", err)
		}
		if ok {
			t.Error("Exists reported a missing key as present")
		}
	})
}

// A key holding an empty value exists. The distinction matters because the
// confirm window stores a JTI and the middleware treats an empty read as "no
// confirmation": a backend that could not tell "stored empty" from "absent"
// would make the two indistinguishable to every caller that checks val == "".
func TestEveryBackendDistinguishesAnEmptyValueFromAMissingKey(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if err := c.Set(ctx, "empty", "", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		val, err := c.Get(ctx, "empty")
		if err != nil {
			t.Errorf("Get on a key stored empty = %v, want no error", err)
		}
		if val != "" {
			t.Errorf("Get returned %q, want the empty string that was stored", val)
		}
		ok, err := c.Exists(ctx, "empty")
		if err != nil {
			t.Errorf("Exists: %v", err)
		}
		if !ok {
			t.Error("Exists reported a key stored with an empty value as absent")
		}
	})
}

// GetAndDelete is the single-use guarantee behind email verification, password
// reset, the OAuth exchange code, the PKCE verifier and the email OTP. The
// second call must find nothing whether or not what followed the first call
// succeeded, otherwise a reset token survives its own use.
func TestEveryBackendConsumesAKeyOnGetAndDelete(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if err := c.Set(ctx, "reset:abc", "user-1", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		val, err := c.GetAndDelete(ctx, "reset:abc")
		if err != nil {
			t.Fatalf("first GetAndDelete: %v", err)
		}
		if val != "user-1" {
			t.Errorf("first GetAndDelete returned %q, want user-1", val)
		}
		if _, err := c.GetAndDelete(ctx, "reset:abc"); !errors.Is(err, ErrNotFound) {
			t.Errorf("second GetAndDelete = %v, want ErrNotFound; the token outlived its use", err)
		}
		if _, err := c.Get(ctx, "reset:abc"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after GetAndDelete = %v, want ErrNotFound", err)
		}
	})
}

// SetIfNotExists is the replay guard: exactly one caller may take a key, and the
// loser must be told so. The TOTP handler rejects a code when it comes back
// false and CompleteMFALogin rejects a challenge token the same way, so a
// backend where the second caller also won would let one TOTP code or one MFA
// challenge be redeemed twice.
func TestEveryBackendLetsOnlyTheFirstCallerTakeAKey(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		ok, err := c.SetIfNotExists(ctx, "totp_used:u1:5", "first", time.Minute)
		if err != nil {
			t.Fatalf("first SetIfNotExists: %v", err)
		}
		if !ok {
			t.Fatal("first SetIfNotExists returned false on a free key")
		}
		ok, err = c.SetIfNotExists(ctx, "totp_used:u1:5", "second", time.Minute)
		if err != nil {
			t.Fatalf("second SetIfNotExists: %v", err)
		}
		if ok {
			t.Error("second SetIfNotExists returned true; the replay guard let a used code through")
		}
		val, err := c.Get(ctx, "totp_used:u1:5")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if val != "first" {
			t.Errorf("stored value = %q, want the first writer's value; the loser overwrote the winner", val)
		}
	})
}

// Deleting the key releases the guard again, which is how a fresh window opens
// after clearLockout or a consumed challenge.
func TestEveryBackendFreesAKeyForSetIfNotExistsAfterDelete(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.SetIfNotExists(ctx, "guard", "v", time.Minute); err != nil {
			t.Fatalf("SetIfNotExists: %v", err)
		}
		if err := c.Delete(ctx, "guard"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		ok, err := c.SetIfNotExists(ctx, "guard", "v2", time.Minute)
		if err != nil {
			t.Fatalf("SetIfNotExists after Delete: %v", err)
		}
		if !ok {
			t.Error("SetIfNotExists refused a key that had been deleted")
		}
	})
}

// The lockout threshold is a comparison against the number Increment returns, so
// the counter must start at 1 and rise by exactly 1. An off-by-one here is a
// different number of password guesses per account.
func TestEveryBackendCountsFromOneOnIncrement(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		for want := int64(1); want <= 5; want++ {
			got, err := c.Increment(ctx, "lockout:u1", time.Minute)
			if err != nil {
				t.Fatalf("Increment: %v", err)
			}
			if got != want {
				t.Fatalf("Increment returned %d, want %d", got, want)
			}
		}
		val, err := c.Get(ctx, "lockout:u1")
		if err != nil {
			t.Fatalf("Get on the counter: %v", err)
		}
		if val != "5" {
			t.Errorf("counter reads %q, want 5; isAccountLocked parses this string", val)
		}
	})
}

// Lockout and rate limiting are fixed windows: the expiry set by the first
// increment stands, and further increments inside the window do not push it out.
// A backend that extended the window on every attempt would turn a 15-minute
// lockout into a permanent one for any account under a steady guessing load.
func TestEveryBackendKeepsTheIncrementWindowFixed(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.Increment(ctx, "rl:ip:198.51.100.7", 300*time.Millisecond); err != nil {
			t.Fatalf("first Increment: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Increment(ctx, "rl:ip:198.51.100.7", time.Hour); err != nil {
			t.Fatalf("second Increment: %v", err)
		}
		time.Sleep(350 * time.Millisecond)
		if _, err := c.Get(ctx, "rl:ip:198.51.100.7"); !errors.Is(err, ErrNotFound) {
			t.Errorf("counter still present after its original window = %v, want ErrNotFound", err)
		}
	})
}

// An expired entry is gone to every reader, and the guard it held is released.
// A lockout that expires in one backend and lingers in another is a different
// account-lockout duration depending on which backend the operator picked.
func TestEveryBackendTreatsAnExpiredEntryAsAbsent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if err := c.Set(ctx, "short", "v", 80*time.Millisecond); err != nil {
			t.Fatalf("Set: %v", err)
		}
		time.Sleep(150 * time.Millisecond)

		if _, err := c.Get(ctx, "short"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get on an expired key = %v, want ErrNotFound", err)
		}
		ok, err := c.Exists(ctx, "short")
		if err != nil {
			t.Errorf("Exists on an expired key: %v", err)
		}
		if ok {
			t.Error("Exists reported an expired key as present")
		}
		if _, err := c.GetAndDelete(ctx, "short"); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetAndDelete on an expired key = %v, want ErrNotFound", err)
		}
		took, err := c.SetIfNotExists(ctx, "short", "fresh", time.Minute)
		if err != nil {
			t.Fatalf("SetIfNotExists over an expired key: %v", err)
		}
		if !took {
			t.Error("SetIfNotExists was blocked by an expired entry; the replay guard never reopens")
		}
	})
}

// Increment must apply the TTL it was handed, not a rounded version of it. The
// Redis backend converted the duration with int64(ttl.Seconds()), which floors:
// a caller asking for a 1500ms window got 1000ms, so the window closed early and
// the counter it was protecting reset early. Anything under a second collapsed
// to the clamp. The two backends must agree on how long a counter lives, because
// that duration is the lockout.
func TestEveryBackendAppliesTheIncrementTTLItWasGiven(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.Increment(ctx, "frac", 1500*time.Millisecond); err != nil {
			t.Fatalf("Increment: %v", err)
		}
		// Well inside the requested window: the counter must still be there.
		time.Sleep(1100 * time.Millisecond)
		if _, err := c.Get(ctx, "frac"); err != nil {
			t.Fatalf("counter expired before the 1500ms window it was given: %v", err)
		}
		// Past it: the counter must be gone.
		time.Sleep(600 * time.Millisecond)
		if _, err := c.Get(ctx, "frac"); !errors.Is(err, ErrNotFound) {
			t.Errorf("counter outlived its window = %v, want ErrNotFound", err)
		}
	})
}

// The interface documents a zero TTL as "no expiration" for Set, SetIfNotExists
// and Increment alike. The Redis backend clamped a zero TTL on Increment up to
// one second, so the same call produced a permanent counter on two backends and
// a counter that vanished a second later on the third.
func TestEveryBackendTreatsAZeroIncrementTTLAsNoExpiry(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.Increment(ctx, "forever", 0); err != nil {
			t.Fatalf("Increment: %v", err)
		}
		time.Sleep(1200 * time.Millisecond)
		val, err := c.Get(ctx, "forever")
		if err != nil {
			t.Fatalf("a counter incremented with a zero TTL expired anyway: %v", err)
		}
		if val != "1" {
			t.Errorf("counter reads %q, want 1", val)
		}
	})
}

// Keys and values round-trip byte for byte, CRLF and NUL included. The RESP
// framing is length-prefixed, so a value carrying a bare \r\n must not be able
// to end the bulk string early and have the remainder read as the next reply:
// that would desynchronize the connection and hand one caller another caller's
// answer. The webauthn session blobs and the OAuth exchange payload are JSON
// documents pulled straight out of the cache and trusted.
func TestEveryBackendRoundTripsKeysAndValuesByteForByte(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"crlf in value", "blob", "line1\r\nline2"},
		{"resp framing in value", "frame", "x\r\n$5\r\nPWNED\r\n"},
		{"nul in value", "nul", "a\x00b"},
		{"crlf in key", "k\r\nsecond", "v"},
		{"space in key", "k with space", "v"},
		{"unicode", "ключ", "значение"},
		{"long value", "long", strings.Repeat("A", 70000)},
	}
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := c.Set(ctx, tc.key, tc.value, time.Minute); err != nil {
					t.Fatalf("Set: %v", err)
				}
				got, err := c.Get(ctx, tc.key)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if got != tc.value {
					t.Errorf("value changed in transit: got %d bytes, want %d", len(got), len(tc.value))
				}
			})
		}
	})
}

// Keys are compared as exact byte strings with no case folding and no trimming.
// Every namespace here is prefix plus identifier, so a backend that folded case
// would merge lockout:<uuid> for two users whose ids differ only in case, and
// one user's failures would lock the other out.
func TestEveryBackendKeepsKeysCaseSensitiveAndDistinct(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if err := c.Set(ctx, "lockout:AbC", "upper", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := c.Set(ctx, "lockout:abc", "lower", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		upper, err := c.Get(ctx, "lockout:AbC")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		lower, err := c.Get(ctx, "lockout:abc")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if upper != "upper" || lower != "lower" {
			t.Errorf("keys folded together: got %q and %q", upper, lower)
		}
	})
}

// The empty key is a key like any other and must not be silently merged with a
// missing one. No caller builds one today, but every key is a literal prefix
// concatenated with an identifier, so an empty identifier is one nil-guard away.
func TestEveryBackendHandlesTheEmptyKey(t *testing.T) {
	forEachBackend(t, func(t *testing.T, c Cache) {
		ctx := context.Background()
		if _, err := c.Get(ctx, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get on an unset empty key = %v, want ErrNotFound", err)
		}
		if err := c.Set(ctx, "", "v", time.Minute); err != nil {
			t.Fatalf("Set on the empty key: %v", err)
		}
		got, err := c.Get(ctx, "")
		if err != nil {
			t.Fatalf("Get on the empty key: %v", err)
		}
		if got != "v" {
			t.Errorf("empty key holds %q, want v", got)
		}
	})
}

// Increment must ask Redis for the caller's TTL in milliseconds, and the script
// must apply it with PEXPIRE. Asserting the wire arguments as well as the
// observable window keeps the fake server from being the thing under test: the
// fake could be taught any unit, but the client can only send one.
func TestTheRedisIncrementScriptCarriesTheFullTTLInMilliseconds(t *testing.T) {
	f := newFakeRedis(t)
	c, err := NewRedisCache(f.addr(), "", 0)
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	defer c.Close() //nolint:errcheck // teardown

	if _, err := c.Increment(context.Background(), "rl:ip:203.0.113.9", 1500*time.Millisecond); err != nil {
		t.Fatalf("Increment: %v", err)
	}

	evals := f.evals()
	if len(evals) != 1 {
		t.Fatalf("server saw %d EVAL commands, want 1", len(evals))
	}
	args := evals[0]
	if !strings.Contains(args[1], "PEXPIRE") {
		t.Errorf("script uses a second-granularity expiry (%q); a sub-second window is floored away", args[1])
	}
	if args[3] != "rl:ip:203.0.113.9" {
		t.Errorf("KEYS[1] = %q, want the caller's key", args[3])
	}
	if args[4] != "1500" {
		t.Errorf("ARGV[1] = %q, want 1500 milliseconds; the caller asked for 1500ms", args[4])
	}
}
