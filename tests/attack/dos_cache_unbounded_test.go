package attack

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

// Every key MemoryCache holds is attacker-chosen in practice: the rate limiter
// writes one per client address on every request including the ones it rejects,
// OAuth authorize writes one nonce per call, and lockout and reset counters key
// on identifiers a caller supplies. An IPv6 source has a /64 to spend. A million
// entries at ~150 bytes is ~150 MiB, living for the window of whichever limiter
// was hit first — up to an hour — inside a 512 MiB pod, and this backend is also
// what the process falls back to when Redis is down, so the flood lands during
// an outage.

// TestDoS_MemoryCacheRefusesNewKeysAtTheCap is the regression. The exact cap is
// a production constant, so the assertion is on the behavior at whatever it is
// rather than on the number.
func TestDoS_MemoryCacheRefusesNewKeysAtTheCap(t *testing.T) {
	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })
	ctx := context.Background()

	var refusedAt int
	for i := 0; i < 1_000_000; i++ {
		_, err := mc.Increment(ctx, fmt.Sprintf("rl:refresh:ip:2001:db8:%d::1", i), time.Hour)
		if errors.Is(err, cache.ErrCacheFull) {
			refusedAt = i
			break
		}
		if err != nil {
			t.Fatalf("Increment #%d: %v", i, err)
		}
	}
	if refusedAt == 0 {
		t.Fatal("a million distinct attacker-chosen keys were all accepted; the cache has no entry cap")
	}
	t.Logf("memory cache refused a new key after %d entries", refusedAt)

	// A key already in the cache must keep working at the cap. The cap must
	// not hand an established caller an unlimited budget, and it must not
	// break the counters that are already tracking one.
	existing := "rl:refresh:ip:2001:db8:0::1"
	n, err := mc.Increment(ctx, existing, time.Hour)
	if err != nil {
		t.Fatalf("Increment of a tracked key at the cap: %v", err)
	}
	if n != 2 {
		t.Fatalf("Increment of a tracked key at the cap = %d, want 2", n)
	}

	// Set and SetIfNotExists refuse too, or the cap would only cover one of
	// the three write paths.
	if err := mc.Set(ctx, "oauth_state:brand-new", "1", time.Minute); !errors.Is(err, cache.ErrCacheFull) {
		t.Fatalf("Set of a new key at the cap = %v, want ErrCacheFull", err)
	}
	if _, err := mc.SetIfNotExists(ctx, "reset:brand-new", "1", time.Minute); !errors.Is(err, cache.ErrCacheFull) {
		t.Fatalf("SetIfNotExists of a new key at the cap = %v, want ErrCacheFull", err)
	}
	// Overwriting a key that is already there is not a new key.
	if err := mc.Set(ctx, existing, "7", time.Hour); err != nil {
		t.Fatalf("Set of a tracked key at the cap: %v", err)
	}
}

// TestDoS_CacheFullIsNotAMiss is why the refusal has its own error. Callers
// read ErrNotFound as "no counter yet", which for a rate limiter or a lockout
// means admit the request — the last answer a saturated cache should give.
func TestDoS_CacheFullIsNotAMiss(t *testing.T) {
	if errors.Is(cache.ErrCacheFull, cache.ErrNotFound) {
		t.Fatal("ErrCacheFull matches ErrNotFound, so a full cache reads as an empty counter " +
			"and every fail-closed limiter admits the flood that filled it")
	}
	if errors.Is(cache.ErrNotFound, cache.ErrCacheFull) {
		t.Fatal("ErrNotFound matches ErrCacheFull")
	}
}

// TestDoS_MemoryCacheIncrementReusesExpiredKey shows the cap does not wedge:
// an entry whose window has lapsed is rewritten in place rather than counted as
// a new key, so a cache at the cap recovers as its TTLs roll over even before
// the 30s sweep runs.
func TestDoS_MemoryCacheIncrementReusesExpiredKey(t *testing.T) {
	mc := cache.NewMemoryCache()
	t.Cleanup(func() { _ = mc.Close() })
	ctx := context.Background()

	if _, err := mc.Increment(ctx, "rl:refresh:ip:203.0.113.1", 20*time.Millisecond); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	n, err := mc.Increment(ctx, "rl:refresh:ip:203.0.113.1", time.Hour)
	if err != nil {
		t.Fatalf("Increment after expiry: %v", err)
	}
	if n != 1 {
		t.Fatalf("Increment after expiry = %d, want 1 (fresh window)", n)
	}
}
