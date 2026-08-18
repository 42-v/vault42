package middleware

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// The in-memory fallback is only reached during a cache outage, and it is keyed
// by client IP. A v6 source presents an unbounded number of distinct keys and
// each entry lives for the limiter's whole window — an hour, for the
// account-deletion limiter — so uncapped it is an OOM during exactly the outage
// it exists to survive (operability audit 3.5).

func TestLocalRateLimiterCapsEntries(t *testing.T) {
	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}

	for i := 0; i < localRLMaxEntries; i++ {
		if got := l.increment("ip:2001:db8::"+strconv.Itoa(i), time.Hour); got != 1 {
			t.Fatalf("increment #%d = %d, want 1", i, got)
		}
	}
	if got := l.localEntryCount(); got != localRLMaxEntries {
		t.Fatalf("entries = %d, want %d", got, localRLMaxEntries)
	}

	// One past the cap: a NEW key is refused rather than admitted, so the
	// degraded control still denies instead of silently allowing everything.
	if got := l.increment("ip:2001:db8::overflow", time.Hour); got != math.MaxInt64 {
		t.Fatalf("increment past the cap = %d, want math.MaxInt64 so the caller answers 429", got)
	}
	if got := l.localEntryCount(); got != localRLMaxEntries {
		t.Fatalf("a refused key was still stored: entries = %d, want %d", got, localRLMaxEntries)
	}

	// A key that is already tracked keeps counting: the cap must not hand an
	// established caller an unlimited budget.
	if got := l.increment("ip:2001:db8::0", time.Hour); got != 2 {
		t.Fatalf("increment of an existing key at the cap = %d, want 2", got)
	}

	// The at-cap warning latches, so a sustained flood logs once, not once per
	// request.
	if !l.atCap {
		t.Fatal("atCap was not latched after the cap was hit")
	}
	if got := l.increment("ip:2001:db8::overflow2", time.Hour); got != math.MaxInt64 {
		t.Fatalf("second overflow = %d, want math.MaxInt64", got)
	}
}

// TestLocalRateLimiterReusesExpiredSlot shows the cap does not wedge: an entry
// whose window has lapsed is rewritten in place rather than counted as new, so
// a limiter at the cap recovers as its windows roll over even before the 60s
// sweep runs.
func TestLocalRateLimiterReusesExpiredSlot(t *testing.T) {
	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}

	if got := l.increment("ip:198.51.100.4", time.Millisecond); got != 1 {
		t.Fatalf("first increment = %d, want 1", got)
	}
	time.Sleep(5 * time.Millisecond)
	if got := l.increment("ip:198.51.100.4", time.Hour); got != 1 {
		t.Fatalf("increment after the window lapsed = %d, want 1 (fresh window)", got)
	}
	if got := l.localEntryCount(); got != 1 {
		t.Fatalf("entries = %d, want 1", got)
	}
}
