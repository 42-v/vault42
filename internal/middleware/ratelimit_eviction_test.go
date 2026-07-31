package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The eviction goroutine is the only thing between a long-lived process and an
// unbounded map. Every distinct rate limit key seen while the shared cache is down
// lands in the fallback limiter and stays there: nothing else ever deletes an entry.
// A limiter keyed by client IP therefore grows one entry per attacker address until
// the sweep runs.
//
// The sweep has to be exact in both directions. Leaving ended windows behind is the
// leak. Dropping a window that is still open is worse: the next request from that key
// starts a fresh window at count 1, which hands whoever is being throttled their full
// budget back and quietly undoes brute-force protection.
func TestRateLimiterEvictionSweepDropsOnlyEndedWindows(t *testing.T) {
	evictInterval = 5 * time.Millisecond
	evictOnce = sync.Once{}

	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}
	const ended = 64
	for i := 0; i < ended; i++ {
		l.increment(fmt.Sprintf("mwcEnded:%d", i), -time.Minute)
	}
	l.increment("mwcOpen", time.Hour)
	l.increment("mwcOpen", time.Hour)

	addLimiter(l)

	var (
		remaining int
		open      *localRLEntry
	)
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		remaining = len(l.entries)
		open = l.entries["mwcOpen"]
		l.mu.Unlock()
		if remaining == 1 && open != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("eviction left %d of %d entries behind; the fallback limiter map grows without bound", remaining, ended+1)
		}
		time.Sleep(time.Millisecond)
	}

	l.mu.Lock()
	count := open.count
	windowEnd := open.windowEnd
	l.mu.Unlock()

	if count != 2 {
		t.Errorf("the open window was reset to count %d, want 2: eviction handed a throttled key a fresh budget", count)
	}
	if !windowEnd.After(time.Now()) {
		t.Errorf("the surviving entry has an ended window %v, so it was not the one under test", windowEnd)
	}

	if next := l.increment("mwcOpen", time.Hour); next != 3 {
		t.Errorf("increment after a sweep returned %d, want 3: the window was restarted rather than continued", next)
	}

	// Safe to restore only now: the sweep we observed happened after the goroutine
	// read evictInterval, and we observed it through the limiter mutex.
	evictInterval = 60 * time.Second
}
