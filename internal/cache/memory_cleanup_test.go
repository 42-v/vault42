package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Get, Exists and GetAndDelete all treat an expired entry as missing, so nothing in
// the read path ever frees one. The background sweep is the only thing that does. In
// a process that has been up for a week, the entries are one-time codes, password
// reset tokens and rate limit counters: short-lived keys arriving continuously, none
// of which are ever deleted by hand. Without the sweep the map only grows.
//
// The sweep must be equally strict about what it keeps. An entry with a live TTL is a
// session or a challenge in flight, and an entry with no TTL never expires at all;
// dropping either logs someone out or breaks a single-use guarantee that is only
// single-use because the key is still there.
func TestMemoryCacheCleanupFreesExpiredEntriesAndKeepsLiveOnes(t *testing.T) {
	m := NewMemoryCache()
	defer m.Close()

	ctx := context.Background()
	const expired = 256
	for i := 0; i < expired; i++ {
		if err := m.Set(ctx, fmt.Sprintf("mwcShort:%d", i), "v", time.Millisecond); err != nil {
			t.Fatalf("set: %v", err)
		}
	}
	if err := m.Set(ctx, "mwcSession", "live", time.Hour); err != nil {
		t.Fatalf("set live: %v", err)
	}
	if err := m.Set(ctx, "mwcPermanent", "forever", 0); err != nil {
		t.Fatalf("set permanent: %v", err)
	}

	go m.cleanup(2 * time.Millisecond)

	var size int
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.RLock()
		size = len(m.data)
		m.mu.RUnlock()
		if size == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("map still holds %d entries, want 2: expired keys are never freed and the cache grows without bound", size)
		}
		time.Sleep(time.Millisecond)
	}

	if v, err := m.Get(ctx, "mwcSession"); err != nil || v != "live" {
		t.Errorf("cleanup evicted an unexpired entry: got (%q, %v), want (\"live\", nil)", v, err)
	}
	if v, err := m.Get(ctx, "mwcPermanent"); err != nil || v != "forever" {
		t.Errorf("cleanup evicted an entry that has no TTL: got (%q, %v), want (\"forever\", nil)", v, err)
	}
	if _, err := m.Get(ctx, "mwcShort:0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired key resurfaced after cleanup: err = %v, want ErrNotFound", err)
	}
}
