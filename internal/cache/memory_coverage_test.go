package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GetAndDelete tests
// ---------------------------------------------------------------------------

func TestMemoryGetAndDelete_ExistingKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "gad", "hello", time.Minute)

	val, err := c.GetAndDelete(ctx, "gad")
	if err != nil {
		t.Fatalf("GetAndDelete error: %v", err)
	}
	if val != "hello" {
		t.Errorf("got %q, want %q", val, "hello")
	}

	// Key should be gone now.
	_, err = c.Get(ctx, "gad")
	if !errors.Is(err, ErrNotFound) {
		t.Error("key should be deleted after GetAndDelete")
	}
}

func TestMemoryGetAndDelete_MissingKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	_, err := c.GetAndDelete(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryGetAndDelete_ExpiredKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "gad_exp", "val", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	_, err := c.GetAndDelete(ctx, "gad_exp")
	if !errors.Is(err, ErrNotFound) {
		t.Error("GetAndDelete on expired key should return ErrNotFound")
	}
}

func TestMemoryGetAndDelete_Concurrent(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "race", "winner", time.Minute)

	var wg sync.WaitGroup
	wins := make(chan string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := c.GetAndDelete(ctx, "race")
			if err == nil {
				wins <- val
			}
		}()
	}
	wg.Wait()
	close(wins)

	// Exactly one goroutine should have succeeded.
	count := 0
	for v := range wins {
		if v != "winner" {
			t.Errorf("unexpected value %q", v)
		}
		count++
	}
	if count != 1 {
		t.Errorf("expected exactly 1 winner, got %d", count)
	}
}

func TestMemoryGetAndDelete_ZeroTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	// TTL 0 means no expiry.
	c.Set(ctx, "notexp", "perm", 0)
	val, err := c.GetAndDelete(ctx, "notexp")
	if err != nil {
		t.Fatalf("GetAndDelete error: %v", err)
	}
	if val != "perm" {
		t.Errorf("got %q, want %q", val, "perm")
	}
}

// ---------------------------------------------------------------------------
// Cleanup goroutine tests
// ---------------------------------------------------------------------------

func TestMemoryCleanup_RemovesExpiredKeys(t *testing.T) {
	// Create cache with manual ticker trigger.
	mc := &MemoryCache{
		data: make(map[string]memEntry),
		done: make(chan struct{}),
	}
	// Do NOT start the cleanup goroutine; we will invoke the cleanup logic manually.
	ctx := context.Background()

	// Set key with already-expired time.
	mc.mu.Lock()
	mc.data["expired"] = memEntry{value: "old", expiresAt: time.Now().Add(-time.Second)}
	mc.data["alive"] = memEntry{value: "live", expiresAt: time.Now().Add(time.Hour)}
	mc.data["noexp"] = memEntry{value: "perm", expiresAt: time.Time{}}
	mc.mu.Unlock()

	// Run one cycle of cleanup logic manually.
	mc.mu.Lock()
	now := time.Now()
	for k, e := range mc.data {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			delete(mc.data, k)
		}
	}
	mc.mu.Unlock()

	// "expired" should be gone.
	_, err := mc.Get(ctx, "expired")
	if !errors.Is(err, ErrNotFound) {
		t.Error("expired key should have been cleaned up")
	}

	// "alive" should still exist.
	val, err := mc.Get(ctx, "alive")
	if err != nil {
		t.Fatalf("alive key error: %v", err)
	}
	if val != "live" {
		t.Errorf("got %q, want %q", val, "live")
	}

	// "noexp" (zero TTL) should still exist.
	val, err = mc.Get(ctx, "noexp")
	if err != nil {
		t.Fatalf("noexp key error: %v", err)
	}
	if val != "perm" {
		t.Errorf("got %q, want %q", val, "perm")
	}

	close(mc.done)
}

func TestMemoryCleanup_GoroutineStopsOnClose(t *testing.T) {
	c := NewMemoryCache()
	// Close should stop the cleanup goroutine.
	err := c.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}
	// Give goroutine a moment to exit; no panic = success.
	time.Sleep(10 * time.Millisecond)
}

func TestMemoryCleanup_TTLExpiryViaGet(t *testing.T) {
	// Even without cleanup, Get should treat expired entries as not found.
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "short", "v", 30*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	_, err := c.Get(ctx, "short")
	if !errors.Is(err, ErrNotFound) {
		t.Error("expired key via Get should return ErrNotFound")
	}
}

// ---------------------------------------------------------------------------
// Additional memory cache coverage
// ---------------------------------------------------------------------------

func TestMemorySet_OverwriteValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "ow", "first", time.Minute)
	c.Set(ctx, "ow", "second", time.Minute)

	val, err := c.Get(ctx, "ow")
	if err != nil {
		t.Fatal(err)
	}
	if val != "second" {
		t.Errorf("got %q, want %q", val, "second")
	}
}

func TestMemorySet_ZeroTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "z", "val", 0)
	// Should be retrievable since zero TTL = no expiry.
	val, _ := c.Get(ctx, "z")
	if val != "val" {
		t.Errorf("got %q, want %q", val, "val")
	}
}

func TestMemoryDelete_NonexistentKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	// Delete of nonexistent key should not error.
	err := c.Delete(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("Delete nonexistent key should not error: %v", err)
	}
}

func TestMemoryIncrement_StartsAtOne(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	v, err := c.Increment(context.Background(), "fresh", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("first increment = %d, want 1", v)
	}
}

func TestMemoryIncrement_ExpiredResets(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Increment(ctx, "cnt", 20*time.Millisecond)
	c.Increment(ctx, "cnt", 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	// After expiry, should restart at 1.
	v, _ := c.Increment(ctx, "cnt", time.Minute)
	if v != 1 {
		t.Errorf("increment after expiry = %d, want 1", v)
	}
}

func TestMemoryIncrement_NonNumericValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	// Set a non-numeric value, then increment. ParseInt returns 0 on failure, so result is 1.
	c.Set(ctx, "bad", "notanumber", time.Minute)
	v, err := c.Increment(ctx, "bad", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("increment on non-numeric = %d, want 1", v)
	}
}

func TestMemoryIncrement_ZeroTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	v1, _ := c.Increment(ctx, "zt", 0)
	v2, _ := c.Increment(ctx, "zt", 0)
	if v1 != 1 || v2 != 2 {
		t.Errorf("zero TTL increments = %d, %d; want 1, 2", v1, v2)
	}
}

func TestMemoryExists_Expired(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "ex", "v", 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	exists, err := c.Exists(ctx, "ex")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expired key should not exist")
	}
}

func TestMemoryClose_ReturnsNil(t *testing.T) {
	c := NewMemoryCache()
	err := c.Close()
	if err != nil {
		t.Fatalf("Close should return nil, got %v", err)
	}
}

// The oracle here is the race detector, not a comparison. Every operation on the
// memory cache touches the same map and the same expiry bookkeeping, and
// interleaving all of them across 50 goroutines is what makes an unguarded
// access observable when the suite runs under -race. Completing is the second
// half: several of these paths take locks in sequence, so a lock-order mistake
// hangs rather than fails, and the package timeout is what reports it.
func TestMemoryConcurrent_StressAllOps(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("stress_%d", i%5)
			c.Set(ctx, key, "val", time.Minute)
			c.Get(ctx, key)
			c.Exists(ctx, key)
			c.Increment(ctx, fmt.Sprintf("stress_cnt_%d", i%3), time.Minute)
			c.GetAndDelete(ctx, key)
			c.Delete(ctx, key)
		}(i)
	}
	wg.Wait()
}

func TestMemoryGetAndDelete_ThenGetAndDeleteAgain(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "once", "val", time.Minute)

	_, err := c.GetAndDelete(ctx, "once")
	if err != nil {
		t.Fatal(err)
	}

	// Second call should return ErrNotFound.
	_, err = c.GetAndDelete(ctx, "once")
	if !errors.Is(err, ErrNotFound) {
		t.Error("second GetAndDelete should return ErrNotFound")
	}
}

func TestMemorySet_EmptyKeyAndValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	err := c.Set(ctx, "", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	val, err := c.Get(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if val != "" {
		t.Errorf("got %q, want empty string", val)
	}
}

func TestMemorySet_LargeValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	large := make([]byte, 1<<16) // 64 KB
	for i := range large {
		large[i] = byte('a' + i%26)
	}
	s := string(large)

	c.Set(ctx, "big", s, time.Minute)
	val, err := c.Get(ctx, "big")
	if err != nil {
		t.Fatal(err)
	}
	if val != s {
		t.Error("large value roundtrip failed")
	}
}
