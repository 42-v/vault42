package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Increment uses fixed-window semantics: the expiry set on the first increment
// is preserved across subsequent increments rather than being extended. A key
// created with a short TTL must therefore expire at the original deadline even
// if it keeps being incremented.
func TestMemory_IncrementPreservesFixedWindow(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	if _, err := c.Increment(ctx, "window", 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Second increment must not reset the original window.
	if _, err := c.Increment(ctx, "window", time.Hour); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	if _, err := c.Get(ctx, "window"); !errors.Is(err, ErrNotFound) {
		t.Errorf("counter should expire at the original window, got err=%v", err)
	}
}

// After a window expires, the next increment must restart the counter at 1 and
// apply the freshly supplied TTL (a new fixed window), so the reset value
// survives past the original deadline.
func TestMemory_IncrementResetsWindowAfterExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Increment(ctx, "reset-win", 20*time.Millisecond)
	c.Increment(ctx, "reset-win", 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	v, err := c.Increment(ctx, "reset-win", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("increment after expiry = %d, want 1", v)
	}

	// The fresh TTL must keep the reset value alive well past the old window.
	time.Sleep(30 * time.Millisecond)
	val, err := c.Get(ctx, "reset-win")
	if err != nil {
		t.Fatalf("reset counter should survive its new window: %v", err)
	}
	if val != "1" {
		t.Errorf("value = %q, want 1", val)
	}
}

// GetAndDelete on an expired entry returns ErrNotFound and, as a side effect,
// the subsequent SetIfNotExists must treat the slot as free (the stale entry
// must not block a new write).
func TestMemory_GetAndDeleteExpired_FreesSlot(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "stale", "old", 15*time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	if _, err := c.GetAndDelete(ctx, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAndDelete on expired key = %v, want ErrNotFound", err)
	}

	ok, err := c.SetIfNotExists(ctx, "stale", "fresh", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("SetIfNotExists should succeed once the expired entry is gone")
	}
}

// SetIfNotExists must observe a value freshly written by Increment as an
// existing key and refuse to overwrite it, returning false.
func TestMemory_SetIfNotExistsBlockedByIncrement(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Increment(ctx, "counter-key", time.Minute)

	ok, err := c.SetIfNotExists(ctx, "counter-key", "override", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("SetIfNotExists should return false against an existing counter")
	}

	val, err := c.Get(ctx, "counter-key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "1" {
		t.Errorf("value = %q, want the counter value 1", val)
	}
}

// A key consumed by GetAndDelete is truly removed, so a following
// SetIfNotExists for the same key succeeds.
func TestMemory_SetIfNotExistsAfterGetAndDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "consumed", "token", time.Minute)
	if _, err := c.GetAndDelete(ctx, "consumed"); err != nil {
		t.Fatal(err)
	}

	ok, err := c.SetIfNotExists(ctx, "consumed", "reissued", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("SetIfNotExists after GetAndDelete should succeed")
	}
}

// Under a concurrent SetIfNotExists race exactly one writer wins, and the
// value stored in the cache must be that same winner's value.
func TestMemory_SetIfNotExistsRace_WinnerValueStored(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const goroutines = 40
	var mu sync.Mutex
	var winnerVal string
	wins := 0

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			val := fmt.Sprintf("writer-%d", id)
			ok, err := c.SetIfNotExists(ctx, "lock", val, time.Minute)
			if err != nil {
				t.Errorf("writer %d: %v", id, err)
				return
			}
			if ok {
				mu.Lock()
				winnerVal = val
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", wins)
	}
	stored, err := c.Get(ctx, "lock")
	if err != nil {
		t.Fatal(err)
	}
	if stored != winnerVal {
		t.Errorf("stored value = %q, want winner's value %q", stored, winnerVal)
	}
}

// Increment treats a non-numeric stored value as zero, so incrementing a key
// previously set to text yields 1 without error (graceful type handling).
func TestMemory_IncrementOverNonNumericResetsToOne(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "typed", "alice", time.Minute)
	v, err := c.Increment(ctx, "typed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("increment over non-numeric value = %d, want 1", v)
	}
}
