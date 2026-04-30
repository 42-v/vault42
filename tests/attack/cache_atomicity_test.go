package attack

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

// TestCacheSetIfNotExistsAtomicity verifies that SetIfNotExists is truly
// atomic under high contention — no double-grants even with goroutines
// racing at maximum speed.
func TestCacheSetIfNotExistsAtomicity(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	// Run 100 rounds with 50 goroutines each
	for round := 0; round < 100; round++ {
		key := "atomic_test_" + string(rune(round+'A'))
		var granted int64
		var wg sync.WaitGroup
		const workers = 50
		wg.Add(workers)

		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				ok, _ := mc.SetIfNotExists(ctx, key, "1", time.Second)
				if ok {
					atomic.AddInt64(&granted, 1)
				}
			}()
		}

		wg.Wait()

		if granted != 1 {
			t.Fatalf("round %d: expected exactly 1 grant, got %d", round, granted)
		}

		// Clean up for next round
		mc.Delete(ctx, key)
	}
}

// TestCacheGetAndDeleteAtomicity verifies that GetAndDelete is atomic —
// only one goroutine gets the value when many race to consume a token.
func TestCacheGetAndDeleteAtomicity(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	for round := 0; round < 100; round++ {
		key := "token_consume_" + string(rune(round+'A'))
		mc.Set(ctx, key, "secret-value", time.Minute)

		var found int64
		var wg sync.WaitGroup
		const workers = 50
		wg.Add(workers)

		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				val, err := mc.GetAndDelete(ctx, key)
				if err == nil && val == "secret-value" {
					atomic.AddInt64(&found, 1)
				}
			}()
		}

		wg.Wait()

		if found != 1 {
			t.Fatalf("round %d: expected exactly 1 consumer, got %d", round, found)
		}
	}
}

// TestCacheIncrementRaceConsistency verifies that Increment under contention
// produces the correct final count (no lost increments).
func TestCacheIncrementRaceConsistency(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	key := "rate_limit_counter"
	const increments = 1000
	var wg sync.WaitGroup
	wg.Add(increments)

	for i := 0; i < increments; i++ {
		go func() {
			defer wg.Done()
			mc.Increment(ctx, key, time.Minute)
		}()
	}

	wg.Wait()

	val, err := mc.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "1000" {
		t.Fatalf("expected counter=1000 after %d increments, got %s", increments, val)
	}
}
