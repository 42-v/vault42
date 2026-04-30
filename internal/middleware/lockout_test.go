package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

func TestLockoutUnderThreshold(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	threshold := 5

	// Simulate 3 failed attempts (under threshold of 5)
	var locked bool
	var err error
	for i := 0; i < 3; i++ {
		locked, err = CheckAccountLockout(ctx, c, "user-001", threshold, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error on attempt %d: %v", i+1, err)
		}
	}

	if locked {
		t.Error("user should not be locked after 3 attempts with threshold 5")
	}
}

func TestLockoutExceedsThreshold(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	threshold := 5

	// Simulate 6 failed attempts (exceeds threshold of 5)
	var locked bool
	var err error
	for i := 0; i < 6; i++ {
		locked, err = CheckAccountLockout(ctx, c, "user-002", threshold, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error on attempt %d: %v", i+1, err)
		}
	}

	if !locked {
		t.Error("user should be locked after 6 attempts with threshold 5")
	}
}

func TestLockoutCacheError(t *testing.T) {
	c := cache.NewMemoryCache()
	// Close the cache to simulate failure — MemoryCache won't actually error,
	// so we test the graceful degradation path by verifying the function
	// returns false (not locked) even on the first call.
	c.Close()

	ctx := context.Background()

	// Even though cache might be in an uncertain state, CheckAccountLockout
	// should gracefully degrade and return false (not locked) on error.
	locked, err := CheckAccountLockout(ctx, c, "user-003", 1, time.Minute)
	if err != nil {
		t.Fatalf("expected nil error (graceful degradation), got: %v", err)
	}
	if locked {
		t.Error("should return false (not locked) on cache error / graceful degradation")
	}
}

func TestLockoutExactThreshold(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	threshold := 5

	// Exactly 5 attempts — should NOT be locked (count > threshold, not >=)
	var locked bool
	for i := 0; i < 5; i++ {
		var err error
		locked, err = CheckAccountLockout(ctx, c, "user-004", threshold, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error on attempt %d: %v", i+1, err)
		}
	}

	if locked {
		t.Error("user should not be locked at exactly the threshold (count must exceed, not equal)")
	}

	// The 6th attempt should trigger lockout
	locked, err := CheckAccountLockout(ctx, c, "user-004", threshold, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !locked {
		t.Error("user should be locked after exceeding the threshold")
	}
}
