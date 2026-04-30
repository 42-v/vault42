package attack

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

// TestTOTPReplayRaceCondition verifies that the TOTP replay prevention
// uses atomic SetIfNotExists to prevent concurrent replay attacks.
// Previously, Exists() + Set() had a TOCTOU race window where two
// concurrent requests with the same TOTP code could both succeed.
func TestTOTPReplayRaceCondition(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()

	cacheKey := "totp_used:user-123:55000000"
	ctx := context.Background()

	// Simulate 10 concurrent attempts to use the same TOTP code.
	// Only ONE should succeed (get true from SetIfNotExists).
	const concurrency = 10
	results := make([]bool, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			ok, err := mc.SetIfNotExists(ctx, cacheKey, "1", 90*time.Second)
			if err != nil {
				t.Errorf("SetIfNotExists error: %v", err)
				return
			}
			results[idx] = ok
		}(i)
	}

	wg.Wait()

	// Count how many succeeded
	succeeded := 0
	for _, ok := range results {
		if ok {
			succeeded++
		}
	}

	if succeeded != 1 {
		t.Fatalf("Expected exactly 1 successful SetIfNotExists, got %d (race condition!)", succeeded)
	}
}

// TestTOTPReplaySetIfNotExistsRejectsSecondAttempt verifies that after a
// TOTP code is marked as used, subsequent attempts are rejected.
func TestTOTPReplaySetIfNotExistsRejectsSecondAttempt(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	cacheKey := "totp_used:user-456:55000001"

	// First attempt should succeed
	ok1, err := mc.SetIfNotExists(ctx, cacheKey, "1", 90*time.Second)
	if err != nil {
		t.Fatalf("first SetIfNotExists error: %v", err)
	}
	if !ok1 {
		t.Fatal("first SetIfNotExists should have returned true")
	}

	// Second attempt should fail
	ok2, err := mc.SetIfNotExists(ctx, cacheKey, "1", 90*time.Second)
	if err != nil {
		t.Fatalf("second SetIfNotExists error: %v", err)
	}
	if ok2 {
		t.Fatal("second SetIfNotExists should have returned false (replay detected)")
	}
}

// TestTOTPReplayExpiry verifies that TOTP replay protection expires after TTL,
// allowing the same time step key to be reused in a new window.
func TestTOTPReplayExpiry(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	cacheKey := "totp_used:user-789:55000002"

	// Use a short TTL for testing (50ms avoids flakiness from scheduler jitter)
	ok, _ := mc.SetIfNotExists(ctx, cacheKey, "1", 50*time.Millisecond)
	if !ok {
		t.Fatal("first SetIfNotExists should succeed")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should succeed again after expiry
	ok2, _ := mc.SetIfNotExists(ctx, cacheKey, "1", 90*time.Second)
	if !ok2 {
		t.Fatal("SetIfNotExists should succeed after expiry")
	}
}
