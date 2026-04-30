package attack

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/service"
)

// TestChallengeToken_ReplayBlocked verifies that a consumed challenge token JTI
// is rejected on second use via the cache-backed single-use enforcement.
func TestChallengeToken_ReplayBlocked(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemoryCache()
	defer c.Close()

	jti := "test-challenge-jti-001"

	// First use: SetIfNotExists should succeed
	set, err := c.SetIfNotExists(ctx, "challenge_used:"+jti, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}
	if !set {
		t.Fatal("first use of challenge JTI should succeed")
	}

	// Second use: SetIfNotExists should fail (already consumed)
	set, err = c.SetIfNotExists(ctx, "challenge_used:"+jti, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error on replay: %v", err)
	}
	if set {
		t.Fatal("replayed challenge JTI should be rejected (SetIfNotExists should return false)")
	}
}

// TestChallengeToken_ReplayDifferentJTIs verifies that different JTIs are
// tracked independently (consuming one does not block another).
func TestChallengeToken_ReplayDifferentJTIs(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemoryCache()
	defer c.Close()

	jti1 := "challenge-jti-aaa"
	jti2 := "challenge-jti-bbb"

	// Consume jti1
	set, _ := c.SetIfNotExists(ctx, "challenge_used:"+jti1, "1", 5*time.Minute)
	if !set {
		t.Fatal("jti1 first use should succeed")
	}

	// jti2 should still be available
	set, _ = c.SetIfNotExists(ctx, "challenge_used:"+jti2, "1", 5*time.Minute)
	if !set {
		t.Fatal("jti2 should succeed independently of jti1")
	}

	// jti1 replay should fail
	set, _ = c.SetIfNotExists(ctx, "challenge_used:"+jti1, "1", 5*time.Minute)
	if set {
		t.Fatal("jti1 replay should be rejected")
	}
}

// TestErrChallengeConsumed verifies the sentinel error is properly defined.
func TestErrChallengeConsumed(t *testing.T) {
	err := service.ErrChallengeConsumed
	if err == nil {
		t.Fatal("ErrChallengeConsumed should not be nil")
	}
	if err.Error() != "challenge token already consumed" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}
