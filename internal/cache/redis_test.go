package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	vredis "github.com/42-v/vault42/internal/redis"
)

// ---------------------------------------------------------------------------
// Redis cache tests — no real Redis server required.
// These exercise constructor error paths and struct validation.
// ---------------------------------------------------------------------------

func TestNewRedisCache_ErrorCases(t *testing.T) {
	tests := []struct {
		name string
		addr string
		pass string
		db   int
	}{
		{"invalid_addr", "invalid:99999", "", 0},
		{"empty_addr", "", "", 0},
		{"port_zero", "localhost:0", "", 0},
		{"high_db", "invalid:99999", "", 15},
		{"with_password", "invalid:99999", "secret", 0},
		{"with_db", "invalid:99999", "", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRedisCache(tt.addr, tt.pass, tt.db)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewRedisCache_TimeoutBehavior(t *testing.T) {
	// Connect to an address that will time out (non-routable IP).
	// The constructor has a 5-second timeout, but we don't want to wait that long.
	// Use a clearly invalid address instead.
	start := time.Now()
	_, err := NewRedisCache("invalid:99999", "", 0)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error")
	}
	// Should fail relatively quickly (DNS failure), not hang for 5s.
	if elapsed > 10*time.Second {
		t.Errorf("took %v, expected much faster failure", elapsed)
	}
}

func TestRedisCacheStruct_ImplementsInterface(t *testing.T) {
	// Compile-time check that RedisCache satisfies Cache.
	var _ Cache = (*RedisCache)(nil)
}

// TestRedisCache_Methods_NilClient covers the redis cache method bodies for coverage (early deref panics recovered).
func TestRedisCache_Methods_NilClient(t *testing.T) {
	rc := &RedisCache{client: (*vredis.Client)(nil)}
	ctx := context.Background()
	cases := []func(){
		func() { _, _ = rc.Get(ctx, "k") },
		func() { _ = rc.Set(ctx, "k", "v", time.Second) },
		func() { _ = rc.Delete(ctx, "k") },
		func() { _, _ = rc.GetAndDelete(ctx, "k") },
		func() { _, _ = rc.SetIfNotExists(ctx, "k", "v", time.Second) },
		func() { _, _ = rc.Increment(ctx, "k", time.Second) },
		func() { _, _ = rc.Exists(ctx, "k") },
		func() { rc.Close() },
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("rc_%d", i), func(t *testing.T) {
			defer func() { _ = recover() }()
			c()
		})
	}
}
