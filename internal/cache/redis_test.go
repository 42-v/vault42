package cache

import (
	"context"
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
		{"unresolvable_host", "bad:1", "", 0},
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

// Compile-time conformance. This was a test function whose body was this line,
// so it ran, asserted nothing, and reported the same result whether or not the
// package still compiled -- the compiler had already decided by then.
var _ Cache = (*RedisCache)(nil)

// A RedisCache holding no client cannot be built through NewRedisCache, so this
// is reaching past the constructor to run the method bodies. What it pins is
// that they fail loudly: a wrapper that swallowed the nil and returned a zero
// value would hand a rate limiter ("", ErrNotFound) or (0, nil), which reads as
// "no attempts recorded yet" and admits the request. Close is on the list for
// the same reason -- it is the one method a caller might expect to tolerate a
// half-built cache.
func TestRedisCache_Methods_NilClient(t *testing.T) {
	rc := &RedisCache{client: (*vredis.Client)(nil)}
	ctx := context.Background()
	cases := []struct {
		name string
		call func()
	}{
		{"Get", func() { _, _ = rc.Get(ctx, "k") }},
		{"Set", func() { _ = rc.Set(ctx, "k", "v", time.Second) }},
		{"Delete", func() { _ = rc.Delete(ctx, "k") }},
		{"GetAndDelete", func() { _, _ = rc.GetAndDelete(ctx, "k") }},
		{"SetIfNotExists", func() { _, _ = rc.SetIfNotExists(ctx, "k", "v", time.Second) }},
		{"Increment", func() { _, _ = rc.Increment(ctx, "k", time.Second) }},
		{"Exists", func() { _, _ = rc.Exists(ctx, "k") }},
		{"Close", func() { _ = rc.Close() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s returned a value with no client behind it; a caller cannot tell that from a real answer", tc.name)
				}
			}()
			tc.call()
		})
	}
}
