package cache

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// PostgresCache tests — no real PostgreSQL required.
// These test the constructor, interface conformance, Close, and error handling
// when operations are called with a nil pool.
// ---------------------------------------------------------------------------

func TestNewPostgresCache_NilPool(t *testing.T) {
	// Constructor accepts nil pool (validation is in the factory, not here).
	pc, err := NewPostgresCache(nil)
	if err != nil {
		t.Fatalf("NewPostgresCache(nil) error: %v", err)
	}
	if pc == nil {
		t.Fatal("NewPostgresCache(nil) returned nil cache")
	}
}

// Compile-time conformance. This was a test function whose body was this line,
// so it ran, asserted nothing, and reported the same result whether or not the
// package still compiled -- the compiler had already decided by then.
var _ Cache = (*PostgresCache)(nil)

func TestPostgresCache_Close(t *testing.T) {
	pc, _ := NewPostgresCache(nil)
	err := pc.Close()
	if err != nil {
		t.Fatalf("Close should return nil, got %v", err)
	}
}

func TestPostgresCache_CloseMultiple(t *testing.T) {
	pc, _ := NewPostgresCache(nil)
	for i := 0; i < 3; i++ {
		if err := pc.Close(); err != nil {
			t.Fatalf("Close call %d: %v", i, err)
		}
	}
}

func TestPostgresCache_StructFields(t *testing.T) {
	pc, _ := NewPostgresCache(nil)
	// pool should be nil when constructed with nil.
	if pc.pool != nil {
		t.Error("pool should be nil")
	}
}

// The factory refuses a nil pool, so this reaches past it to run the method
// bodies with nothing behind them. What it pins is that they fail loudly rather
// than answering: a method that swallowed the nil and returned ("", ErrNotFound)
// or (false, nil) would be indistinguishable from a genuine cache miss, and a
// miss is what the rate limiter and the lockout counter read as "no attempts
// recorded yet". Close is excluded because it touches no pool and is documented
// as safe on a half-built cache; TestPostgresCache_Close covers it.
func TestPostgresCache_Methods_NilPool(t *testing.T) {
	pc, err := NewPostgresCache(nil)
	if err != nil || pc == nil {
		t.Fatal("constructor")
	}
	ctx := context.Background()
	cases := []struct {
		name string
		call func()
	}{
		{"Get", func() { _, _ = pc.Get(ctx, "k") }},
		{"Set", func() { _ = pc.Set(ctx, "k", "v", time.Minute) }},
		{"Delete", func() { _ = pc.Delete(ctx, "k") }},
		{"GetAndDelete", func() { _, _ = pc.GetAndDelete(ctx, "k") }},
		{"SetIfNotExists", func() { _, _ = pc.SetIfNotExists(ctx, "k", "v", time.Minute) }},
		{"Increment", func() { _, _ = pc.Increment(ctx, "k", time.Minute) }},
		{"Exists", func() { _, _ = pc.Exists(ctx, "k") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s returned a value with no pool behind it; a caller cannot tell that from a real cache miss", tc.name)
				}
			}()
			tc.call()
		})
	}

	if err := pc.Close(); err != nil {
		t.Errorf("Close on a pool-less cache = %v, want nil", err)
	}
}
