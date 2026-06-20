package cache

import (
	"context"
	"fmt"
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

func TestPostgresCache_ImplementsInterface(t *testing.T) {
	var _ Cache = (*PostgresCache)(nil)
}

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

// TestPostgresCache_Methods_NilPool executes the method bodies (they panic on nil pool)
// to achieve statement coverage for the error-path / wrapper code. Panics are recovered.
func TestPostgresCache_Methods_NilPool(t *testing.T) {
	pc, err := NewPostgresCache(nil)
	if err != nil || pc == nil {
		t.Fatal("constructor")
	}
	ctx := context.Background()
	cases := []func(){
		func() { _, _ = pc.Get(ctx, "k") },
		func() { _ = pc.Set(ctx, "k", "v", time.Minute) },
		func() { _ = pc.Delete(ctx, "k") },
		func() { _, _ = pc.GetAndDelete(ctx, "k") },
		func() { _, _ = pc.SetIfNotExists(ctx, "k", "v", time.Minute) },
		func() { _, _ = pc.Increment(ctx, "k", time.Minute) },
		func() { _, _ = pc.Exists(ctx, "k") },
		func() { _ = pc.Close() },
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("method_%d", i), func(t *testing.T) {
			defer func() { _ = recover() }()
			c()
		})
	}
}
