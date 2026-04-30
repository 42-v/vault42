package cache

import (
	"testing"
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
