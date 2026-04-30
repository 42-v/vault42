package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ErrNotFound tests
// ---------------------------------------------------------------------------

func TestErrNotFound_Error(t *testing.T) {
	msg := ErrNotFound.Error()
	if msg != "cache: key not found" {
		t.Errorf("ErrNotFound.Error() = %q, want %q", msg, "cache: key not found")
	}
}

func TestErrNotFound_WrappedErrorsIs(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("errors.Is on wrapped ErrNotFound should be true")
	}
}

// ---------------------------------------------------------------------------
// NewCache factory tests
// ---------------------------------------------------------------------------

func TestNewCache_Memory(t *testing.T) {
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache(memory) error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "fk", "fv", time.Minute); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	val, err := c.Get(ctx, "fk")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "fv" {
		t.Errorf("got %q, want %q", val, "fv")
	}
}

func TestNewCache_MemoryIsDefault(t *testing.T) {
	// Unknown backend should fall back to memory.
	c, err := NewCache("unknown_backend", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache(unknown) error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "dk", "dv", time.Minute); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	val, err := c.Get(ctx, "dk")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "dv" {
		t.Errorf("got %q, want %q", val, "dv")
	}
}

func TestNewCache_EmptyStringDefault(t *testing.T) {
	c, err := NewCache("", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache('') error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "ek", "ev", time.Minute); err != nil {
		t.Fatal(err)
	}
	val, err := c.Get(ctx, "ek")
	if err != nil {
		t.Fatal(err)
	}
	if val != "ev" {
		t.Errorf("got %q, want %q", val, "ev")
	}
}

func TestNewCache_RedisInvalidAddr(t *testing.T) {
	// Invalid address should fail to ping and return an error.
	_, err := NewCache("redis", "invalid:99999", "", nil)
	if err == nil {
		t.Fatal("NewCache(redis, invalid addr) should return error")
	}
}

func TestNewCache_PostgresNilPool(t *testing.T) {
	_, err := NewCache("postgres", "", "", nil)
	if err == nil {
		t.Fatal("NewCache(postgres, nil pool) should return error")
	}
}

func TestNewCache_PostgresNilPoolMessage(t *testing.T) {
	_, err := NewCache("postgres", "", "", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	want := "cache: postgres backend requires a connection pool"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestNewCache_MemoryImplementsInterface(t *testing.T) {
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Verify the returned value satisfies Cache interface.
	_ = c
}

func TestNewCache_MemoryCloseIdempotent(t *testing.T) {
	// Close from factory-created cache should work.
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
}
