package cache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryCacheGetSet(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "key1", "value1", time.Minute); err != nil {
		t.Fatal(err)
	}

	val, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatal(err)
	}
	if val != "value1" {
		t.Errorf("got %q, want value1", val)
	}
}

func TestMemoryCacheNotFound(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	_, err := c.Get(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryCacheTTLExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "expiring", "val", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Should exist immediately
	val, err := c.Get(ctx, "expiring")
	if err != nil {
		t.Fatal(err)
	}
	if val != "val" {
		t.Error("should exist immediately")
	}

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	_, err = c.Get(ctx, "expiring")
	if !errors.Is(err, ErrNotFound) {
		t.Error("should be expired")
	}
}

func TestMemoryCacheDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "del", "val", time.Minute)
	c.Delete(ctx, "del")

	_, err := c.Get(ctx, "del")
	if !errors.Is(err, ErrNotFound) {
		t.Error("deleted key should not be found")
	}
}

func TestMemoryCacheIncrement(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	v1, _ := c.Increment(ctx, "counter", time.Minute)
	if v1 != 1 {
		t.Errorf("first increment = %d, want 1", v1)
	}

	v2, _ := c.Increment(ctx, "counter", time.Minute)
	if v2 != 2 {
		t.Errorf("second increment = %d, want 2", v2)
	}

	v3, _ := c.Increment(ctx, "counter", time.Minute)
	if v3 != 3 {
		t.Errorf("third increment = %d, want 3", v3)
	}
}

func TestMemoryCacheExists(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	exists, _ := c.Exists(ctx, "nope")
	if exists {
		t.Error("nonexistent key should not exist")
	}

	c.Set(ctx, "yes", "val", time.Minute)
	exists, _ = c.Exists(ctx, "yes")
	if !exists {
		t.Error("set key should exist")
	}
}

func TestMemoryCacheConcurrent(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key"
			c.Set(ctx, key, "val", time.Minute)
			c.Get(ctx, key)
			c.Increment(ctx, "counter", time.Minute)
			c.Exists(ctx, key)
		}(i)
	}
	wg.Wait()

	// Counter should be 100
	val, _ := c.Get(ctx, "counter")
	if val != "100" {
		t.Errorf("concurrent counter = %s, want 100", val)
	}
}
