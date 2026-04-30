package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSetIfNotExists_NewKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	ok, err := c.SetIfNotExists(ctx, "fresh", "value1", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists error: %v", err)
	}
	if !ok {
		t.Error("SetIfNotExists on new key should return true")
	}
}

func TestSetIfNotExists_ExistingNonExpiredKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	ok, err := c.SetIfNotExists(ctx, "taken", "first", time.Minute)
	if err != nil {
		t.Fatalf("first SetIfNotExists error: %v", err)
	}
	if !ok {
		t.Fatal("first SetIfNotExists should return true")
	}

	ok, err = c.SetIfNotExists(ctx, "taken", "second", time.Minute)
	if err != nil {
		t.Fatalf("second SetIfNotExists error: %v", err)
	}
	if ok {
		t.Error("SetIfNotExists on existing non-expired key should return false")
	}

	// Value should still be the original.
	val, err := c.Get(ctx, "taken")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "first" {
		t.Errorf("value = %q, want %q", val, "first")
	}
}

func TestSetIfNotExists_ExpiredKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	ok, err := c.SetIfNotExists(ctx, "expiring", "old", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("SetIfNotExists error: %v", err)
	}
	if !ok {
		t.Fatal("initial SetIfNotExists should return true")
	}

	time.Sleep(40 * time.Millisecond)

	// Key has expired, so SetIfNotExists should treat it as new.
	ok, err = c.SetIfNotExists(ctx, "expiring", "new", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists on expired key error: %v", err)
	}
	if !ok {
		t.Error("SetIfNotExists on expired key should return true")
	}

	val, err := c.Get(ctx, "expiring")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "new" {
		t.Errorf("value = %q, want %q", val, "new")
	}
}

func TestSetIfNotExists_ZeroTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	ok, err := c.SetIfNotExists(ctx, "perm", "forever", 0)
	if err != nil {
		t.Fatalf("SetIfNotExists error: %v", err)
	}
	if !ok {
		t.Error("SetIfNotExists with zero TTL should return true for new key")
	}

	// Zero TTL means no expiry, so a second attempt should fail.
	ok, err = c.SetIfNotExists(ctx, "perm", "nope", 0)
	if err != nil {
		t.Fatalf("second SetIfNotExists error: %v", err)
	}
	if ok {
		t.Error("SetIfNotExists should return false when key exists with no expiry")
	}

	// Value should still be the original.
	val, err := c.Get(ctx, "perm")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "forever" {
		t.Errorf("value = %q, want %q", val, "forever")
	}
}

func TestSetIfNotExists_ThenGet(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	ok, err := c.SetIfNotExists(ctx, "readable", "hello", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists error: %v", err)
	}
	if !ok {
		t.Fatal("SetIfNotExists should return true")
	}

	val, err := c.Get(ctx, "readable")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "hello" {
		t.Errorf("Get returned %q, want %q", val, "hello")
	}
}

func TestSetIfNotExists_ThenGetAfterExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.SetIfNotExists(ctx, "brief", "temp", 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	_, err := c.Get(ctx, "brief")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Get after expiry should return ErrNotFound")
	}
}

func TestSetIfNotExists_Concurrent(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const goroutines = 50
	wins := make(chan int, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ok, err := c.SetIfNotExists(ctx, "race", fmt.Sprintf("goroutine-%d", id), time.Minute)
			if err != nil {
				t.Errorf("goroutine %d: SetIfNotExists error: %v", id, err)
				return
			}
			if ok {
				wins <- id
			}
		}(i)
	}
	wg.Wait()
	close(wins)

	// Exactly one goroutine should have won the race.
	count := 0
	for range wins {
		count++
	}
	if count != 1 {
		t.Errorf("expected exactly 1 winner, got %d", count)
	}

	// The key should exist with the winner's value.
	val, err := c.Get(ctx, "race")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val == "" {
		t.Error("value should not be empty")
	}
}

func TestSetIfNotExists_ConcurrentDifferentKeys(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", id)
			ok, err := c.SetIfNotExists(ctx, key, "val", time.Minute)
			if err != nil {
				t.Errorf("goroutine %d error: %v", id, err)
				return
			}
			if !ok {
				t.Errorf("goroutine %d: unique key should always succeed", id)
			}
		}(i)
	}
	wg.Wait()

	// All keys should exist.
	for i := 0; i < goroutines; i++ {
		key := fmt.Sprintf("key-%d", i)
		exists, _ := c.Exists(ctx, key)
		if !exists {
			t.Errorf("key %q should exist", key)
		}
	}
}

func TestClose_DoubleClose(t *testing.T) {
	c := NewMemoryCache()

	err := c.Close()
	if err != nil {
		t.Fatalf("first Close error: %v", err)
	}

	// Second close should not panic due to sync.Once.
	err = c.Close()
	if err != nil {
		t.Fatalf("second Close error: %v", err)
	}
}

func TestClose_TripleClose(t *testing.T) {
	c := NewMemoryCache()

	for i := 0; i < 3; i++ {
		err := c.Close()
		if err != nil {
			t.Fatalf("Close #%d error: %v", i+1, err)
		}
	}
}

func TestClose_ConcurrentClose(t *testing.T) {
	c := NewMemoryCache()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.Close()
			if err != nil {
				t.Errorf("concurrent Close error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestSetIfNotExists_AfterDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.SetIfNotExists(ctx, "delme", "first", time.Minute)
	c.Delete(ctx, "delme")

	ok, err := c.SetIfNotExists(ctx, "delme", "second", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists after Delete error: %v", err)
	}
	if !ok {
		t.Error("SetIfNotExists after Delete should return true")
	}

	val, _ := c.Get(ctx, "delme")
	if val != "second" {
		t.Errorf("value = %q, want %q", val, "second")
	}
}
