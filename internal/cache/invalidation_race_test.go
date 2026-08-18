package cache

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestRevocationDeleteIsVisibleToSubsequentGets is the stale-read window
// the lock is supposed to close: after Delete returns, a Get of the same
// key must miss. A Get that held the read lock across a Delete that did
// not take the write lock would keep serving a revoked value.
func TestRevocationDeleteIsVisibleToSubsequentGets(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const key = "refresh:family:revoked"
	if err := c.Set(ctx, key, "live-session", time.Minute); err != nil {
		t.Fatal(err)
	}

	const readers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	deleted := make(chan struct{})

	wg.Add(readers + 1)
	go func() {
		defer wg.Done()
		<-start
		if err := c.Delete(ctx, key); err != nil {
			t.Errorf("Delete: %v", err)
		}
		close(deleted)
	}()
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			<-start
			<-deleted
			_, err := c.Get(ctx, key)
			if err != ErrNotFound {
				t.Errorf("Get after Delete returned %v, want ErrNotFound; a revoked session is still readable", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}

// TestIncrementDoesNotRestoreADeletedCounter is the lockout/revocation
// interleaving: Delete (clearLockout) racing one Increment (a concurrent
// failure) from a known prior of 4.
//
// Under a correct exclusive RMW the only surviving states are "missing"
// (Increment then Delete) or "1" (Delete then Increment). A check-then-act
// Increment that sampled 4, lost the lock, and wrote 5 after the Delete
// would leave "5": a lockout counter that outlived the success that
// cleared it.
func TestIncrementDoesNotRestoreADeletedCounter(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const key = "lockout:user-1"
	const rounds = 200
	for round := 0; round < rounds; round++ {
		if err := c.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			if _, err := c.Increment(ctx, key, time.Minute); err != nil {
				t.Fatal(err)
			}
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = c.Delete(ctx, key)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.Increment(ctx, key, time.Minute)
		}()
		close(start)
		wg.Wait()

		got, err := c.Get(ctx, key)
		if err == ErrNotFound {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got != "1" {
			t.Fatalf("round %d: counter = %q after Delete∥Increment from 4; want missing or \"1\" (a restored pre-delete sample would be \"5\")", round, got)
		}
	}
}

// TestSetAfterDeleteIsANewWrite, not a resurrection of the revoked value.
func TestSetAfterDeleteIsANewWrite(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	const key = "session:1"
	_ = c.Set(ctx, key, "old", time.Minute)
	_ = c.Delete(ctx, key)
	_ = c.Set(ctx, key, "new", time.Minute)
	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != "new" {
		t.Fatalf("Get = %q, want the write that followed the revocation, not %q", got, "old")
	}
}
