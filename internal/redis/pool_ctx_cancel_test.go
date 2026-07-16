package redis

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Deterministic coverage for the ctx.Done branch in pool.get. CI runs flaked
// 0..1 statement on this line because it depends on goroutine scheduling
// during parallel tests; this test pins it by saturating the semaphore and
// pre-cancelling the context.
func TestPoolGet_CtxCancelled(t *testing.T) {
	p := newPool(&Options{PoolSize: 1})
	defer close(p.done)

	// Drain the only semaphore slot so the next get() must wait on the select.
	<-p.sem

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := p.get(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("p.get did not return on ctx.Done")
	}
}

// Same select, third case: a caller blocked on a saturated pool must be
// released with a closed-client error when the pool shuts down, not left
// waiting forever. The atomic closed check at the top of get cannot catch
// this because the getter is already inside the select when close fires.
func TestPoolGet_ClosedWhileWaiting(t *testing.T) {
	p := newPool(&Options{PoolSize: 1})

	// Drain the only semaphore slot so get() must wait on the select. With a
	// background context the done case is the only way out.
	<-p.sem

	done := make(chan error, 1)
	go func() {
		_, err := p.get(context.Background())
		done <- err
	}()

	close(p.done)

	select {
	case err := <-done:
		if err == nil || err.Error() != "redis: client is closed" {
			t.Fatalf("expected closed-client error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("p.get did not return when the pool was closed")
	}
}
