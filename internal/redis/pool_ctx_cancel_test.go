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
