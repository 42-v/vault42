package deferwork

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcherRunsJobsAndDrainsOnClose(t *testing.T) {
	d := New(2, 8)

	var ran atomic.Int64
	for i := 0; i < 5; i++ {
		d.Enqueue(func(context.Context) { ran.Add(1) })
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := ran.Load(); got != 5 {
		t.Fatalf("ran %d jobs, want 5 — the drain returned before the queue was empty", got)
	}
	if got := d.Dropped(); got != 0 {
		t.Fatalf("dropped %d jobs with an empty pool", got)
	}
}

// TestDispatcherDropsRatherThanBlocks is the bound itself. Blocking would put
// relay latency back on the request path, which is the timing leak the deferred
// send exists to avoid.
func TestDispatcherDropsRatherThanBlocks(t *testing.T) {
	release := make(chan struct{})
	d := New(1, 1)

	var started sync.WaitGroup
	started.Add(1)
	d.Enqueue(func(context.Context) {
		started.Done()
		<-release
	})
	started.Wait() // the single worker is now busy

	// One more fills the single queue slot; everything after it is dropped.
	d.Enqueue(func(context.Context) {})
	for i := 0; i < 20; i++ {
		d.Enqueue(func(context.Context) {})
	}

	if got := d.Dropped(); got == 0 {
		t.Fatal("a saturated pool queued everything it was handed; the bound is not holding")
	}
	if got := d.QueueDepth(); got > 1 {
		t.Fatalf("queue depth %d, over the configured 1", got)
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestCloseReportsAnExpiredDrain covers the deadline arm: a wedged relay must
// not hold the process open, and the caller has to learn that mail was
// abandoned rather than sent.
func TestCloseReportsAnExpiredDrain(t *testing.T) {
	blocked := make(chan struct{})
	d := New(1, 4)

	var jobCtx atomic.Value
	var started sync.WaitGroup
	started.Add(1)
	d.Enqueue(func(ctx context.Context) {
		jobCtx.Store(ctx)
		started.Done()
		<-blocked
	})
	started.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := d.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want the drain deadline to be reported", err)
	}

	// The job's context is canceled, so a send still running stops touching
	// state the caller is about to tear down.
	jc, _ := jobCtx.Load().(context.Context)
	if jc == nil {
		t.Fatal("the job never received a context")
	}
	select {
	case <-jc.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the job's context was not canceled after the drain expired")
	}
	close(blocked)
}

// TestEnqueueAfterCloseIsANoOp keeps a late send from panicking on a closed
// channel during shutdown.
func TestEnqueueAfterCloseIsANoOp(t *testing.T) {
	d := New(1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Both of these must be safe, and Close must be idempotent.
	d.Enqueue(func(context.Context) { t.Error("a job enqueued after Close ran") })
	if err := d.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
}

// TestNilAndZeroValuesAreSafe covers the defensive paths: a nil dispatcher and
// a nil job are both no-ops, and a non-positive pool size is clamped rather
// than deadlocking on a zero-capacity channel with no workers.
func TestNilAndZeroValuesAreSafe(t *testing.T) {
	var d *Dispatcher
	d.Enqueue(func(context.Context) { t.Error("a nil dispatcher ran a job") })
	if got := d.Dropped(); got != 0 {
		t.Errorf("nil Dropped = %d", got)
	}
	if got := d.QueueDepth(); got != 0 {
		t.Errorf("nil QueueDepth = %d", got)
	}
	if err := d.Close(context.Background()); err != nil {
		t.Errorf("nil Close = %v", err)
	}

	clamped := New(0, 0)
	var ran atomic.Bool
	clamped.Enqueue(nil)
	clamped.Enqueue(func(context.Context) { ran.Store(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clamped.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ran.Load() {
		t.Error("a dispatcher built with zero workers ran nothing")
	}
}

// TestPackageLevelPoolIsBounded pins the default every call site uses. A
// package-level pool exists precisely so the bound holds whether or not
// somebody remembered to wire one.
func TestPackageLevelPoolIsBounded(t *testing.T) {
	if DefaultWorkers < 1 || DefaultQueueDepth < 1 {
		t.Fatalf("default pool is %d workers / %d queue", DefaultWorkers, DefaultQueueDepth)
	}
	if cap(defaultDispatcher.queue) != DefaultQueueDepth {
		t.Fatalf("package pool queue capacity = %d, want %d", cap(defaultDispatcher.queue), DefaultQueueDepth)
	}

	done := make(chan struct{})
	Go(func(context.Context) { close(done) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the package-level pool did not run a job")
	}
	if got := QueueDepth(); got < 0 {
		t.Fatalf("QueueDepth = %d", got)
	}
	if got := Dropped(); got != 0 {
		t.Fatalf("the package pool dropped %d jobs during a single-job test", got)
	}
}
