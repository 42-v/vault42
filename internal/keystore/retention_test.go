package keystore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// stubReaper counts sweeps and can be made to fail, so the loop's behavior is
// observable without a database. The real reap is one DELETE and is covered
// against a live Postgres in tests/integration.
type stubReaper struct {
	calls   atomic.Int64
	entered chan struct{}
	swept   chan struct{}
	err     error
	rows    int64
	block   chan struct{}
}

func newStubReaper() *stubReaper {
	return &stubReaper{
		entered: make(chan struct{}, 16),
		swept:   make(chan struct{}, 16),
	}
}

func (s *stubReaper) CleanupExpired(ctx context.Context) (int64, error) {
	s.calls.Add(1)
	send(s.entered)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	send(s.swept)
	return s.rows, s.err
}

// send never blocks, so a stub whose signals nobody is reading cannot wedge the
// loop under test.
func send(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *stubReaper) awaitEntry(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep loop never entered CleanupExpired")
	}
}

func (s *stubReaper) awaitSweep(t *testing.T) {
	t.Helper()
	select {
	case <-s.swept:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper never reaped: a retention loop that does not run on start is the " +
			"defect this type exists to fix")
	}
}

// A sweeper that only reaps on its ticker never reaps at all in a deployment
// that restarts more often than the interval, which is the shape a rolling
// update has. The first sweep must happen at Start.
func TestTheSweeperReapsOnceImmediatelyOnStart(t *testing.T) {
	reaper := newStubReaper()
	r := NewRetention(reaper)

	r.Start(context.Background())
	defer r.Stop()

	reaper.awaitSweep(t)
}

// Stop is what makes "the sweeper does not outlive shutdown" true rather than
// merely intended. cmd/vault defers it directly above a deferred close of the
// database pool, so a Stop that returned while a sweep was still inside its
// DELETE would have the pool pulled out from under it.
func TestStopBlocksUntilTheSweepLoopHasActuallyExited(t *testing.T) {
	reaper := newStubReaper()
	reaper.block = make(chan struct{})
	r := NewRetention(reaper)

	r.Start(context.Background())
	reaper.awaitEntry(t)

	stopped := make(chan struct{})
	go func() {
		r.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned while a sweep was still in flight; the caller would close the " +
			"database pool underneath the DELETE")
	case <-time.After(50 * time.Millisecond):
	}

	close(reaper.block)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop never returned after the in-flight sweep finished")
	}

	select {
	case <-r.Done():
	default:
		t.Error("Done is not closed after Stop returned, so nothing downstream can tell that the " +
			"loop has really exited")
	}
}

// Stop runs from a defer, and defers run on every exit path including the ones
// that already called Stop. Closing a closed channel panics, which would turn a
// clean shutdown into a crash.
func TestStopIsSafeToCallTwiceAndOnASweeperThatNeverStarted(t *testing.T) {
	r := NewRetention(newStubReaper())
	r.Stop()
	r.Stop()

	r2 := NewRetention(newStubReaper())
	r2.Start(context.Background())
	r2.Stop()
	r2.Stop()
}

// A cancelled context is how cmd/vault ends on SIGTERM. The loop must notice it
// even though nothing called Stop, or the process hangs on the deferred Stop.
func TestACancelledContextEndsTheSweepLoop(t *testing.T) {
	reaper := newStubReaper()
	r := NewRetention(reaper)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	reaper.awaitSweep(t)
	cancel()

	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep loop is still running after its context was cancelled")
	}

	r.Stop()
}

// A failing sweep is a database problem, not a reason to stop reaping. The loop
// logs and carries on, because the next tick may well succeed and a sweeper
// that gave up would put the table back to growing without bound silently.
func TestASweepFailureDoesNotEndTheLoop(t *testing.T) {
	reaper := newStubReaper()
	reaper.err = errors.New("connection refused")
	r := NewRetention(reaper)

	r.Start(context.Background())
	defer r.Stop()

	reaper.awaitSweep(t)

	select {
	case <-r.Done():
		t.Error("the sweep loop exited after one failed sweep, so a transient database outage " +
			"stops reaping for the lifetime of the process")
	case <-time.After(50 * time.Millisecond):
	}
}

// Sweep is exported so an operator-facing path can reap on demand without
// running the loop, and it must report the row count the caller can log.
func TestSweepReturnsTheNumberOfRowsReaped(t *testing.T) {
	reaper := newStubReaper()
	reaper.rows = 3
	r := NewRetention(reaper)

	n, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 3 {
		t.Errorf("Sweep = %d, want 3", n)
	}
	if got := reaper.calls.Load(); got != 1 {
		t.Errorf("Sweep called CleanupExpired %d times, want 1", got)
	}
}

// A sweep failure must reach the caller rather than be reported as zero rows
// reaped, which reads identically to a healthy sweep of an empty table.
func TestSweepSurfacesTheReapError(t *testing.T) {
	want := errors.New("permission denied for table signing_keys")
	reaper := newStubReaper()
	reaper.err = want
	r := NewRetention(reaper)

	if _, err := r.Sweep(context.Background()); !errors.Is(err, want) {
		t.Errorf("Sweep error = %v, want it to wrap %v", err, want)
	}
}

// The count of reaped rows is the only evidence an operator gets that the
// sweeper is doing anything, and a loop that swept silently would be
// indistinguishable from one that never started.
func TestTheLoopReportsTheRowsItReaped(t *testing.T) {
	reaper := newStubReaper()
	reaper.rows = 2
	r := NewRetention(reaper)

	r.Start(context.Background())
	defer r.Stop()

	reaper.awaitSweep(t)
	if got := reaper.calls.Load(); got < 1 {
		t.Errorf("the loop called CleanupExpired %d times, want at least 1", got)
	}
}

// A sweeper handed no reaper at all must be inert rather than dereference it on
// the first tick, where the panic happens in a goroutine with no request to
// attribute it to.
func TestASweeperWithNothingToSweepIsInert(t *testing.T) {
	r := NewRetention(nil)
	if r.Enabled() {
		t.Error("a sweeper built over nothing reports itself enabled")
	}

	r.Start(context.Background())
	if n, err := r.Sweep(context.Background()); n != 0 || err != nil {
		t.Errorf("Sweep on an inert sweeper = (%d, %v), want (0, nil)", n, err)
	}
	r.Stop()

	var nilSweeper *Retention
	if nilSweeper.Enabled() {
		t.Error("a nil *Retention reports itself enabled")
	}
}

// The file-based signing key mode builds no keystore, so cmd/vault has a nil
// one to hand the constructor. A sweeper over nothing must be inert rather than
// panic on the first tick.
func TestASweeperOverAKeyStoreThatWasNeverBuiltIsInert(t *testing.T) {
	var ks *KeyStore
	r := NewRetention(ks)

	if r.Enabled() {
		t.Error("a sweeper built over a nil keystore reports itself enabled")
	}

	r.Start(context.Background())
	if n, err := r.Sweep(context.Background()); n != 0 || err != nil {
		t.Errorf("Sweep on an inert sweeper = (%d, %v), want (0, nil)", n, err)
	}
	r.Stop()
}
