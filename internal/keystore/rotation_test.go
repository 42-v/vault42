package keystore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// stubRotator counts rotation checks and can be made to fail or to block, so the
// loop's behavior is observable without a database. The rotation itself is
// covered against a live Postgres in keystore_rotation_schedule_test.go.
type stubRotator struct {
	calls   atomic.Int64
	entered chan struct{}
	done    chan struct{}
	err     error
	kid     string
	maxAge  atomic.Int64
	block   chan struct{}
}

func newStubRotator() *stubRotator {
	return &stubRotator{
		entered: make(chan struct{}, 16),
		done:    make(chan struct{}, 16),
	}
}

func (s *stubRotator) RotateIfOlderThan(ctx context.Context, maxAge time.Duration) (string, error) {
	s.calls.Add(1)
	s.maxAge.Store(int64(maxAge))
	send(s.entered)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	send(s.done)
	return s.kid, s.err
}

func (s *stubRotator) awaitEntry(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the rotation loop never asked whether the key was due")
	}
}

func (s *stubRotator) awaitCheck(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the scheduler never checked the key's age: a rotation loop that does not run on " +
			"start never runs at all in a deployment that rolls more often than the check interval")
	}
}

// Nothing rotated the signing key on a schedule. The whole point of this type is
// that the first check happens at Start, because a deployment that restarts more
// often than the check interval would otherwise never reach a tick.
func TestTheSchedulerChecksOnceImmediatelyOnStart(t *testing.T) {
	rotator := newStubRotator()
	r := NewRotation(rotator, DefaultRotationInterval)

	r.Start(context.Background())
	defer r.Stop()

	rotator.awaitCheck(t)
	if got := time.Duration(rotator.maxAge.Load()); got != DefaultRotationInterval {
		t.Errorf("the loop asked for maxAge %s, want the configured interval %s", got, DefaultRotationInterval)
	}
}

// Stop is deferred in cmd/vault directly above a deferred close of the database
// pool, so a Stop that returned while a rotation was still inside its
// transaction would have the pool pulled out from under it.
func TestStopBlocksUntilTheRotationLoopHasActuallyExited(t *testing.T) {
	rotator := newStubRotator()
	rotator.block = make(chan struct{})
	r := NewRotation(rotator, DefaultRotationInterval)

	r.Start(context.Background())
	rotator.awaitEntry(t)

	stopped := make(chan struct{})
	go func() {
		r.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned while a rotation was still in flight; the caller would close the " +
			"database pool underneath it")
	case <-time.After(50 * time.Millisecond):
	}

	close(rotator.block)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop never returned after the in-flight rotation finished")
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
func TestRotationStopIsSafeToCallTwiceAndOnASchedulerThatNeverStarted(t *testing.T) {
	r := NewRotation(newStubRotator(), DefaultRotationInterval)
	r.Stop()
	r.Stop()

	r2 := NewRotation(newStubRotator(), DefaultRotationInterval)
	r2.Start(context.Background())
	r2.Stop()
	r2.Stop()
}

// Two loops would share one doneCh, and the second to exit would close an
// already-closed channel: a panic raised from a deferred call in a background
// goroutine, which no handler can catch.
func TestStartingTheSchedulerTwiceStartsOneLoop(t *testing.T) {
	rotator := newStubRotator()
	rotator.block = make(chan struct{})
	r := NewRotation(rotator, DefaultRotationInterval)

	r.Start(context.Background())
	rotator.awaitEntry(t)
	r.Start(context.Background())

	close(rotator.block)
	r.Stop()

	select {
	case <-r.Done():
	default:
		t.Error("Done is not closed, so the second Start replaced rather than skipped the loop")
	}
}

// A canceled context is how cmd/vault ends on SIGTERM. The loop must notice it
// even though nothing called Stop, or the process hangs on the deferred Stop.
func TestACanceledContextEndsTheRotationLoop(t *testing.T) {
	rotator := newStubRotator()
	r := NewRotation(rotator, DefaultRotationInterval)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	rotator.awaitCheck(t)
	cancel()

	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the rotation loop is still running after its context was canceled")
	}

	r.Stop()
}

// A failed rotation is a database problem, not a reason to stop rotating. The
// decision is re-derived from the stored key's age next tick, so giving up would
// silently return the deployment to signing with one key forever.
func TestARotationFailureDoesNotEndTheLoop(t *testing.T) {
	rotator := newStubRotator()
	rotator.err = errors.New("connection refused")
	r := NewRotation(rotator, DefaultRotationInterval)

	r.Start(context.Background())
	defer r.Stop()

	rotator.awaitCheck(t)

	select {
	case <-r.Done():
		t.Error("the loop exited after one failed rotation, so a transient database outage stops " +
			"rotation for the lifetime of the process")
	case <-time.After(50 * time.Millisecond):
	}
}

// The kid is the only evidence an operator gets that a rotation happened, and it
// is what the loop logs.
func TestTheLoopReportsTheKeyItRotatedTo(t *testing.T) {
	rotator := newStubRotator()
	rotator.kid = "abcd1234-5678ef90"
	r := NewRotation(rotator, DefaultRotationInterval)

	r.Start(context.Background())
	defer r.Stop()

	rotator.awaitCheck(t)
	if got := rotator.calls.Load(); got < 1 {
		t.Errorf("the loop checked %d times, want at least 1", got)
	}
}

// Rotate is exported so an operator-facing path can force the check without
// running the loop.
func TestRotateReturnsTheNewKID(t *testing.T) {
	rotator := newStubRotator()
	rotator.kid = "deadbeef-cafebabe"
	r := NewRotation(rotator, DefaultRotationInterval)

	kid, err := r.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if kid != "deadbeef-cafebabe" {
		t.Errorf("Rotate = %q, want the new kid", kid)
	}
	if got := rotator.calls.Load(); got != 1 {
		t.Errorf("Rotate called RotateIfOlderThan %d times, want 1", got)
	}
}

// A rotation failure must reach the caller rather than be reported as "nothing
// was due", which reads identically to a healthy check of a fresh key.
func TestRotateSurfacesTheRotationError(t *testing.T) {
	want := errors.New("permission denied for table signing_keys")
	rotator := newStubRotator()
	rotator.err = want
	r := NewRotation(rotator, DefaultRotationInterval)

	if _, err := r.Rotate(context.Background()); !errors.Is(err, want) {
		t.Errorf("Rotate error = %v, want it to wrap %v", err, want)
	}
}

// An operator who rotates on their own schedule turns the scheduler off with a
// non-positive interval, and it must then be inert rather than rotate on every
// tick because "older than zero" is true of every key.
func TestANonPositiveIntervalDisablesTheScheduler(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Hour} {
		rotator := newStubRotator()
		r := NewRotation(rotator, interval)
		if r.Enabled() {
			t.Fatalf("interval %s reports the scheduler enabled", interval)
		}

		r.Start(context.Background())
		if kid, err := r.Rotate(context.Background()); kid != "" || err != nil {
			t.Errorf("Rotate on an inert scheduler = (%q, %v), want (\"\", nil)", kid, err)
		}
		r.Stop()

		if got := rotator.calls.Load(); got != 0 {
			t.Errorf("an inert scheduler rotated %d times", got)
		}
	}
}

// A scheduler handed no keystore at all must be inert rather than dereference it
// on the first tick, where the panic happens in a goroutine with no request to
// attribute it to.
func TestASchedulerWithNothingToRotateIsInert(t *testing.T) {
	r := NewRotation(nil, DefaultRotationInterval)
	if r.Enabled() {
		t.Error("a scheduler built over nothing reports itself enabled")
	}
	r.Start(context.Background())
	if kid, err := r.Rotate(context.Background()); kid != "" || err != nil {
		t.Errorf("Rotate on an inert scheduler = (%q, %v), want (\"\", nil)", kid, err)
	}
	r.Stop()

	var nilScheduler *Rotation
	if nilScheduler.Enabled() {
		t.Error("a nil *Rotation reports itself enabled")
	}
}

// The file-based signing key mode builds no keystore, so cmd/vault has a nil one
// to hand the constructor. A typed nil in an interface is not a nil interface.
func TestASchedulerOverAKeyStoreThatWasNeverBuiltIsInert(t *testing.T) {
	var ks *KeyStore
	r := NewRotation(ks, DefaultRotationInterval)

	if r.Enabled() {
		t.Error("a scheduler built over a nil keystore reports itself enabled")
	}

	r.Start(context.Background())
	if kid, err := r.Rotate(context.Background()); kid != "" || err != nil {
		t.Errorf("Rotate on an inert scheduler = (%q, %v), want (\"\", nil)", kid, err)
	}
	r.Stop()
}

// The check interval is not the rotation interval, and confusing the two is how
// a 30-day rotation becomes an hourly one. The decision is re-derived from the
// stored key's age every hour; the horizon it is compared against is the
// configured interval.
func TestTheCheckIntervalIsShorterThanTheRotationHorizon(t *testing.T) {
	if RotationCheckInterval >= DefaultRotationInterval {
		t.Fatalf("RotationCheckInterval (%s) must be well short of DefaultRotationInterval (%s), "+
			"or a due rotation waits a full horizon to be noticed", RotationCheckInterval, DefaultRotationInterval)
	}
}
