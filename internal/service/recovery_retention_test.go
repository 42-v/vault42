package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// stubPruner records what the sweeper asked the escrow store to do. It is local
// rather than in tests/mocks because the pruner is a deliberately narrow
// interface: nothing else in the tree holds one.
type stubPruner struct {
	mu       sync.Mutex
	cutoff   time.Time
	calls    int
	swept    chan struct{}
	deleted  int64
	acquired bool
	err      error
}

func newStubPruner(deleted int64, acquired bool, err error) *stubPruner {
	return &stubPruner{swept: make(chan struct{}, 1), deleted: deleted, acquired: acquired, err: err}
}

func (s *stubPruner) Prune(_ context.Context, olderThan time.Time) (int64, error) {
	return s.record(olderThan)
}

func (s *stubPruner) PruneLocked(_ context.Context, olderThan time.Time) (int64, bool, error) {
	deleted, err := s.record(olderThan)
	return deleted, s.acquired, err
}

func (s *stubPruner) record(olderThan time.Time) (int64, error) {
	s.mu.Lock()
	s.calls++
	s.cutoff = olderThan
	s.mu.Unlock()
	select {
	case s.swept <- struct{}{}:
	default:
	}
	return s.deleted, s.err
}

func (s *stubPruner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubPruner) horizon() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cutoff
}

// Disabled is the default, and it must be a hard no-op. The escrow holds the only
// recoverable copy of an erased account, so a deployment that never set a horizon
// must not have one inferred for it and start destroying records on upgrade.
func TestRecoveryRetention_DisabledNeverPurges(t *testing.T) {
	pruner := newStubPruner(4, true, nil)

	r := NewRecoveryRetention(pruner, 0)
	if r.Enabled() {
		t.Fatal("zero period must be disabled")
	}
	if _, err := r.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if pruner.count() != 0 {
		t.Error("disabled retention must not touch the escrow store")
	}
}

// A configured horizon with no pruner behind it must stay disabled rather than
// panic on the first tick.
func TestRecoveryRetention_NoPrunerIsDisabled(t *testing.T) {
	r := NewRecoveryRetention(nil, 30*24*time.Hour)
	if r.Enabled() {
		t.Fatal("a sweeper with nothing to sweep must report disabled")
	}
	if _, err := r.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
}

// The cutoff is what bounds how long the escrowed email lives. An off-by-one here
// either keeps it past its retention period or destroys the recoverable record early.
func TestRecoveryRetention_PurgesOlderThanHorizon(t *testing.T) {
	pruner := newStubPruner(7, true, nil)

	const horizon = 90 * 24 * time.Hour
	before := time.Now().Add(-horizon)

	deleted, err := NewRecoveryRetention(pruner, horizon).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 7 {
		t.Errorf("deleted = %d, want 7", deleted)
	}
	cutoff := pruner.horizon()
	if cutoff.Before(before.Add(-time.Minute)) || cutoff.After(time.Now().Add(-horizon).Add(time.Minute)) {
		t.Errorf("cutoff %v is not ~now-%s", cutoff, horizon)
	}
}

// The prune takes an ACCESS EXCLUSIVE lock on the escrow table, so one replica
// sweeps at a time. A replica that lost the lock did no work and must not report
// the winner's row count as its own.
func TestRecoveryRetention_LockContentionReportsNothingPurged(t *testing.T) {
	deleted, err := NewRecoveryRetention(newStubPruner(999, false, nil), 30*24*time.Hour).Sweep(context.Background())
	if err != nil {
		t.Fatalf("losing the lock is not an error, the work is idempotent and retries next tick: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0, this replica swept nothing", deleted)
	}
}

// A sweep failure surfaces to the caller rather than being reported as a purge of
// zero rows, which an operator would read as "the horizon is enforced".
func TestRecoveryRetention_SweepErrorSurfaces(t *testing.T) {
	if _, err := NewRecoveryRetention(newStubPruner(0, true, errors.New("db down")), time.Hour).Sweep(context.Background()); err == nil {
		t.Error("expected the sweep error to surface to the caller")
	}
}

// Start must sweep immediately rather than waiting for the first tick. The tick
// interval is hours; a pod that restarts more often than that would otherwise
// never reach a tick and the purge would silently never run.
func TestRecoveryRetention_StartSweepsImmediately(t *testing.T) {
	pruner := newStubPruner(3, true, nil)
	r := NewRecoveryRetention(pruner, 30*24*time.Hour)
	r.Start(context.Background())
	defer r.Stop()

	select {
	case <-pruner.swept:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not sweep before the first tick")
	}
}

// A failed sweep must not kill the loop. If it did, the retention horizon would
// stop being enforced for the rest of the process lifetime and nothing would say
// so. Stop must still wait for the loop to exit.
func TestRecoveryRetention_SweepErrorDoesNotKillTheSweeper(t *testing.T) {
	pruner := newStubPruner(0, false, errors.New("db down"))
	r := NewRecoveryRetention(pruner, 30*24*time.Hour)
	r.Start(context.Background())

	select {
	case <-pruner.swept:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper never ran")
	}

	select {
	case <-r.Done():
		t.Fatal("the sweep loop exited on a failed sweep; the horizon would never be enforced again")
	case <-time.After(50 * time.Millisecond):
	}

	r.Stop()
	select {
	case <-r.Done():
	default:
		t.Error("Stop returned while the sweep loop was still running")
	}
}

// A canceled context must end the loop, otherwise the sweeper outlives shutdown
// and keeps issuing deletes against a closing pool.
//
// This deliberately does not call Stop: the loop parks in a select over stopCh,
// ctx.Done and the ticker, and Go picks at random among ready cases, so signaling
// both would make which return statement the coverage profile records a coin flip.
func TestRecoveryRetention_StopsOnContextCancel(t *testing.T) {
	pruner := newStubPruner(0, true, nil)
	ctx, cancel := context.WithCancel(context.Background())
	r := NewRecoveryRetention(pruner, time.Hour)
	r.Start(ctx)

	select {
	case <-pruner.swept:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper never started")
	}

	cancel()

	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper did not exit when its context was canceled, it would outlive shutdown")
	}
}

// Start has to be idempotent the way Stop is. Two calls used to launch two sweep
// loops over one pair of channels, and the second goroutine's deferred
// close(doneCh) closed an already-closed channel: an unrecoverable panic that
// takes the whole auth server down, some hours after start-up, from a defer in a
// background goroutine that no handler can recover.
//
// It is reachable from ordinary wiring - a second Start in a restart path, or a
// caller that starts the sweeper on config reload - and the two loops would also
// double the rate at which an ACCESS EXCLUSIVE lock is taken on the escrow table.
func TestRecoveryRetention_StartTwiceRunsOneSweeperAndDoesNotPanic(t *testing.T) {
	pruner := newStubPruner(0, true, nil)
	r := NewRecoveryRetention(pruner, 30*24*time.Hour)

	r.Start(context.Background())
	select {
	case <-pruner.swept:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper never ran")
	}

	r.Start(context.Background())

	// A second loop sweeps immediately on start, so its arrival is observable.
	select {
	case <-pruner.swept:
		t.Fatal("a second Start launched a second sweep loop; its deferred close of the done channel panics the process")
	case <-time.After(200 * time.Millisecond):
	}

	r.Stop()
	select {
	case <-r.Done():
	default:
		t.Error("Stop returned while a sweep loop was still running")
	}
}

// Disabled retention must be inert, not panic, when Start and Stop are called, and
// Stop must be safe more than once.
func TestRecoveryRetention_DisabledLifecycleIsSafe(t *testing.T) {
	r := NewRecoveryRetention(newStubPruner(0, true, nil), 0)
	r.Start(context.Background())
	r.Stop()
	r.Stop()
	select {
	case <-r.Done():
		t.Error("a sweeper that never started must not report itself done")
	default:
	}
}
