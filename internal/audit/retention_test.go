package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// Disabled is the default, and it must be a hard no-op: a deployment that never
// set a horizon must not have one inferred for it and start deleting security
// logs on upgrade.
func TestRetention_DisabledNeverPurges(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	var called bool
	repo.CleanupFn = func(context.Context, time.Time) (int64, error) {
		called = true
		return 0, nil
	}

	r := NewRetention(repo, 0)
	if r.Enabled() {
		t.Fatal("zero period must be disabled")
	}
	if _, err := r.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if called {
		t.Error("disabled retention must not touch the audit store")
	}
}

// The cutoff is what bounds how long personal data in the audit trail lives, so
// it has to be "now minus the horizon" — an off-by-one here either keeps data
// past its retention period or deletes it early.
func TestRetention_PurgesOlderThanHorizon(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	var cutoff time.Time
	repo.CleanupFn = func(_ context.Context, olderThan time.Time) (int64, error) {
		cutoff = olderThan
		return 7, nil
	}

	const horizon = 90 * 24 * time.Hour
	r := NewRetention(repo, horizon)
	before := time.Now().Add(-horizon)

	deleted, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 7 {
		t.Errorf("deleted = %d, want 7", deleted)
	}
	if cutoff.Before(before.Add(-time.Minute)) || cutoff.After(time.Now().Add(-horizon).Add(time.Minute)) {
		t.Errorf("cutoff %v is not ~now-%s", cutoff, horizon)
	}
}

// Start must sweep immediately rather than waiting for the first tick. The tick
// interval is hours; a pod that restarts more often than that would otherwise
// never reach a tick, and the purge would silently never run.
func TestRetention_StartSweepsImmediately(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	swept := make(chan struct{}, 1)
	repo.CleanupFn = func(context.Context, time.Time) (int64, error) {
		select {
		case swept <- struct{}{}:
		default:
		}
		return 3, nil
	}

	r := NewRetention(repo, 30*24*time.Hour)
	r.Start(context.Background())
	defer r.Stop()

	select {
	case <-swept:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not sweep before the first tick")
	}
}

// A cancelled context must end the loop — otherwise the sweeper outlives
// shutdown and keeps issuing deletes against a closing pool.
//
// This deliberately does NOT call Stop. The loop parks in a select over stopCh,
// ctx.Done and the ticker; Go chooses at random among the cases that are ready, so
// cancelling the context *and* closing stopCh would leave the exit path a coin
// flip — and with it, which of the two return statements the coverage profile
// records. That is not a cosmetic problem: it made the suite's own coverage total
// vary by a statement between identical runs, so the number CI published could
// disagree with the number in the docs. Cancelling alone leaves exactly one ready
// case, which is what makes this test assert the thing it claims to.
func TestRetention_StopsOnContextCancel(t *testing.T) {
	swept := make(chan struct{}, 1)
	repo := &mocks.MockAuditRepo{
		CleanupFn: func(context.Context, time.Time) (int64, error) {
			select {
			case swept <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := NewRetention(repo, time.Hour)
	r.Start(ctx)

	// Wait for the immediate sweep, so the loop is known to have reached the select
	// before the context is cancelled under it.
	select {
	case <-swept:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper never started")
	}

	cancel()

	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper did not exit when its context was cancelled — it would outlive shutdown")
	}
}

// A sweep failure must not kill the loop: a transient DB error should be logged
// and retried on the next tick, not silently disable retention until restart.
func TestRetention_SweepErrorSurfaces(t *testing.T) {
	repo := &mocks.MockAuditRepo{
		CleanupFn: func(context.Context, time.Time) (int64, error) {
			return 0, errors.New("db down")
		},
	}
	r := NewRetention(repo, time.Hour)

	if _, err := r.Sweep(context.Background()); err == nil {
		t.Error("expected the sweep error to surface to the caller")
	}
}

// Disabled retention must be inert, not panic, when Start/Stop are called.
func TestRetention_DisabledLifecycleIsSafe(t *testing.T) {
	r := NewRetention(&mocks.MockAuditRepo{}, 0)
	r.Start(context.Background())
	r.Stop()
}

// The cleanup takes an ACCESS EXCLUSIVE lock on the audit table — it disables the
// append-only trigger to delete — so only one replica may sweep at a time. A
// replica that does not win the advisory lock has done no work, and must say so:
// reporting the winner's row count as its own would have every replica log the
// same purge, and an operator counting deletions across the fleet would see the
// horizon apply several times over when it applied exactly once.
//
// The repo here returns rows *and* acquired=false, which is the shape that catches
// a refactor returning `deleted` unconditionally.
func TestRetention_ReplicaThatLosesTheLockReportsNoWork(t *testing.T) {
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			return 99, false, nil
		},
	}
	r := NewRetention(repo, 30*24*time.Hour)

	deleted, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("losing the lock is not an error — the work is idempotent and retries next tick: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 — this replica swept nothing and must not claim another's rows", deleted)
	}
}
