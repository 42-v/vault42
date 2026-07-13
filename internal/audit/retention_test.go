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
func TestRetention_StopsOnContextCancel(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	repo.CleanupFn = func(context.Context, time.Time) (int64, error) { return 0, nil }

	ctx, cancel := context.WithCancel(context.Background())
	r := NewRetention(repo, time.Hour)
	r.Start(ctx)
	cancel()

	// Stop must remain safe to call after the context already ended the loop.
	r.Stop()
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
