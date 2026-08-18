package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// audit.cleanup_old_entries has to disable the append-only trigger to delete
// anything, which is ALTER TABLE and therefore ACCESS EXCLUSIVE on
// audit.audit_log. Run over one unbounded DELETE it held that lock for the
// length of the whole purge — and a failed login is a critical event, written
// synchronously on the request path even when the buffer is full, so every one
// of those inserts waited behind it.

func TestSweepLoopsUntilTheHorizonIsClear(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	// A full batch means there is more; a short one means the horizon is clear.
	batches := []int64{repository.AuditCleanupBatch, repository.AuditCleanupBatch, 137}
	call := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		n := batches[call]
		call++
		return n, true, nil
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if want := int64(2*repository.AuditCleanupBatch + 137); got != want {
		t.Fatalf("Sweep purged %d rows, want %d across the batches", got, want)
	}
	if call != len(batches) {
		t.Fatalf("made %d calls, want %d — the loop has to keep going while rows are still "+
			"coming back", call, len(batches))
	}
}

// TestSweepStopsAtTheBatchCeiling keeps a tick bounded. A sweep that runs until
// the table is empty is a tick with no end, and the remainder is not urgent:
// the next tick picks it up.
func TestSweepStopsAtTheBatchCeiling(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	calls := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		calls++
		return repository.AuditCleanupBatch, true, nil // never runs dry
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if calls != SweepMaxBatches {
		t.Fatalf("made %d calls, want the %d ceiling", calls, SweepMaxBatches)
	}
	if want := int64(SweepMaxBatches) * repository.AuditCleanupBatch; got != want {
		t.Fatalf("Sweep purged %d rows, want %d", got, want)
	}
}

// TestSweepYieldsToAnotherReplica keeps the advisory lock meaningful: a replica
// that does not hold it stops rather than spinning on the lock, because the
// work is idempotent and there is nothing to catch up on.
func TestSweepYieldsToAnotherReplica(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	calls := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		calls++
		if calls == 1 {
			return repository.AuditCleanupBatch, true, nil
		}
		return 0, false, nil // another replica took the lock
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got != repository.AuditCleanupBatch {
		t.Fatalf("Sweep reported %d rows, want the %d that did go", got, repository.AuditCleanupBatch)
	}
	if calls != 2 {
		t.Fatalf("made %d calls, want 2 — a lost lock ends the sweep", calls)
	}
}

func TestSweepReportsAnErrorMidLoop(t *testing.T) {
	wantErr := errors.New("statement timeout")
	repo := &mocks.MockAuditRepo{}
	calls := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		calls++
		if calls == 1 {
			return repository.AuditCleanupBatch, true, nil
		}
		return 0, true, wantErr
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Sweep err = %v, want %v", err, wantErr)
	}
	if got != repository.AuditCleanupBatch {
		t.Fatalf("Sweep reported %d rows, want the %d that went before the failure", got, repository.AuditCleanupBatch)
	}
}

// TestSweepHonoursCancellationBetweenBatches is why the batches are separated by
// a check rather than run back to back: a shutdown arriving mid-purge should not
// have to wait for twenty more exclusive locks.
func TestSweepHonoursCancellationBetweenBatches(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		calls++
		cancel()
		return repository.AuditCleanupBatch, true, nil
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep err = %v, want context.Canceled", err)
	}
	if got != repository.AuditCleanupBatch {
		t.Fatalf("Sweep reported %d rows, want %d", got, repository.AuditCleanupBatch)
	}
	if calls != 1 {
		t.Fatalf("made %d calls after cancellation, want 1", calls)
	}
}

// TestSweepStopsOnStop covers the other between-batch exit.
func TestSweepStopsOnStop(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	r := NewRetention(repo, 30*24*time.Hour)
	calls := 0
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		calls++
		r.Stop()
		return repository.AuditCleanupBatch, true, nil
	}

	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got != repository.AuditCleanupBatch || calls != 1 {
		t.Fatalf("Sweep = (%d rows, %d calls), want (%d, 1) — Stop has to end the batch loop", got, calls, repository.AuditCleanupBatch)
	}
}
