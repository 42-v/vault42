package audit

import (
	"context"
	"errors"
	"testing"
	"time"

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
	batches := []int64{2000, 2000, 137, 0}
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
	if got != 4137 {
		t.Fatalf("Sweep purged %d rows, want 4137 across the batches", got)
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
		return 2000, true, nil // never runs dry
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if calls != SweepMaxBatches {
		t.Fatalf("made %d calls, want the %d ceiling", calls, SweepMaxBatches)
	}
	if want := int64(SweepMaxBatches) * 2000; got != want {
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
			return 2000, true, nil
		}
		return 0, false, nil // another replica took the lock
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got != 2000 {
		t.Fatalf("Sweep reported %d rows, want the 2000 that did go", got)
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
			return 2000, true, nil
		}
		return 0, true, wantErr
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Sweep err = %v, want %v", err, wantErr)
	}
	if got != 2000 {
		t.Fatalf("Sweep reported %d rows, want the 2000 that went before the failure", got)
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
		return 2000, true, nil
	}

	r := NewRetention(repo, 30*24*time.Hour)
	got, err := r.Sweep(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep err = %v, want context.Canceled", err)
	}
	if got != 2000 {
		t.Fatalf("Sweep reported %d rows, want 2000", got)
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
		return 2000, true, nil
	}

	got, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got != 2000 || calls != 1 {
		t.Fatalf("Sweep = (%d rows, %d calls), want (2000, 1) — Stop has to end the batch loop", got, calls)
	}
}
