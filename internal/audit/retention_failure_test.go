package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// The sweeper is the only thing bounding how long audit PII lives (Art. 5(1)(e)),
// and it runs on a six-hour tick against a database that will occasionally be
// unavailable. A failed sweep must be survivable: if the loop returned on error
// the retention horizon would stop being enforced for the rest of the process
// lifetime, and nothing would say so. The next restart would be the only thing
// that ever resumed purging.
func TestRetention_SweepErrorDoesNotKillTheSweeper(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	swept := make(chan struct{}, 1)
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		select {
		case swept <- struct{}{}:
		default:
		}
		return 0, false, errors.New("db down")
	}

	r := NewRetention(repo, 30*24*time.Hour)
	r.Start(context.Background())

	select {
	case <-swept:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper never ran")
	}

	select {
	case <-r.Done():
		t.Fatal("the sweep loop exited on a failed sweep; the retention horizon would never be enforced again")
	case <-time.After(50 * time.Millisecond):
	}

	r.Stop()
	select {
	case <-r.Done():
	default:
		t.Error("Stop returned while the sweep loop was still running")
	}
}

// A sweep that lost the advisory lock is not a purge. Reporting rows deleted
// there would let an operator read the log as evidence that the horizon was
// enforced on this replica when another replica held the lock and this one did
// nothing.
func TestRetention_LockContentionReportsNothingPurged(t *testing.T) {
	repo := &mocks.MockAuditRepo{}
	repo.CleanupLockedFn = func(context.Context, time.Time) (int64, bool, error) {
		return 999, false, nil
	}

	deleted, err := NewRetention(repo, 30*24*time.Hour).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0, a replica that never held the lock purged nothing", deleted)
	}
}
