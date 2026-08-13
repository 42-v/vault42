package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// flakyAuditRepo fails InsertBatch until it is told to stop, so a test can watch
// what happens to entries a failed flush was holding.
type flakyAuditRepo struct {
	mu       sync.Mutex
	failing  bool
	inserted []*model.AuditEntry
	attempts int
}

func (f *flakyAuditRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.failing {
		return errors.New("audit store unavailable")
	}
	f.inserted = append(f.inserted, entries...)
	return nil
}

func (f *flakyAuditRepo) Insert(ctx context.Context, e *model.AuditEntry) error {
	return f.InsertBatch(ctx, []*model.AuditEntry{e})
}

func (f *flakyAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (f *flakyAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (f *flakyAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (f *flakyAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

func (f *flakyAuditRepo) stopFailing() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = false
}

func (f *flakyAuditRepo) insertedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inserted)
}

// TestFlushKeepsEntriesWhenTheStoreRejectsThem is the regression for a silent
// hole in an append-only trail.
//
// Flush emptied the buffer under the lock and then called InsertBatch outside
// it. On any repository error the entries were already gone from the buffer and
// nothing put them back, so a transient database blip destroyed a whole batch of
// audit records. batchLoop discarded the error with `_ = l.Flush(...)`, under a
// comment claiming errors were logged inside Flush, which they were not. So the
// loss was silent at both levels and DroppedTotal did not move either.
//
// This matters more than an ordinary retry, because the audit log is the only
// copy. A dropped login failure or password change is not recoverable from
// anywhere else, and the events most likely to be in flight during a database
// problem are the ones describing what was happening at the time.
func TestFlushKeepsEntriesWhenTheStoreRejectsThem(t *testing.T) {
	repo := &flakyAuditRepo{failing: true}
	l := NewLoggerWithBufferSize(repo, time.Hour, 100)

	const events = 5
	for i := 0; i < events; i++ {
		if err := l.Log(context.Background(), LoginSuccess, "user-1", "", "10.0.0.1", "ua", "", "", nil, 10); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	if err := l.Flush(context.Background()); err == nil {
		t.Fatal("Flush reported success while the store was rejecting every batch")
	}
	if repo.insertedCount() != 0 {
		t.Fatalf("the failing store recorded %d entries", repo.insertedCount())
	}

	// The entries must still be held. This is the assertion the defect fails:
	// before the fix the buffer was already nil and the events were gone.
	repo.stopFailing()
	if err := l.Flush(context.Background()); err != nil {
		t.Fatalf("second Flush: %v", err)
	}

	if got := repo.insertedCount(); got != events {
		t.Errorf("after the store recovered, %d of %d events reached it. A failed flush "+
			"discarded the batch it was holding, and the audit log is the only copy of those "+
			"records.", got, events)
	}
	if dropped := l.DroppedTotal(); dropped != 0 {
		t.Errorf("DroppedTotal = %d, want 0: nothing was actually lost, so nothing should be "+
			"counted as lost", dropped)
	}
}

// TestFlushCountsWhatItCannotKeep is the other half.
//
// Holding entries back cannot be unconditional, or a store that stays down turns
// the buffer into an unbounded leak in a process that is already unhealthy. What
// does not fit is counted, so the figure an operator alerts on stays honest
// rather than the loss being silent in a different way.
func TestFlushCountsWhatItCannotKeep(t *testing.T) {
	const capacity = 4
	repo := &flakyAuditRepo{failing: true}
	l := NewLoggerWithBufferSize(repo, time.Hour, capacity)

	for i := 0; i < capacity; i++ {
		if err := l.Log(context.Background(), LoginSuccess, "user-1", "", "10.0.0.1", "ua", "", "", nil, 10); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Flush(context.Background()); err == nil {
		t.Fatal("Flush reported success while the store was failing")
	}

	// Fill it again on top of what was put back, so the next failure has more
	// than the buffer can hold.
	for i := 0; i < capacity; i++ {
		_ = l.Log(context.Background(), LoginSuccess, "user-2", "", "10.0.0.2", "ua", "", "", nil, 10) // #nosec G104 -- overflow is the condition under test
	}
	if err := l.Flush(context.Background()); err == nil {
		t.Fatal("Flush reported success while the store was failing")
	}

	if l.DroppedTotal() == 0 {
		t.Error("the buffer overflowed while the store was down and DroppedTotal stayed at 0, so " +
			"an operator watching it sees no loss while records are being discarded")
	}

	repo.stopFailing()
	if err := l.Flush(context.Background()); err != nil {
		t.Fatalf("final Flush: %v", err)
	}
	if repo.insertedCount() == 0 {
		t.Error("nothing survived a store outage that ended, so the retry keeps nothing at all")
	}
	if repo.insertedCount() > capacity {
		t.Errorf("%d entries were kept against a buffer of %d; the retry is unbounded and a "+
			"store that stays down grows the buffer without limit", repo.insertedCount(), capacity)
	}
}
