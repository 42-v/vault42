package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// The purge is the one thing the append-only log cannot record by holding its
// result: the rows that would have shown it are the rows it deleted. Without an
// entry of its own, a trail that stops abruptly reads the same whether the
// sweeper ran on the configured horizon, ran on a horizon somebody changed, or
// never ran at all and a hand-written call to audit.cleanup_old_entries() took
// the rows instead.
//
// This asserts the content of the row rather than that something was written. A
// call count is satisfied by an entry naming neither the boundary that was
// applied nor how much went, which answers none of the questions the entry
// exists for.
func TestRetention_PurgeIsRecordedInTheAuditLog(t *testing.T) {
	var logged []*model.AuditEntry
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			return 12, true, nil
		},
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			logged = append(logged, e)
			return nil
		},
	}

	const horizon = 90 * 24 * time.Hour
	before := time.Now().Add(-horizon)
	if _, err := NewRetention(repo, horizon).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	after := time.Now().Add(-horizon)

	if len(logged) != 1 {
		t.Fatalf("a purge of 12 entries wrote %d audit entries, want exactly 1. A purge that "+
			"leaves no trace in the log it purges is indistinguishable from a direct call to "+
			"audit.cleanup_old_entries()", len(logged))
	}

	e := logged[0]
	if e.EventType != AdminAction {
		t.Errorf("event_type = %q, want %q", e.EventType, AdminAction)
	}
	// The severity and the id come from Logger.Log. Writing the row straight to
	// the repository would leave both unset and skip the scrubbing every other
	// entry goes through.
	if e.RiskScore != Severity(AdminAction) {
		t.Errorf("risk_score = %d, want %d: the entry did not go through Logger.Log",
			e.RiskScore, Severity(AdminAction))
	}
	if e.ID == "" {
		t.Error("the entry has no id, so it did not go through Logger.Log")
	}
	// A purge has no subject. Filling these in would put an operator's address
	// in a row about a scheduled job, and audit rows outlive erasure.
	if e.UserID != "" || e.IP != "" || e.UserAgent != "" {
		t.Errorf("the purge entry carries a subject: user=%q ip=%q ua=%q", e.UserID, e.IP, e.UserAgent)
	}

	meta := e.Metadata
	if meta == nil {
		t.Fatal("the purge entry has no metadata, so it records nothing about the purge")
	}
	if got := meta["action"]; got != "audit_retention_purge" {
		t.Errorf("action = %v, want audit_retention_purge: admin_action is a class, and the "+
			"metadata is what says which action it was", got)
	}
	if got := meta["outcome"]; got != "completed" {
		t.Errorf("outcome = %v, want completed", got)
	}
	if got := meta["deleted"]; got != int64(12) {
		t.Errorf("deleted = %v, want 12: the row count is the whole point of the record", got)
	}
	if got := meta["horizon"]; got != horizon.String() {
		t.Errorf("horizon = %v, want %s", got, horizon)
	}
	if got, _ := meta["replica"].(string); got != replicaID {
		t.Errorf("replica = %q, want %q: without it, a fleet whose purge has stopped looks "+
			"exactly like a fleet where one replica does all of it", got, replicaID)
	}

	raw, ok := meta["cutoff"].(string)
	if !ok {
		t.Fatalf("cutoff = %v (%T), want an RFC 3339 string", meta["cutoff"], meta["cutoff"])
	}
	cutoff, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("cutoff %q does not parse as RFC 3339: %v", raw, err)
	}
	// The cutoff has to be the one the DELETE used. A record naming a boundary
	// nothing applied is worse than no record: it attests to a horizon that was
	// never enforced.
	if cutoff.Before(before.Add(-time.Minute)) || cutoff.After(after.Add(time.Minute)) {
		t.Errorf("cutoff %v is not ~now-%s, so the record names a boundary the purge did not use",
			cutoff, horizon)
	}
}

// A sweep that took the lock, deleted rows and then failed is the case where
// knowing how much went matters most: the rows are gone, the horizon was not
// finished, and the next tick starts over. Recording only successes would leave
// the trail claiming nothing happened during the sweep that did the most damage
// without completing.
func TestRetention_FailedPurgeIsRecordedWithWhatItAlreadyDeleted(t *testing.T) {
	var logged []*model.AuditEntry
	call := 0
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			call++
			if call == 1 {
				// A full batch, so the loop comes back for another.
				return repository.AuditCleanupBatch, true, nil
			}
			return 0, true, errors.New("db down")
		},
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			logged = append(logged, e)
			return nil
		},
	}

	deleted, err := NewRetention(repo, 30*24*time.Hour).Sweep(context.Background())
	if err == nil {
		t.Fatal("expected the sweep error to surface")
	}
	if deleted != repository.AuditCleanupBatch {
		t.Fatalf("Sweep returned %d, want %d from the batch that landed before the failure",
			deleted, repository.AuditCleanupBatch)
	}

	if len(logged) != 1 {
		t.Fatalf("a failed purge wrote %d audit entries, want exactly 1", len(logged))
	}
	meta := logged[0].Metadata
	if got := meta["outcome"]; got != "failed" {
		t.Errorf("outcome = %v, want failed", got)
	}
	if got := meta["deleted"]; got != int64(repository.AuditCleanupBatch) {
		t.Errorf("deleted = %v, want %d: a partial purge still destroyed that many rows",
			got, repository.AuditCleanupBatch)
	}
}

// A sweep that found nothing past the horizon destroyed nothing, so there is
// nothing to attest to. Recording it anyway would write a row every six hours
// per replica saying there was no work -- and because that row is itself an
// audit entry, a horizon later it becomes something to purge, and its purge
// would write the next one. The log would end up as a chain of records of
// purging its own records.
func TestRetention_EmptyPurgeWritesNoRow(t *testing.T) {
	var logged []*model.AuditEntry
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			return 0, true, nil
		},
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			logged = append(logged, e)
			return nil
		},
	}

	if _, err := NewRetention(repo, 30*24*time.Hour).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(logged) != 0 {
		t.Errorf("a sweep that deleted nothing wrote %d audit entries, want 0", len(logged))
	}
}

// Every replica ticks on the same schedule and one wins the advisory lock. The
// losers did no work, and a record from them would put one row per replica in
// the log for a single purge -- the same over-count the sweeper already refuses
// to make in its return value.
func TestRetention_ReplicaThatLostTheElectionRecordsNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deleted  int64
		acquired bool
		err      error
	}{
		// The winner is mid-purge. This replica never touched a row.
		{name: "lock held elsewhere", deleted: 99, acquired: false},
		// The lock is taken before the delete, so a failure with acquired=false
		// is a database that would not answer, not a purge that went wrong.
		{name: "lock query failed", acquired: false, err: errors.New("db down")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged []*model.AuditEntry
			repo := &mocks.MockAuditRepo{
				CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
					return tc.deleted, tc.acquired, tc.err
				},
				InsertFn: func(_ context.Context, e *model.AuditEntry) error {
					logged = append(logged, e)
					return nil
				},
			}

			_, _ = NewRetention(repo, 30*24*time.Hour).Sweep(context.Background())

			if len(logged) != 0 {
				t.Errorf("a replica that never held the lock wrote %d audit entries, want 0: "+
					"one purge would be recorded once per replica", len(logged))
			}
		})
	}
}

// Shutdown cancels the sweep's context between batches, and the rows deleted
// before that point are already gone. Writing the record on the same context
// would cancel it too, so the one purge nobody watched finish -- the interesting
// one -- would be the one purge with no entry. A real store honors the context
// it is handed, so the double here does the same; a mock that ignored it would
// pass whichever context the sweeper used.
func TestRetention_PurgeInterruptedByShutdownIsStillRecorded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logged []*model.AuditEntry
	var insertErr error
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			// A full batch, so the loop reaches the shutdown check between
			// batches rather than finishing on its own.
			cancel()
			return repository.AuditCleanupBatch, true, nil
		},
		InsertFn: func(insertCtx context.Context, e *model.AuditEntry) error {
			if err := insertCtx.Err(); err != nil {
				insertErr = err
				return err
			}
			logged = append(logged, e)
			return nil
		},
	}

	if _, err := NewRetention(repo, 30*24*time.Hour).Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep err = %v, want context.Canceled", err)
	}
	if insertErr != nil {
		t.Fatalf("the record was written on the canceled sweep context (%v), so a shutdown "+
			"mid-purge destroys the evidence of the rows it already deleted", insertErr)
	}
	if len(logged) != 1 {
		t.Fatalf("an interrupted purge wrote %d audit entries, want exactly 1", len(logged))
	}
	if got := logged[0].Metadata["deleted"]; got != int64(repository.AuditCleanupBatch) {
		t.Errorf("deleted = %v, want %d", got, repository.AuditCleanupBatch)
	}
}

// The label has to name a replica even on a host that will not name itself, and
// it has to stay distinct between two processes sharing one host, which is what
// a compose file or a bare-metal box looks like.
func TestReplicaLabelNamesTheHostAndTheProcess(t *testing.T) {
	pid := os.Getpid()

	if got, want := replicaLabel("vault-7d9c-abc"), fmt.Sprintf("vault-7d9c-abc/%d", pid); got != want {
		t.Errorf("replicaLabel = %q, want %q", got, want)
	}
	if got := replicaLabel(""); !strings.HasPrefix(got, "unknown/") {
		t.Errorf("replicaLabel(\"\") = %q, want an unknown/<pid> placeholder: an empty field "+
			"reads as \"nobody recorded which replica swept\"", got)
	}
	if replicaID == "" {
		t.Error("replicaID is empty, so no purge record can say which replica ran it")
	}
}
