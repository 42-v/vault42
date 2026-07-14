package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// The audit log is the record an investigator reads after an incident, and its value
// rests entirely on being complete. A write that fails silently does not produce a
// visibly broken log — it produces a log with a hole in it that looks exactly like a
// log in which nothing happened.
//
// Insert is called on every login, every failed attempt and every admin action. The
// caller treats it as best-effort and discards the error, which is a deliberate choice
// (auditing must never block authentication) — but that choice is only survivable if
// the repository reports the failure honestly to everything else that asks, and if the
// query path cannot pass off an empty result as "no events matched".
func TestAuditRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAuditRepo(deadPool(t))
	ctx := context.Background()

	entry := &model.AuditEntry{
		ID: "a-1", EventType: "login_success", UserID: "u-1", IP: "203.0.113.1",
	}

	if err := repo.Insert(ctx, entry); err == nil {
		t.Error("Insert reported success against an unreachable database — the event was never recorded")
	}
	if err := repo.InsertBatch(ctx, []*model.AuditEntry{entry}); err == nil {
		t.Error("InsertBatch reported success against an unreachable database")
	}
	if _, err := repo.Query(ctx, repository.AuditFilter{Limit: 10}); err == nil {
		t.Error("Query returned no error — an empty result would read as 'no such events', which is what an investigator would conclude")
	}
	if _, err := repo.Cleanup(ctx, time.Now().Add(-24*time.Hour)); err == nil {
		t.Error("Cleanup reported success against an unreachable database")
	}

	// CleanupLocked reports whether it won the advisory lock. On a database failure it
	// must not claim it acquired one: a caller told "acquired, 0 rows" would record a
	// successful sweep that never ran.
	deleted, acquired, err := repo.CleanupLocked(ctx, time.Now().Add(-24*time.Hour))
	if err == nil {
		t.Error("CleanupLocked reported success against an unreachable database")
	}
	if acquired {
		t.Error("CleanupLocked claimed the advisory lock while the database was unreachable")
	}
	if deleted != 0 {
		t.Errorf("a failed CleanupLocked reported %d rows purged", deleted)
	}
}
