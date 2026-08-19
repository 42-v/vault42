package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// auth.cleanup_old_recovery has to disable the append-only trigger to delete
// anything, which is ALTER TABLE and therefore ACCESS EXCLUSIVE on
// auth.account_recovery. The one-argument form holds that lock over a single
// unbounded DELETE, so a purge against a table that has accumulated for the
// length of a retention horizon blocks every write to it for as long as it takes
// — and what writes to it is the erasure path: every Art. 17 deletion with a
// recovery key configured appends its escrow record before the account goes.
//
// Migration 032 fixed exactly this shape for the audit log. 034 rewrote this
// function for three other defects and did not carry the batching across, and
// PruneLocked — the scheduled path — kept calling the unbounded form. 036 adds
// the two-argument form and PruneLocked calls it.
//
// Against a real PostgreSQL, because the guards are plpgsql and the LIMIT is
// planner-visible.

func TestRecoveryCleanupBatchedDeletesAtMostMaxRows(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAccountRecoveryRepo(&postgres.DB{Pool: pool})

	const seeded = 25
	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for range seeded {
		seedRecoveryRecord(t, repo, old)
	}

	// A batch smaller than the backlog must take exactly the batch.
	var deleted int64
	if err := pool.QueryRow(ctx,
		"SELECT auth.cleanup_old_recovery($1::interval, $2)", "30 days", 10,
	).Scan(&deleted); err != nil {
		t.Fatalf("batched cleanup: %v", err)
	}
	if deleted != 10 {
		t.Fatalf("deleted = %d, want 10. An unbatched DELETE holds ACCESS EXCLUSIVE on the "+
			"escrow table for the whole horizon, and erasures append to it on the request path.",
			deleted)
	}

	// The rest goes over further calls, and the last one is short, which is how
	// the sweeper knows to stop.
	total := deleted
	for range 5 {
		if err := pool.QueryRow(ctx,
			"SELECT auth.cleanup_old_recovery($1::interval, $2)", "30 days", 10,
		).Scan(&deleted); err != nil {
			t.Fatalf("batched cleanup: %v", err)
		}
		total += deleted
		if deleted < 10 {
			break
		}
	}
	if total != seeded {
		t.Errorf("the loop purged %d of %d rows", total, seeded)
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Errorf("%d rows past the horizon survived the loop", remaining)
	}

	// The append-only guard has to be back on after a batched call too. It is
	// turned off inside the function, and a batch that returned early with it
	// still disabled would leave the escrow silently rewritable.
	var enabled string
	if err := pool.QueryRow(ctx,
		`SELECT tgenabled FROM pg_trigger WHERE tgname = 'account_recovery_no_delete'`,
	).Scan(&enabled); err != nil {
		t.Fatalf("read trigger state: %v", err)
	}
	if enabled != "O" {
		t.Errorf("account_recovery_no_delete is %q, want \"O\" (enabled)", enabled)
	}
}

// The batched form has to keep every guard 034 put on the unbatched one, plus
// one of its own on the batch size. A guard that only exists on the overload
// nobody schedules is not a guard.
func TestRecoveryCleanupBatchedKeepsTheGuards(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAccountRecoveryRepo(&postgres.DB{Pool: pool})
	seedRecoveryRecord(t, repo, time.Now().UTC().Add(-90*24*time.Hour))

	refused := []struct {
		name     string
		interval any
		maxRows  any
	}{
		{"a zero horizon takes the whole table", "0 seconds", 10},
		{"a negative horizon puts the cutoff in the future", "-1 day", 10},
		{"a NULL horizon makes the predicate NULL", nil, 10},
		{"a NULL batch size", "30 days", nil},
		{"a zero batch size would delete nothing forever", "30 days", 0},
		{"a negative batch size", "30 days", -1},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			var deleted int64
			err := pool.QueryRow(ctx,
				"SELECT auth.cleanup_old_recovery($1::interval, $2::integer)", tc.interval, tc.maxRows,
			).Scan(&deleted)
			if err == nil {
				t.Fatalf("the call was accepted and deleted %d rows", deleted)
			}
		})
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("%d escrow rows remain, want 1: a refused call must delete nothing", remaining)
	}
}

// PruneLocked is the scheduled path, and the point of 036 is that it stopped
// calling the unbounded form. Proving that needs a backlog larger than the
// batch, so the seeding is one bulk INSERT rather than 2001 round trips.
func TestRecoveryPruneLockedTakesAtMostOneBatch(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAccountRecoveryRepo(&postgres.DB{Pool: pool})

	const backlog = repository.RecoveryCleanupBatch + 1
	if _, err := pool.Exec(ctx,
		`INSERT INTO auth.account_recovery (id, pseudonym, payload, deleted_at, deleted_by, reason)
		 SELECT gen_random_uuid(), 'p-' || i, '\x00'::bytea, $1, 'self', 'user_request'
		   FROM generate_series(1, $2) AS i`,
		time.Now().UTC().Add(-90*24*time.Hour), backlog,
	); err != nil {
		t.Fatalf("seed backlog: %v", err)
	}

	deleted, acquired, err := repo.PruneLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneLocked: %v", err)
	}
	if !acquired {
		t.Fatal("an uncontended sweep must acquire the lock")
	}
	if deleted != repository.RecoveryCleanupBatch {
		t.Fatalf("PruneLocked deleted %d of a %d-row backlog, want exactly %d. One call holds "+
			"ACCESS EXCLUSIVE on the escrow table for the whole of its DELETE, and every "+
			"erasure appending its escrow record waits behind that lock.",
			deleted, backlog, repository.RecoveryCleanupBatch)
	}

	// A short second call is what tells the sweeper the horizon is clear.
	deleted, _, err = repo.PruneLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneLocked second: %v", err)
	}
	if deleted != 1 {
		t.Errorf("the second call deleted %d, want the 1 row the first left", deleted)
	}
}
