package integration_test

import (
	"context"
	"testing"
	"time"
)

// audit.cleanup_old_entries has to disable the append-only trigger to delete
// anything, which is ALTER TABLE and therefore ACCESS EXCLUSIVE on
// audit.audit_log. The one-argument form holds that lock over a single
// unbounded DELETE, so a purge against a table that has been accumulating for
// the length of a retention horizon blocks every audit insert for as long as it
// takes — and a failed login is a critical event, written synchronously on the
// request path even when the buffer is full.
//
// Migration 030 adds a form that deletes at most max_rows and reports how many
// went, so internal/audit can loop and the exclusive lock is taken and released
// once per batch. These run it against a real PostgreSQL: the guards are
// plpgsql and the LIMIT is planner-visible, neither of which a unit test can
// check.

func TestAuditCleanupBatchedDeletesAtMostMaxRows(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	const seeded = 25
	old := time.Now().Add(-90 * 24 * time.Hour)
	for i := 0; i < seeded; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO audit.audit_log (id, event_type, timestamp, risk_score)
			 VALUES (gen_random_uuid(), 'login_failure', $1, 10)`, old,
		); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	// A batch smaller than the backlog must take exactly the batch.
	var deleted int64
	if err := pool.QueryRow(ctx,
		"SELECT audit.cleanup_old_entries($1::interval, $2)", "30 days", 10,
	).Scan(&deleted); err != nil {
		t.Fatalf("batched cleanup: %v", err)
	}
	if deleted != 10 {
		t.Fatalf("first batch deleted %d rows, want the 10 the LIMIT allows — an unbatched "+
			"DELETE holds ACCESS EXCLUSIVE for the whole purge and every audit insert waits", deleted)
	}

	// Looping drains the rest, and the last batch is short, which is how the
	// sweeper knows to stop.
	total := deleted
	for i := 0; i < 10 && deleted == 10; i++ {
		if err := pool.QueryRow(ctx,
			"SELECT audit.cleanup_old_entries($1::interval, $2)", "30 days", 10,
		).Scan(&deleted); err != nil {
			t.Fatalf("batch %d: %v", i+2, err)
		}
		total += deleted
	}
	if total != seeded {
		t.Fatalf("the loop purged %d rows, want %d", total, seeded)
	}

	// The append-only trigger has to be back on afterwards, or the purge has
	// left the audit table deletable by anyone who can reach it.
	//
	// audit_log_no_delete is BEFORE DELETE FOR EACH ROW, so it only fires if
	// the DELETE actually reaches a row. The purge above emptied the table, so
	// this needs a row inside the horizon to aim at — otherwise the check
	// passes on a statement that deleted nothing and proves nothing.
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit.audit_log (id, event_type, timestamp, risk_score)
		 VALUES (gen_random_uuid(), 'login_failure', NOW(), 0)`,
	); err != nil {
		t.Fatalf("seed a live row: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM audit.audit_log"); err == nil {
		t.Fatal("a plain DELETE on audit.audit_log succeeded after the batched purge; the " +
			"append-only trigger was not re-enabled")
	}
}

// TestAuditCleanupBatchedKeepsTheHorizonGuard pins that the batched form
// carries the same guards as the one it was copied from. A guard that lives in
// a different function from the DELETE it protects is one edit away from
// protecting nothing, which is why they are restated rather than shared.
func TestAuditCleanupBatchedKeepsTheHorizonGuard(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	// "1 mon -29 days" is deliberately absent. Whether its cutoff lands in the
	// future depends on the month the test runs in — that is the whole point of
	// the bug migration 018 fixed — so a hardcoded verdict for it passes all
	// year and fails every February. TestAuditCleanupMixedUnitHorizonMatchesThe
	// Oracle below asks Postgres instead, the way the single-argument form's
	// test does.
	for _, tc := range []struct {
		name     string
		interval interface{}
		maxRows  interface{}
	}{
		{"a horizon under a day", "12 hours", 100},
		{"a null horizon", nil, 100},
		{"a zero batch", "90 days", 0},
		{"a negative batch", "90 days", -1},
		{"a null batch", "90 days", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deleted int64
			err := pool.QueryRow(ctx,
				"SELECT audit.cleanup_old_entries($1::interval, $2::integer)", tc.interval, tc.maxRows,
			).Scan(&deleted)
			if err == nil {
				t.Fatalf("cleanup_old_entries(%v, %v) was accepted; the batched form must carry "+
					"every guard the unbatched one does", tc.interval, tc.maxRows)
			}
		})
	}
}

// TestAuditCleanupMixedUnitHorizonMatchesTheOracle is the mixed-unit half of
// the guard, asked rather than assumed.
//
// Comparing two intervals canonicalizes a month to 30 days; subtracting one
// from NOW() uses the real calendar month. Any interval carrying a month
// component therefore behaves differently depending on today's date, so the
// only stable assertion is that the function agrees with the cutoff Postgres
// actually computes right now. Same shape as the single-argument form's test,
// for the same reason.
func TestAuditCleanupMixedUnitHorizonMatchesTheOracle(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	for _, iv := range []string{"1 mon -29 days", "1 mon -28 days", "1 mon -30 days", "2 mons -59 days"} {
		t.Run(iv, func(t *testing.T) {
			var wipesRecent bool
			if err := pool.QueryRow(ctx,
				"SELECT NOW() - $1::interval > NOW() - INTERVAL '1 day'", iv,
			).Scan(&wipesRecent); err != nil {
				t.Fatalf("oracle query for %q: %v", iv, err)
			}

			var deleted int64
			err := pool.QueryRow(ctx,
				"SELECT audit.cleanup_old_entries($1::interval, $2)", iv, 100,
			).Scan(&deleted)

			if wipesRecent && err == nil {
				t.Fatalf("cleanup_old_entries(%q, 100) was accepted, but its cutoff is less than "+
					"a day back — the batched form dropped the guard the unbatched one carries", iv)
			}
			if !wipesRecent && err != nil {
				t.Fatalf("cleanup_old_entries(%q, 100) was rejected (%v), but its cutoff is a full "+
					"day back, so the sweeper cannot run", iv, err)
			}
		})
	}
}

// TestAuditCleanupBatchedAcceptsALegitimateHorizon is the negative control: a
// guard that rejects everything would pass the test above and stop the sweeper
// from ever running.
func TestAuditCleanupBatchedAcceptsALegitimateHorizon(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	var deleted int64
	if err := pool.QueryRow(ctx,
		"SELECT audit.cleanup_old_entries($1::interval, $2)", "90 days", 2000,
	).Scan(&deleted); err != nil {
		t.Fatalf("a 90-day horizon with a 2000-row batch was rejected: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted %d rows from an empty table", deleted)
	}
}
