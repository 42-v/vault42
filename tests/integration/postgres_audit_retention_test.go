package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func seedAuditEntry(t *testing.T, repo *postgres.AuditRepo, at time.Time) {
	t.Helper()
	err := repo.Insert(context.Background(), &model.AuditEntry{
		ID:        randomID(),
		EventType: "login_success",
		UserID:    randomID(),
		IP:        "203.0.113.7",
		UserAgent: "ua",
		Timestamp: at,
	})
	if err != nil {
		t.Fatalf("insert audit entry: %v", err)
	}
}

// CleanupLocked is what the retention sweeper actually calls, and it does two
// things that only a real database can prove: it takes an advisory lock so that
// one replica sweeps at a time, and it runs audit.cleanup_old_entries(), which
// disables the append-only trigger, deletes, and re-enables it — inside the
// transaction that holds the lock.
func TestAuditCleanupLocked(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAuditRepo(&postgres.DB{Pool: pool})

	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	recent := time.Now().UTC().Add(-time.Hour)
	seedAuditEntry(t, repo, old)
	seedAuditEntry(t, repo, old)
	seedAuditEntry(t, repo, recent)

	t.Run("purges past the horizon and keeps the rest", func(t *testing.T) {
		deleted, acquired, err := repo.CleanupLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
		if err != nil {
			t.Fatalf("CleanupLocked: %v", err)
		}
		if !acquired {
			t.Fatal("an uncontended sweep must acquire the lock")
		}
		if deleted != 2 {
			t.Errorf("deleted = %d, want 2", deleted)
		}

		var remaining int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log`).Scan(&remaining); err != nil {
			t.Fatalf("count: %v", err)
		}
		if remaining != 1 {
			t.Errorf("entries inside the horizon were purged: %d remain, want 1", remaining)
		}
	})

	// The append-only guard must be back on afterwards. The cleanup function
	// disables it to delete; if a sweep could leave it disabled, the audit log
	// would silently stop being append-only — the property the whole design rests
	// on.
	t.Run("the append-only trigger is re-enabled", func(t *testing.T) {
		var enabled string
		err := pool.QueryRow(ctx, `
			SELECT tgenabled FROM pg_trigger
			WHERE tgname = 'audit_log_no_delete'
			  AND tgrelid = 'audit.audit_log'::regclass`).Scan(&enabled)
		if err != nil {
			t.Fatalf("read trigger state: %v", err)
		}
		if enabled == "D" {
			t.Fatal("audit_log_no_delete is still DISABLED after a sweep — the audit log is no longer append-only")
		}

		// And prove it: a direct delete must still be refused.
		if _, err := pool.Exec(ctx, `DELETE FROM audit.audit_log`); err == nil {
			t.Error("audit log accepted a DELETE — the append-only trigger is not enforcing")
		}
	})

	// Only one replica may sweep at a time: the cleanup takes an ACCESS EXCLUSIVE
	// lock on the audit table, so a fleet sweeping in parallel would pile up on it
	// and stall audit inserts. A replica that loses the advisory lock must report
	// acquired=false and skip, not block or error.
	t.Run("a second sweeper skips rather than contending", func(t *testing.T) {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer conn.Release()

		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		// Hold the same advisory lock the sweeper uses.
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(4242)`).Scan(&got); err != nil {
			t.Fatalf("take lock: %v", err)
		}
		if !got {
			t.Fatal("could not take the lock to simulate a competing replica")
		}

		deleted, acquired, err := repo.CleanupLocked(ctx, time.Now().UTC().Add(-time.Minute))
		if err != nil {
			t.Fatalf("a losing sweeper must not error: %v", err)
		}
		if acquired {
			t.Error("two replicas swept at once — the advisory lock is not serialising them")
		}
		if deleted != 0 {
			t.Errorf("a skipped sweep must delete nothing, deleted = %d", deleted)
		}
	})
	t.Run("the sweeper on top of the repo", func(t *testing.T) {
		sweeperAgainstPostgres(t, pool)
	})
}

// A deployment whose migrations drifted can lose audit.cleanup_old_entries().
// The sweep must then surface the failure rather than report an empty successful
// sweep: a silent no-op here means the retention promise in docs/PRIVACY.md
// quietly stops being kept. Own container, because the function stays dropped.
func TestAuditCleanupLockedMissingFunction(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAuditRepo(&postgres.DB{Pool: pool})
	seedAuditEntry(t, repo, time.Now().UTC().Add(-90*24*time.Hour))

	// Both overloads. Migration 030 added a batched form and CleanupLocked
	// calls that one, so dropping only the single-argument function left the
	// one under test in place and the sweep reported a clean success — which is
	// exactly the silent no-op this test exists to catch.
	for _, sig := range []string{"interval", "interval, integer"} {
		if _, err := pool.Exec(ctx, `DROP FUNCTION audit.cleanup_old_entries(`+sig+`)`); err != nil {
			t.Fatalf("drop cleanup function(%s): %v", sig, err)
		}
	}

	deleted, acquired, err := repo.CleanupLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err == nil {
		t.Fatal("CleanupLocked reported success with the cleanup function missing")
	}
	if !acquired {
		t.Error("the advisory lock is taken before the cleanup call, acquired must be true")
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("a failed sweep changed the audit log: %d rows remain, want 1", remaining)
	}
}

// sweeperAgainstPostgres: the sweeper on top of the repo — disabled means inert,
// enabled means it purges. A subtest so it shares the container above rather than
// standing up another Postgres.
func sweeperAgainstPostgres(t *testing.T, pool *pgxpool.Pool) {
	ctx := context.Background()

	repo := postgres.NewAuditRepo(&postgres.DB{Pool: pool})
	seedAuditEntry(t, repo, time.Now().UTC().Add(-90*24*time.Hour))

	disabled := audit.NewRetention(repo, 0)
	if n, err := disabled.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("a disabled sweeper must purge nothing: n=%d err=%v", n, err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining < 1 {
		t.Fatalf("disabled retention deleted rows: %d remain", remaining)
	}

	enabled := audit.NewRetention(repo, 30*24*time.Hour)
	if _, err := enabled.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log WHERE timestamp < NOW() - INTERVAL '30 days'`).Scan(&left); err != nil {
		t.Fatalf("count: %v", err)
	}
	if left != 0 {
		t.Errorf("%d entries past the horizon survived the sweep", left)
	}
}
