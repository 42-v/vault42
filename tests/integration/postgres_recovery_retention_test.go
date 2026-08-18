package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

func seedRecoveryRecord(t *testing.T, repo *postgres.AccountRecoveryRepo, at time.Time) {
	t.Helper()
	err := repo.Append(context.Background(), &model.AccountRecovery{
		ID:        randomID(),
		Pseudonym: randomID(),
		Payload:   []byte("encrypted-to-the-offline-key"),
		DeletedAt: at,
		DeletedBy: "self",
		Reason:    "user_request",
	})
	if err != nil {
		t.Fatalf("append recovery record: %v", err)
	}
}

// The escrow was append-only and unbounded: triggers block DELETE, both app roles
// have it revoked, and nothing removed a row. auth.cleanup_old_recovery()
// (migration 011) is the only path that can, and only a real database can prove
// it deletes the right side of the horizon and puts the append-only guard back.
func TestRecoveryPruneLocked(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAccountRecoveryRepo(&postgres.DB{Pool: pool})

	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	recent := time.Now().UTC().Add(-time.Hour)
	seedRecoveryRecord(t, repo, old)
	seedRecoveryRecord(t, repo, old)
	seedRecoveryRecord(t, repo, recent)

	t.Run("purges past the horizon and keeps the rest", func(t *testing.T) {
		deleted, acquired, err := repo.PruneLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
		if err != nil {
			t.Fatalf("PruneLocked: %v", err)
		}
		if !acquired {
			t.Fatal("an uncontended sweep must acquire the lock")
		}
		if deleted != 2 {
			t.Errorf("deleted = %d, want 2", deleted)
		}

		var remaining int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&remaining); err != nil {
			t.Fatalf("count: %v", err)
		}
		if remaining != 1 {
			t.Errorf("records inside the horizon were purged: %d remain, want 1", remaining)
		}
	})

	// The prune disables the append-only trigger to delete. If a sweep could leave
	// it disabled, the escrow would silently stop being append-only, and an
	// attacker who could write rows could then rewrite deletion history.
	t.Run("the append-only trigger is re-enabled", func(t *testing.T) {
		var enabled string
		err := pool.QueryRow(ctx, `
			SELECT tgenabled FROM pg_trigger
			WHERE tgname = 'account_recovery_no_delete'
			  AND tgrelid = 'auth.account_recovery'::regclass`).Scan(&enabled)
		if err != nil {
			t.Fatalf("read trigger state: %v", err)
		}
		if enabled == "D" {
			t.Fatal("account_recovery_no_delete is still DISABLED after a sweep")
		}

		if _, err := pool.Exec(ctx, `DELETE FROM auth.account_recovery`); err == nil {
			t.Error("the escrow accepted a direct DELETE, the append-only trigger is not enforcing")
		}
	})

	// One replica sweeps at a time: the prune takes an ACCESS EXCLUSIVE lock on the
	// escrow table. A replica that loses the advisory lock must skip, not block.
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

		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(4243)`).Scan(&got); err != nil {
			t.Fatalf("take lock: %v", err)
		}
		if !got {
			t.Fatal("could not take the lock to simulate a competing replica")
		}

		deleted, acquired, err := repo.PruneLocked(ctx, time.Now().UTC().Add(-time.Minute))
		if err != nil {
			t.Fatalf("a losing sweeper must not error: %v", err)
		}
		if acquired {
			t.Error("two replicas swept at once, the advisory lock is not serializing them")
		}
		if deleted != 0 {
			t.Errorf("a skipped sweep must delete nothing, deleted = %d", deleted)
		}
	})

	// Disabled means inert. The escrow is the only recoverable copy of an erased
	// account, so a deployment that set no horizon must lose nothing.
	t.Run("the sweeper on top of the repo", func(t *testing.T) {
		seedRecoveryRecord(t, repo, time.Now().UTC().Add(-90*24*time.Hour))

		if n, err := service.NewRecoveryRetention(repo, 0).Sweep(ctx); err != nil || n != 0 {
			t.Errorf("a disabled sweeper must purge nothing: n=%d err=%v", n, err)
		}
		var remaining int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&remaining); err != nil {
			t.Fatalf("count: %v", err)
		}
		if remaining < 1 {
			t.Fatalf("disabled retention deleted rows: %d remain", remaining)
		}

		if _, err := service.NewRecoveryRetention(repo, 30*24*time.Hour).Sweep(ctx); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		var left int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery WHERE deleted_at < NOW() - INTERVAL '30 days'`).Scan(&left); err != nil {
			t.Fatalf("count: %v", err)
		}
		if left != 0 {
			t.Errorf("%d escrow records past the horizon survived the sweep", left)
		}
	})
}

// A deployment whose migrations drifted can lose auth.cleanup_old_recovery(). The
// sweep must surface that rather than report an empty successful sweep, which
// would let the retention promise in docs/PRIVACY.md quietly stop being kept.
// Own container, because the function stays dropped.
func TestRecoveryPruneMissingFunction(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewAccountRecoveryRepo(&postgres.DB{Pool: pool})
	seedRecoveryRecord(t, repo, time.Now().UTC().Add(-90*24*time.Hour))

	if _, err := pool.Exec(ctx, `DROP FUNCTION auth.cleanup_old_recovery(interval)`); err != nil {
		t.Fatalf("drop cleanup function: %v", err)
	}

	deleted, acquired, err := repo.PruneLocked(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err == nil {
		t.Fatal("PruneLocked reported success with the cleanup function missing")
	}
	if !acquired {
		t.Error("the advisory lock is taken before the cleanup call, acquired must be true")
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("a failed sweep changed the escrow: %d rows remain, want 1", remaining)
	}
}
