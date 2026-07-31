package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// audit.cleanup_old_entries() is the only sanctioned way a row ever leaves the
// audit log: it is SECURITY DEFINER precisely so it can disable the append-only
// trigger, and its definer owns audit.audit_log. Every EXECUTE grant on it is
// therefore a hole straight through "the audit log is append-only at DB level",
// and PostgreSQL grants EXECUTE on a function to PUBLIC by default.
//
// The privilege model the sweeper actually needs is narrow: vault_app calls it
// (the retention loop runs in-process in cmd/vault, and `vault cleanup-audit`
// shares that pool), nobody else does, and the only legitimate argument is a
// retention horizon measured in whole days.
func TestAuditPurgeFunctionPrivileges(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)

	ownerRepo := postgres.NewAuditRepo(&postgres.DB{Pool: adminPool})
	seedAuditEntry(t, ownerRepo, time.Now().UTC().Add(-10*24*time.Hour))
	seedAuditEntry(t, ownerRepo, time.Now().UTC().Add(-5*24*time.Hour))
	seedAuditEntry(t, ownerRepo, time.Now().UTC().Add(-time.Hour))

	count := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := adminPool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	t.Run("the definer carries an explicit search_path", func(t *testing.T) {
		var config []string
		err := adminPool.QueryRow(ctx, `
			SELECT p.proconfig FROM pg_proc p
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'audit' AND p.proname = 'cleanup_old_entries'`).Scan(&config)
		if err != nil {
			t.Fatalf("read proconfig: %v", err)
		}
		var found bool
		for _, c := range config {
			if strings.HasPrefix(c, "search_path=") {
				found = true
			}
		}
		if !found {
			t.Errorf("proconfig = %v, want a search_path, because a SECURITY DEFINER function without one resolves names through the caller's schema (CVE-2018-1058)", config)
		}
	})

	t.Run("PUBLIC cannot execute it", func(t *testing.T) {
		var granted bool
		err := adminPool.QueryRow(ctx,
			`SELECT has_function_privilege('public', 'audit.cleanup_old_entries(interval)', 'EXECUTE')`).Scan(&granted)
		if err != nil {
			t.Fatalf("has_function_privilege: %v", err)
		}
		if granted {
			t.Error("EXECUTE is still granted to PUBLIC, so any role in the cluster can purge the audit log")
		}
	})

	t.Run("vault_admin cannot purge", func(t *testing.T) {
		pool := adminRolePool(t, adminPool)
		var deleted int64
		err := pool.QueryRow(ctx, `SELECT audit.cleanup_old_entries(interval '30 days')`).Scan(&deleted)
		if !permissionDenied(err) {
			t.Errorf("the admin gateway role may purge the audit log: err = %v", err)
		}
	})

	appPool := appRolePool(t, adminPool)

	// The Go callers cannot express a non-positive horizon (Retention is disabled
	// at zero and `vault cleanup-audit` rejects it), so the guard exists for the
	// caller that never goes through them: SQL reaching the database as vault_app.
	t.Run("vault_app cannot wipe the log with a degenerate horizon", func(t *testing.T) {
		before := count(t)
		for _, iv := range []string{"0 seconds", "-1 second", "-100 years", "1 hour"} {
			var deleted int64
			err := appPool.QueryRow(ctx, `SELECT audit.cleanup_old_entries($1::interval)`, iv).Scan(&deleted)
			if err == nil {
				t.Errorf("a %s horizon was accepted and removed %d entries", iv, deleted)
			}
		}
		if after := count(t); after != before {
			t.Errorf("%d of %d entries were destroyed by a rejected purge", before-after, before)
		}
	})

	t.Run("vault_app still sweeps at a real horizon", func(t *testing.T) {
		repo := postgres.NewAuditRepo(&postgres.DB{Pool: appPool})
		deleted, acquired, err := repo.CleanupLocked(ctx, time.Now().UTC().Add(-3*24*time.Hour))
		if err != nil {
			t.Fatalf("the retention sweeper can no longer run: %v", err)
		}
		if !acquired {
			t.Fatal("an uncontended sweep must acquire the lock")
		}
		if deleted != 2 {
			t.Errorf("deleted = %d, want 2", deleted)
		}
		if remaining := count(t); remaining != 1 {
			t.Errorf("%d entries remain, want 1: the sweep took entries inside the horizon", remaining)
		}
	})

	t.Run("the append-only trigger survives the sweep", func(t *testing.T) {
		var enabled string
		err := adminPool.QueryRow(ctx, `
			SELECT tgenabled FROM pg_trigger
			WHERE tgname = 'audit_log_no_delete' AND tgrelid = 'audit.audit_log'::regclass`).Scan(&enabled)
		if err != nil {
			t.Fatalf("read trigger state: %v", err)
		}
		if enabled == "D" {
			t.Fatal("audit_log_no_delete is still disabled after a sweep")
		}
		if _, err := appPool.Exec(ctx, `DELETE FROM audit.audit_log`); !permissionDenied(err) {
			t.Errorf("vault_app deleted audit rows directly: err = %v", err)
		}
	})
}
