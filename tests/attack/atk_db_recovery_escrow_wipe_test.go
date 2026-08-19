package attack

// Finding F-1: SQL running as vault_app can destroy the entire account-recovery
// escrow through auth.cleanup_old_recovery().
//
// 007 shipped auth.account_recovery append-only: BEFORE DELETE and BEFORE UPDATE
// triggers refuse both, and neither application role holds DELETE. Its header
// states the invariant in terms — "an attacker who can write rows still cannot
// rewrite or erase escrow history" — because the escrow is the only recoverable
// copy of an erased account and exists to survive a malicious deletion.
//
// 011 then added the one sanctioned removal path. It is SECURITY DEFINER because
// it has to disable the append-only trigger to delete, and its definer owns the
// table. That makes every property of the function load-bearing, and it shipped
// with none of the three that its twin audit.cleanup_old_entries() was given:
//
//   1. No REVOKE ... FROM PUBLIC. PostgreSQL grants EXECUTE on a function to
//      PUBLIC by default, so every role in the cluster held the purge.
//   2. No minimum horizon. INTERVAL '0 seconds' deletes every row whose
//      deleted_at is in the past, which is the whole table; a negative interval
//      puts the cutoff in the future and takes the rest.
//   3. No SET search_path. The body says NOW() unqualified, so a caller that
//      names pg_catalog late in its own search_path chooses which now() the
//      definer runs (CVE-2018-1058) and with it which side of the horizon the
//      DELETE takes.
//
// Each is independently sufficient to lose the escrow, so each is tested on its
// own rather than through one composite call. These run every hostile statement
// as the real vault_app role against the migrations applied verbatim.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// atkRecoveryTruncate empties the escrow as the owner. TRUNCATE bypasses row
// triggers, which is the only way to clear an append-only table between
// subtests without going through the very function under test.
func atkRecoveryTruncate(t *testing.T, owner *pgxpool.Pool) {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `TRUNCATE auth.account_recovery`); err != nil {
		t.Fatalf("truncate account_recovery: %v", err)
	}
}

// atkRecoverySeed writes one escrow row per age, as vault_app, which is the role
// that legitimately appends them (007 grants it INSERT and SELECT).
func atkRecoverySeed(t *testing.T, app *pgxpool.Pool, ages ...time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, age := range ages {
		_, err := app.Exec(ctx, `
			INSERT INTO auth.account_recovery (id, pseudonym, payload, deleted_at, deleted_by, reason)
			VALUES ($1, $2, $3, NOW() - $4::interval, 'self', 'user_request')`,
			atkDBRandomID(t), atkDBRandomID(t), []byte("encrypted-to-the-offline-key"),
			age.String())
		if err != nil {
			t.Fatalf("seed escrow row aged %s: %v", age, err)
		}
	}
}

// atkRecoveryCount reads the escrow as the owner, so a permission error in the
// counter can never be mistaken for an empty table.
func atkRecoveryCount(t *testing.T, owner *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(context.Background(), `SELECT COUNT(*) FROM auth.account_recovery`).Scan(&n); err != nil {
		t.Fatalf("count escrow: %v", err)
	}
	return n
}

// TestRecoveryEscrowPurgePrivilegesAsVaultApp exercises F-1's three weaknesses
// separately, then the legitimate sweep that must survive all three fixes.
func TestRecoveryEscrowPurgePrivilegesAsVaultApp(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	app := atkDBRolePool(t, owner, "vault_app")
	admin := atkDBRolePool(t, owner, "vault_admin")

	t.Run("weakness 1: PUBLIC does not hold the purge", func(t *testing.T) {
		var granted bool
		err := owner.QueryRow(ctx,
			`SELECT has_function_privilege('public', 'auth.cleanup_old_recovery(interval)', 'EXECUTE')`).Scan(&granted)
		if err != nil {
			t.Fatalf("has_function_privilege: %v", err)
		}
		if granted {
			t.Error("EXECUTE on auth.cleanup_old_recovery is still granted to PUBLIC, so every role " +
				"in the cluster can disable the append-only trigger and purge the escrow")
		}

		// vault_admin is the second real login in this cluster and never prunes:
		// cmd/admin-gateway builds an AccountRecoveryRepo to append escrow rows on
		// erasure and calls neither Prune nor PruneLocked. A runtime refusal is
		// what proves the ACL rather than the catalog agreeing with itself.
		var deleted int64
		err = admin.QueryRow(ctx, `SELECT auth.cleanup_old_recovery(interval '30 days')`).Scan(&deleted)
		if !atkRecoveryPermissionDenied(err) {
			t.Errorf("the admin gateway role may purge the escrow: err = %v", err)
		}
	})

	t.Run("weakness 2: a horizon under a day is refused", func(t *testing.T) {
		atkRecoveryTruncate(t, owner)
		atkRecoverySeed(t, app, 90*24*time.Hour, 10*24*time.Hour, time.Hour)
		before := atkRecoveryCount(t, owner)

		// Every one of these destroys the whole escrow through the 011 body as it
		// shipped. A NULL argument is included because NOW() - NULL is NULL and
		// `deleted_at < NULL` is NULL rather than true: it deletes nothing today,
		// so a guard that folds NULL into the cutoff comparison would look fine
		// and then admit whatever a later edit made of it.
		for _, horizon := range []any{"0 seconds", "-1 second", "-100 years", "1 hour", "23 hours", nil} {
			var deleted int64
			err := app.QueryRow(ctx, `SELECT auth.cleanup_old_recovery($1::interval)`, horizon).Scan(&deleted)
			if err == nil {
				t.Errorf("a %v horizon was accepted and removed %d escrow records", horizon, deleted)
			}
		}

		if after := atkRecoveryCount(t, owner); after != before {
			t.Errorf("%d of %d escrow records were destroyed by a rejected purge", before-after, before)
		}
	})

	t.Run("weakness 3: a shadowed search_path does not redirect the definer", func(t *testing.T) {
		atkRecoveryTruncate(t, owner)
		atkRecoverySeed(t, app, time.Hour, 2*time.Hour)
		before := atkRecoveryCount(t, owner)

		// The decoy is created by the owner and only used by vault_app. vault_app
		// holds no CREATE anywhere today, so this is the CVE-2018-1058 class
		// rather than a live vault_app path: any role that can put a schema on
		// the search path — an extension, a later migration, an operator's
		// scratch schema — chooses which now() a definer without a pinned
		// search_path executes.
		for _, stmt := range []string{
			`DROP SCHEMA IF EXISTS atk_shadow CASCADE`,
			`CREATE SCHEMA atk_shadow`,
			`CREATE FUNCTION atk_shadow.now() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $f$ SELECT '2999-01-01'::timestamptz $f$`,
			`GRANT USAGE ON SCHEMA atk_shadow TO vault_app`,
			`GRANT EXECUTE ON FUNCTION atk_shadow.now() TO vault_app`,
		} {
			if _, err := owner.Exec(ctx, stmt); err != nil {
				t.Fatalf("build the decoy schema (%s): %v", stmt, err)
			}
		}
		defer func() { _, _ = owner.Exec(ctx, `DROP SCHEMA IF EXISTS atk_shadow CASCADE`) }()

		// One connection for the whole attack: SET search_path is per-session, and
		// a pool hands the next statement to whichever connection is free.
		conn, err := app.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer conn.Release()
		defer func() { _, _ = conn.Exec(ctx, `RESET search_path`) }()

		// pg_catalog is searched first unless it is named explicitly, so naming it
		// last is what puts the decoy ahead of the real now().
		if _, err := conn.Exec(ctx, `SET search_path = atk_shadow, pg_catalog`); err != nil {
			t.Fatalf("set the hostile search_path: %v", err)
		}

		// A year-long horizon must not touch escrow written an hour ago. It does
		// exactly that when the definer resolves now() through the caller.
		var deleted int64
		if err := conn.QueryRow(ctx, `SELECT auth.cleanup_old_recovery(interval '365 days')`).Scan(&deleted); err != nil {
			t.Fatalf("the legitimate 365-day sweep failed under a hostile search_path: %v", err)
		}
		if deleted != 0 {
			t.Errorf("a 365-day horizon removed %d escrow records aged one and two hours: the definer "+
				"ran the caller's now(), so the caller chose the cutoff", deleted)
		}
		if after := atkRecoveryCount(t, owner); after != before {
			t.Errorf("%d of %d escrow records survived, want all of them", after, before)
		}
	})

	t.Run("control: vault_app still sweeps at a real horizon", func(t *testing.T) {
		atkRecoveryTruncate(t, owner)
		atkRecoverySeed(t, app, 90*24*time.Hour, 40*24*time.Hour, time.Hour)

		var deleted int64
		if err := app.QueryRow(ctx, `SELECT auth.cleanup_old_recovery(interval '30 days')`).Scan(&deleted); err != nil {
			t.Fatalf("the retention sweeper can no longer run as vault_app: %v", err)
		}
		if deleted != 2 {
			t.Errorf("deleted = %d, want 2", deleted)
		}
		if remaining := atkRecoveryCount(t, owner); remaining != 1 {
			t.Errorf("%d escrow records remain, want 1: the sweep crossed its own horizon", remaining)
		}
	})

	t.Run("control: the append-only trigger is enabled after a sweep", func(t *testing.T) {
		var enabled string
		err := owner.QueryRow(ctx, `
			SELECT tgenabled FROM pg_trigger
			WHERE tgname = 'account_recovery_no_delete'
			  AND tgrelid = 'auth.account_recovery'::regclass`).Scan(&enabled)
		if err != nil {
			t.Fatalf("read trigger state: %v", err)
		}
		if enabled == "D" {
			t.Fatal("account_recovery_no_delete is still disabled after a sweep, so the escrow is no " +
				"longer append-only for anyone")
		}
		if _, err := app.Exec(ctx, `DELETE FROM auth.account_recovery`); !atkRecoveryPermissionDenied(err) {
			t.Errorf("vault_app deleted escrow rows directly: err = %v", err)
		}
	})
}

// atkRecoveryPermissionDenied reports whether err is PostgreSQL's
// insufficient_privilege. Matching the SQLSTATE rather than the message text so
// a server speaking another language still answers the question.
func atkRecoveryPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
