package attack

// Finding: the documented "user identity columns are immutable to the app roles"
// invariant is not enforced by the database. Migration 009 widened the erasure
// grants with blanket column privileges, so both application roles can now write
// email / display_name / avatar_url on any row through any statement, not only the
// tombstone UPDATE the grant was added for.
//
// What the model claims:
//
//   * 001 (auth.users grants) comments the vault_app UPDATE grant as excluding the
//     "immutable columns (id, email, created_at)", and comments the vault_admin
//     grant "Admin cannot modify user identity data (password, email, display_name,
//     avatar) ... lock/unlock only".
//   * docs/security.md and the release model repeat it: vault_admin has
//     "column-level UPDATE on users limited to lock/unlock".
//
// What 009 actually does:
//
//   * GRANT UPDATE (email) ON auth.users TO vault_app;                     (009:36)
//   * GRANT UPDATE (email, display_name, avatar_url, deleted, deleted_at,
//       updated_at) ON auth.users TO vault_admin;                          (009:45)
//
// 009's own comment argues the invariant "still holds ... the grants below add
// erasure (delete + tombstone), not arbitrary mutation". That is the claim these
// tests falsify. A GRANT is a standing column privilege; PostgreSQL does not bind
// it to the WHERE clause or the other columns of the statement that motivated it.
// So vault_admin can run `UPDATE auth.users SET email = $evil WHERE id = $victim`
// on a live, non-deleted account, and PostgreSQL accepts it.
//
// Impact: the column-level grants are the DB-layer backstop the architecture
// advertises, the one that is supposed to hold when the service layer is wrong or
// injected. For email / display_name / avatar_url on the user table it no longer
// holds. Changing a victim's email is an account-takeover primitive (password
// reset follows the address); it is now reachable by anything that reaches the DB
// as vault_admin or vault_app, which for the admin plane includes every admin
// tier, since they all share the vault_admin login regardless of RBAC rank.
//
// These tests connect as the real roles with the real grants and issue an
// ordinary, non-erasure UPDATE. The finding assertions FAIL today; the control
// assertions (password_hash still denied, id / created_at still denied) PASS,
// which is what proves the harness is faithful and the loss is specific to the
// three identity columns 009 opened.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// atkDBPermissionDenied reports whether err is a PostgreSQL privilege refusal
// (SQLSTATE 42501), the signal that a column-level grant did its job.
func atkDBPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "42501") || strings.Contains(s, "permission denied")
}

func TestVaultAdminCanModifyUserIdentityData(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	gateway := atkDBRolePool(t, owner, "vault_admin")
	user := atkDBSeedUser(t, owner, "victim-admin-identity@test.com")

	readEmail := func() string { return atkDBReadUserEmail(t, ctx, owner, user.ID) }

	// Finding: a plain, non-erasure email rewrite by vault_admin is accepted. The
	// row is left live (deleted stays FALSE), so this is not the tombstone the
	// grant was justified by. The invariant "admin cannot modify user identity
	// data" says this must be refused; it is not.
	t.Run("email rewrite on a live account is NOT blocked (finding)", func(t *testing.T) {
		_, err := gateway.Exec(ctx,
			`UPDATE auth.users SET email = $2 WHERE id = $1`, user.ID, "takeover@evil.example")
		if atkDBPermissionDenied(err) {
			return // desired: the DB refused it. A future narrowing lands here.
		}
		if err != nil {
			t.Fatalf("email UPDATE failed for an unrelated reason: %v", err)
		}
		if got := readEmail(); got != "takeover@evil.example" {
			t.Fatalf("UPDATE reported success but email is %q", got)
		}
		t.Errorf("vault_admin rewrote a live user's email with no erasure involved; " +
			"the documented 'admin cannot modify user identity data' invariant is not " +
			"enforced at the DB level (migration 009 granted UPDATE(email) to vault_admin)")
	})

	t.Run("display_name and avatar_url rewrites are NOT blocked (finding)", func(t *testing.T) {
		_, err := gateway.Exec(ctx,
			`UPDATE auth.users SET display_name = $2, avatar_url = $3 WHERE id = $1`,
			user.ID, "impersonated", "https://evil.example/a.png")
		if atkDBPermissionDenied(err) {
			return
		}
		if err != nil {
			t.Fatalf("identity UPDATE failed for an unrelated reason: %v", err)
		}
		t.Errorf("vault_admin rewrote a live user's display_name and avatar_url; " +
			"009 granted these columns for the tombstone but the grant is not erasure-scoped")
	})

	// Control: password_hash was never granted to vault_admin, so it stays denied.
	// This is the shape the identity columns above were supposed to keep.
	t.Run("password_hash rewrite is blocked (control)", func(t *testing.T) {
		_, err := gateway.Exec(ctx,
			`UPDATE auth.users SET password_hash = $2 WHERE id = $1`, user.ID, "$argon2id$attacker")
		if !atkDBPermissionDenied(err) {
			t.Errorf("vault_admin changed a user's password hash: err = %v", err)
		}
	})

	// Control: the legitimate lock/unlock column is allowed, confirming the role is
	// wired and the failures above are about column scope, not a dead connection.
	t.Run("locked_until update is allowed (control)", func(t *testing.T) {
		if _, err := gateway.Exec(ctx,
			`UPDATE auth.users SET locked_until = NOW() + INTERVAL '1 hour' WHERE id = $1`, user.ID); err != nil {
			t.Fatalf("vault_admin cannot lock a user, so the role is mis-wired: %v", err)
		}
	})
}

func TestVaultAppCanModifyImmutableEmail(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	app := atkDBRolePool(t, owner, "vault_app")
	user := atkDBSeedUser(t, owner, "victim-app-identity@test.com")

	// Finding: 001 documents email as an immutable column for vault_app; 009
	// granted UPDATE(email). A non-erasure email rewrite by vault_app is accepted.
	t.Run("email rewrite is NOT blocked (finding)", func(t *testing.T) {
		_, err := app.Exec(ctx,
			`UPDATE auth.users SET email = $2 WHERE id = $1`, user.ID, "reassigned@evil.example")
		if atkDBPermissionDenied(err) {
			return
		}
		if err != nil {
			t.Fatalf("email UPDATE failed for an unrelated reason: %v", err)
		}
		if got := atkDBReadUserEmail(t, ctx, owner, user.ID); got != "reassigned@evil.example" {
			t.Fatalf("UPDATE reported success but email is %q", got)
		}
		t.Errorf("vault_app rewrote a user's email; 001 documents email as immutable to " +
			"vault_app but migration 009 granted UPDATE(email), so the DB does not enforce it")
	})

	// Controls: the columns that were never granted stay denied. PostgreSQL refuses
	// the whole statement when a single target column is denied, so these prove the
	// remaining immutable columns really are immutable to vault_app.
	t.Run("id rewrite is blocked (control)", func(t *testing.T) {
		_, err := app.Exec(ctx, `UPDATE auth.users SET id = $2 WHERE id = $1`, user.ID, atkDBRandomID(t))
		if !atkDBPermissionDenied(err) {
			t.Errorf("vault_app changed a user's primary key: err = %v", err)
		}
	})
	t.Run("created_at rewrite is blocked (control)", func(t *testing.T) {
		_, err := app.Exec(ctx, `UPDATE auth.users SET created_at = NOW() WHERE id = $1`, user.ID)
		if !atkDBPermissionDenied(err) {
			t.Errorf("vault_app changed a user's created_at: err = %v", err)
		}
	})
	t.Run("writing auth.admin_users is blocked (control)", func(t *testing.T) {
		_, err := app.Exec(ctx,
			`INSERT INTO auth.admin_users (id, username, password_hash, role) VALUES ($1, $2, $3, 'super_admin')`,
			atkDBRandomID(t), "atk-app-admin", "$argon2id$x")
		if !atkDBPermissionDenied(err) {
			t.Errorf("vault_app wrote the admin table: err = %v", err)
		}
	})
	t.Run("updating auth.clients is blocked (control)", func(t *testing.T) {
		_, err := app.Exec(ctx, `UPDATE auth.clients SET active = FALSE WHERE id = $1`, atkDBRandomID(t))
		if !atkDBPermissionDenied(err) {
			t.Errorf("vault_app updated a client row (001 reserves UPDATE for the admin gateway): err = %v", err)
		}
	})
}

func atkDBReadUserEmail(t *testing.T, ctx context.Context, owner *pgxpool.Pool, id string) string {
	t.Helper()
	var email string
	if err := owner.QueryRow(ctx, `SELECT email FROM auth.users WHERE id = $1`, id).Scan(&email); err != nil {
		t.Fatalf("read user email: %v", err)
	}
	return email
}
