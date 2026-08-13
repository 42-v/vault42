package attack

// Finding: the admin-role-escalation backstop guards UPDATE but not INSERT, so a
// statement running as vault_admin can mint a fresh super_admin the trigger never
// sees.
//
// Migration 001 installs auth.deny_role_escalation as a BEFORE UPDATE trigger on
// auth.admin_users and comments it as the SQL-injection backstop: "even if SQL
// injection reaches the DB, a lower-ranked admin cannot promote themselves to a
// higher rank." The trigger fires on UPDATE only (001 line 411-413). The admin
// gateway connects as vault_admin, which 001 grants full INSERT/UPDATE/DELETE on
// auth.admin_users (line 430). So the three routes to a super_admin row are:
//
//   * UPDATE an existing row's role upward        -> trigger fires, blocked.
//   * INSERT ... ON CONFLICT DO UPDATE (role up)  -> fires the UPDATE trigger, blocked.
//   * INSERT a brand-new super_admin row          -> NO trigger. Succeeds.
//
// The third is the hole. An attacker who reaches the database as vault_admin
// (the standing threat the trigger exists for) does not need to promote their own
// row, which is what the trigger stops; they insert a new super_admin with a
// password hash they chose and log in as it. DELETE-then-INSERT of one's own row
// is the same hole reached differently.
//
// Honest scope: turning this into privilege escalation needs a SQL-injection sink
// in a vault_admin query, and the admin-gateway repositories this suite reviewed
// are all parameterised, so no live injection is demonstrated here. What is proven
// is narrower and still real: the DB-level control the migration advertises as the
// injection backstop does not cover the INSERT path, so it is worth exactly as
// much as the parameterised queries in front of it and no more. This test encodes
// the invariant the comment claims ("SQL as vault_admin cannot mint a higher
// rank") and shows precisely which path violates it.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAdminEscalationTriggerIgnoresInsert(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	// The role the admin gateway actually runs as, with the grants migration 001
	// actually makes.
	gateway := atkDBRolePool(t, owner, "vault_admin")

	// A pre-existing low-rank admin: the "attacker" whose session reaches the DB.
	operatorID := atkDBRandomID(t)
	if _, err := owner.Exec(ctx,
		`INSERT INTO auth.admin_users (id, username, password_hash, role) VALUES ($1, $2, $3, 'operator')`,
		operatorID, "atk-operator", "$argon2id$known-to-attacker"); err != nil {
		t.Fatalf("seed operator admin: %v", err)
	}

	isEscalationBlocked := func(err error) bool {
		// The trigger raises with this message; a permission error (42501) would be a
		// different, weaker control and must not count as the trigger doing its job.
		return err != nil && strings.Contains(err.Error(), "role escalation denied")
	}

	// Control 1: in-place promotion via UPDATE is blocked. This is the path the
	// trigger was written for and it holds. Passing here is what proves the INSERT
	// result below is a genuine gap in the same control, not a broken fixture.
	t.Run("UPDATE promotion is blocked (control)", func(t *testing.T) {
		_, err := gateway.Exec(ctx,
			`UPDATE auth.admin_users SET role = 'super_admin' WHERE id = $1`, operatorID)
		if !isEscalationBlocked(err) {
			t.Fatalf("expected the escalation trigger to block an UPDATE promotion, got err = %v", err)
		}
	})

	// Control 2: ON CONFLICT DO UPDATE is an insert-shaped statement that still
	// fires the UPDATE trigger, so it is blocked too. Verifying this rules out the
	// obvious "did they just forget ON CONFLICT" reading and isolates the gap to a
	// plain INSERT.
	t.Run("INSERT ON CONFLICT DO UPDATE promotion is blocked (control)", func(t *testing.T) {
		_, err := gateway.Exec(ctx, `
			INSERT INTO auth.admin_users (id, username, password_hash, role)
			VALUES ($1, 'atk-operator-conflict', '$argon2id$x', 'viewer')
			ON CONFLICT (id) DO UPDATE SET role = 'super_admin'`, operatorID)
		if !isEscalationBlocked(err) {
			t.Fatalf("expected the escalation trigger to block ON CONFLICT DO UPDATE, got err = %v", err)
		}
	})

	// Control 3: the blunt escape hatch, disabling triggers for the session, is a
	// superuser-only GUC. vault_admin is not a superuser, so this must fail. If it
	// ever stops failing the whole trigger model is moot.
	t.Run("session_replication_role cannot be flipped by vault_admin (control)", func(t *testing.T) {
		if _, err := gateway.Exec(ctx, `SET session_replication_role = 'replica'`); err == nil {
			t.Error("vault_admin set session_replication_role=replica: it can disable every trigger at will")
		}
	})

	// The finding: a brand-new super_admin inserted as vault_admin is accepted,
	// because no trigger guards INSERT. The invariant the migration advertises is
	// that SQL reaching the DB cannot mint a higher rank; this asserts that
	// invariant and therefore FAILS today.
	t.Run("INSERT of a new super_admin is NOT blocked (finding)", func(t *testing.T) {
		newAdminID := atkDBRandomID(t)
		_, err := gateway.Exec(ctx, `
			INSERT INTO auth.admin_users (id, username, password_hash, role, created_by)
			VALUES ($1, 'atk-backdoor', '$argon2id$attacker-chosen', 'super_admin', $2)`,
			newAdminID, operatorID)
		if err != nil {
			// The desired outcome: the write was refused. If a future BEFORE INSERT
			// guard lands, this branch is where it shows up and the test goes green.
			if isEscalationBlocked(err) || strings.Contains(err.Error(), "42501") ||
				strings.Contains(err.Error(), "permission denied") {
				return
			}
			t.Fatalf("INSERT failed for an unrelated reason: %v", err)
		}

		// It went in. Confirm the super_admin row is really there and usable.
		if !superAdminExists(t, ctx, owner, newAdminID) {
			t.Fatalf("INSERT reported success but the super_admin row is not present")
		}
		t.Errorf("vault_admin minted a new super_admin via a plain INSERT: the role-escalation " +
			"trigger guards UPDATE only, so the DB-level SQL-injection backstop does not cover " +
			"the INSERT path (auth.admin_users_no_escalation is BEFORE UPDATE, migration 001)")
	})
}

func superAdminExists(t *testing.T, ctx context.Context, owner *pgxpool.Pool, id string) bool {
	t.Helper()
	var role string
	err := owner.QueryRow(ctx, `SELECT role FROM auth.admin_users WHERE id = $1`, id).Scan(&role)
	if err != nil {
		return false
	}
	return role == "super_admin"
}
