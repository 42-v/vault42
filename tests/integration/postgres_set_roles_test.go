package integration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestSetRolesRunsUnderTheRealAdminRole is what migration 044 exists for.
//
// PUT /admin/users/{id}/roles runs as vault_admin, and PostgreSQL checks the
// column privilege against every target an UPDATE names. vault_admin holds
// column-scoped UPDATE on auth.users -- locked_until and failed_login_count from
// 001, must_reset_password from 039, roles from 044 -- because 015 revoked the
// six columns 009 had lent it. Without the 044 grant the route answers 500 with
// 42501 in any deployment running as the real role, and passes in every test
// that drives the owner pool, which is the shape 040 was written to fix for
// refresh_tokens one table over.
//
// So this drives the real role deliberately. Through the owner pool it would
// pass with or without the migration, and prove nothing about the deployment.
func TestSetRolesRunsUnderTheRealAdminRole(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	applyRealGrants(t, adminPool)
	ctx := context.Background()

	// Seeded through the owner; the write under test is the one below.
	id := randomID()
	if _, err := adminPool.Exec(ctx,
		`INSERT INTO auth.users (id, email, roles, created_at)
		 VALUES ($1, $2, ARRAY['user'], NOW())`,
		id, "roles-"+id+"@example.com"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	repo := postgres.NewUserRepo(&postgres.DB{Pool: adminRolePool(t, adminPool)})

	t.Run("the grant reaches the roles column", func(t *testing.T) {
		if err := repo.SetRoles(ctx, id, []string{"viewer", "operator"}); err != nil {
			t.Fatalf("SetRoles as vault_admin: %v\n"+
				"A 42501 here means migration 044's grant did not run, and the route answers "+
				"500 in any deployment using the real role while every owner-pool test passes.",
				err)
		}
		var roles []string
		if err := adminPool.QueryRow(ctx,
			`SELECT roles FROM auth.users WHERE id = $1`, id).Scan(&roles); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if len(roles) != 2 || roles[0] != "viewer" || roles[1] != "operator" {
			t.Fatalf("roles = %v, want [viewer operator]", roles)
		}
	})

	t.Run("a nil slice clears rather than nulling the column", func(t *testing.T) {
		// roles is NOT NULL DEFAULT '{}' (003), and pgx binds a nil []string as
		// NULL rather than as an empty array -- so without the normalization this
		// is a 23502 not-null violation, not an empty set.
		if err := repo.SetRoles(ctx, id, nil); err != nil {
			t.Fatalf("SetRoles with nil: %v. The column is NOT NULL, so a nil slice has to "+
				"become an empty array before it reaches the statement.", err)
		}
		var roles []string
		if err := adminPool.QueryRow(ctx,
			`SELECT roles FROM auth.users WHERE id = $1`, id).Scan(&roles); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if len(roles) != 0 {
			t.Fatalf("roles = %v, want empty", roles)
		}
	})

	t.Run("the application role cannot set roles", func(t *testing.T) {
		// The other half of the same privilege statement, and the reason this
		// method returns an error at all. 015 revoked from vault_app the six
		// columns 009 had lent it, and 044 grants roles to vault_admin only, so
		// the application role has no writer for the column an admin uses to
		// grant privileges. A deployment where it did would let anything with the
		// app credential promote a user.
		//
		// Driven under the real role deliberately: through the owner pool this
		// write succeeds, which is exactly what makes the privilege model
		// invisible to the rest of the suite.
		appRepo := postgres.NewUserRepo(&postgres.DB{Pool: appRolePool(t, adminPool)})
		err := appRepo.SetRoles(ctx, id, []string{"super_admin"})
		if err == nil {
			t.Fatal("SetRoles succeeded as vault_app. The roles column is how the admin " +
				"plane grants privilege, so the application role must not be able to write " +
				"it: check that 015's revoke still stands and that no later migration " +
				"re-granted roles to vault_app.")
		}
		if !strings.Contains(err.Error(), "set roles") {
			t.Errorf("error = %v, want it wrapped by SetRoles (\"set roles: ...\")", err)
		}
		if !strings.Contains(err.Error(), "42501") && !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error = %v, want a 42501 permission denial rather than some other failure", err)
		}
	})

	t.Run("an id that does not exist is not an error", func(t *testing.T) {
		// Matches the other column-scoped setters: the handler resolves the user
		// before calling this, so a missing row here is not the layer that
		// reports it.
		if err := repo.SetRoles(ctx, randomID(), []string{"viewer"}); err != nil {
			t.Fatalf("SetRoles on an absent id: %v", err)
		}
	})
}
