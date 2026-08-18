package integration_test

// must_reset_password on auth.users, under the roles the services connect as.
//
// The column is the forced-password-reset flag: while it is true the password
// path refuses the account and mails a reset link instead of issuing a session
// (internal/service/auth.go, the MustResetPassword branch of Login). It is the
// legacy-migration lever -- an account imported with a hash vault42 cannot verify
// has no usable credential, and the flag is what turns that into "we emailed you
// a reset" instead of a permanent, silent refusal -- but nothing about it is
// import-specific, and an operator may carry any account into the state.
//
// Which role may move it in which direction is the whole of this file. Setting it
// is an administrative act with the same shape as a ban: one UPDATE with no WHERE
// puts every account in the deployment through a forced reset and mails all of
// them, so it belongs to the admin plane, exactly where 024 and 029 put the rest
// of the account-state set. Clearing it is the application role's own work,
// because the password-reset handler that clears it runs in the web server under
// vault_app.
//
// These tests exercise the real roles with the real grants, because the shared
// fixture strips the privilege model before a test can see it.

import (
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// forcedResetRefused reports whether err is the direction guard refusing a write.
// Deliberately distinct from permissionDenied, for the reason
// postgres_account_state_flags_test.go gives: a column the role still holds is
// refused by the trigger and names the transition, a column it does not hold is
// refused by PostgreSQL with 42501, and a test that accepted either would not
// notice the two swapping places.
func forcedResetRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "forced password reset")
}

func TestForcedPasswordResetIsSetByTheAdminPlaneAndClearedByTheApplicationRole(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	ownerDB := &postgres.DB{Pool: adminPool}
	appPool := appRolePool(t, adminPool)
	gatewayPool := adminRolePool(t, adminPool)

	flagOf := func(t *testing.T, id string) bool {
		t.Helper()
		var flag bool
		if err := adminPool.QueryRow(ctx,
			`SELECT must_reset_password FROM auth.users WHERE id = $1`, id).Scan(&flag); err != nil {
			t.Fatalf("read must_reset_password: %v", err)
		}
		return flag
	}

	t.Run("a new account is not carrying a forced reset", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-default@test.com")
		if flagOf(t, u.ID) {
			t.Error("must_reset_password defaulted to TRUE, which refuses the password login of " +
				"every account created before an operator asked for anything")
		}
	})

	t.Run("the admin plane can force a reset", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-admin-set@test.com")
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("the admin plane cannot force a password reset, so the flag has no writer: %v", err)
		}
		if !flagOf(t, u.ID) {
			t.Error("the write reported success but the column did not move")
		}
	})

	t.Run("the admin plane can lift a forced reset", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-admin-clear@test.com")
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("seed the forced reset: %v", err)
		}
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = FALSE WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("the admin plane cannot lift a forced reset it imposed: %v", err)
		}
		if flagOf(t, u.ID) {
			t.Error("the write reported success but the column did not move")
		}
	})

	t.Run("the application role cannot force a reset", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-app-set@test.com")
		_, err := appPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID)
		if !forcedResetRefused(err) {
			t.Fatalf("vault_app forced a password reset: err = %v.\n"+
				"The same statement without a WHERE refuses the password login of every account "+
				"in the deployment and mails all of them, and no vault_app code path sets this "+
				"column at all.", err)
		}
	})

	t.Run("the application role can clear a forced reset", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-app-clear@test.com")
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("seed the forced reset: %v", err)
		}
		if _, err := appPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = FALSE, updated_at = NOW() WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("vault_app cannot clear the flag, so completing a password reset can never "+
				"lift it and the account is locked out of password login forever: %v", err)
		}
		if flagOf(t, u.ID) {
			t.Error("the write reported success but the column did not move")
		}
	})

	// The repository is the only thing that reads and writes this column in
	// production, so the SQL above proves nothing about the feature unless the two
	// statements the server actually issues agree with it.
	t.Run("the import carries the flag in and the repository reads it back", func(t *testing.T) {
		gatewayDB := &postgres.DB{Pool: gatewayPool}
		imported := makeUser("forced-import@test.com")
		imported.ImportedFrom = "legacy"
		imported.LegacyID = randomID()
		imported.MustResetPassword = true
		if err := postgres.NewUserRepo(gatewayDB).CreateImported(ctx, imported); err != nil {
			t.Fatalf("POST /admin/users/import cannot flag an imported account: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByEmail(ctx, "forced-import@test.com")
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.MustResetPassword {
			t.Fatal("the import wrote the flag but GetByEmail does not read it, so Login can " +
				"never see the state and the account is refused with no explanation")
		}
	})

	t.Run("a completed reset clears the flag through the repository", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-repo-clear@test.com")
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("seed the forced reset: %v", err)
		}
		app := postgres.NewUserRepo(&postgres.DB{Pool: appPool})
		if err := app.ClearMustResetPassword(ctx, u.ID); err != nil {
			t.Fatalf("vault_app cannot clear the flag, so a completed password reset can never "+
				"lift it: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if got.MustResetPassword {
			t.Error("ClearMustResetPassword reported success but the column did not move")
		}
	})

	// A forced reset is not one-way, unlike import_pending: an operator who sets
	// it by mistake, or whose reason has passed, must be able to take it off, and
	// the account may enter the state again later.
	t.Run("an account can be carried into the state twice", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-recycle@test.com")
		for i := 0; i < 2; i++ {
			if _, err := gatewayPool.Exec(ctx,
				`UPDATE auth.users SET must_reset_password = TRUE WHERE id = $1`, u.ID); err != nil {
				t.Fatalf("round %d: forcing a reset again is refused, so the flag is one-way: %v", i, err)
			}
			if _, err := appPool.Exec(ctx,
				`UPDATE auth.users SET must_reset_password = FALSE, updated_at = NOW() WHERE id = $1`, u.ID); err != nil {
				t.Fatalf("round %d: clearing: %v", i, err)
			}
		}
	})
}
