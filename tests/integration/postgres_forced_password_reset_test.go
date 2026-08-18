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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
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

	// The operator route writes through UserRepo.SetMustResetPassword under the
	// gateway's role. Migration 039 granted vault_admin UPDATE
	// (must_reset_password) before any route existed to use it, so this is the
	// test that the grant is real rather than assumed, and that the statement the
	// route issues is one the direction trigger admits from this role.
	t.Run("the admin plane imposes a forced reset through the repository", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-repo-set@test.com")
		gateway := postgres.NewUserRepo(&postgres.DB{Pool: gatewayPool})
		if err := gateway.SetMustResetPassword(ctx, u.ID, true); err != nil {
			t.Fatalf("the admin plane cannot impose a forced reset through the repository, so the "+
				"operator route has no writer and the flag is reachable only through an import: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.MustResetPassword {
			t.Error("SetMustResetPassword reported success but GetByID does not see the flag, so " +
				"Login never will either and the operator's forced reset does nothing at all")
		}
	})

	// The application role must not reach the setter, whichever Go call site
	// holds it. The interface is shared by both planes, so the database is the
	// only thing that keeps the direction rule, and this is it being kept.
	t.Run("the application role cannot impose a forced reset through the repository", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "forced-repo-app-set@test.com")
		app := postgres.NewUserRepo(&postgres.DB{Pool: appPool})
		if err := app.SetMustResetPassword(ctx, u.ID, true); !forcedResetRefused(err) {
			t.Fatalf("vault_app imposed a forced reset through the repository: err = %v.\n"+
				"The setter sits on the interface both planes hold, so the trigger is the only "+
				"thing separating them, and it just let the web server ban every password login "+
				"in the deployment.", err)
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

	// The operator routes, end to end, over the real column under the real role.
	//
	// The unit tests in internal/adminapi drive these handlers against a mock, so
	// what they prove is that the route calls the repository and audits it. What
	// they cannot prove is that the call lands: that vault_admin actually holds
	// the privilege migration 039 granted, that the direction trigger admits the
	// statement from the gateway's role, and that the column the route writes is
	// the one GetByID reads into model.User.MustResetPassword -- the field
	// AuthService.Login branches on. That last hop is what turns "the route
	// answered 200" into "the next login for this account is refused and mailed
	// a reset link".
	t.Run("the operator routes move the flag Login reads", func(t *testing.T) {
		gatewayDB := &postgres.DB{Pool: gatewayPool}
		users := postgres.NewUserRepo(gatewayDB)
		h := adminapi.NewHandler(
			users, postgres.NewClientRepo(gatewayDB), postgres.NewRefreshTokenRepo(gatewayDB),
			postgres.NewAuditRepo(gatewayDB), postgres.NewAdminUserRepo(gatewayDB),
			postgres.NewAdminSessionRepo(gatewayDB), postgres.NewAdminConfigRepo(gatewayDB),
			nil, audit.NewLogger(postgres.NewAuditRepo(gatewayDB), 0), make([]byte, 32), "",
		)

		u := seedAccountStateUser(t, ctx, ownerDB, "forced-route@test.com")
		call := func(t *testing.T, handler func(http.ResponseWriter, *http.Request), path, body string) map[string]any {
			t.Helper()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.SetPathValue("id", u.ID)
			r = r.WithContext(adminapi.WithAdmin(ctx, &model.AdminUser{ID: "adm-1", Username: "root"}))
			rec := httptest.NewRecorder()
			handler(rec, r)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			var out map[string]any
			if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
				t.Fatalf("decode: %v", err)
			}
			return out
		}

		out := call(t, h.RequirePasswordReset, "/admin/users/"+u.ID+"/require-password-reset",
			`{"reason":"legacy hash cannot be verified"}`)
		// Pinned as false, and that is a finding rather than a design.
		//
		// The route asks RevokeAllForUser to end the account's live sessions,
		// because POST /auth/refresh does not read must_reset_password and a
		// session that already exists would otherwise rotate straight past the
		// forced reset. Under the gateway's own role that write is refused:
		// vault_admin holds SELECT (001) and DELETE (009) on auth.refresh_tokens
		// and no UPDATE, so `UPDATE auth.refresh_tokens SET revoked = TRUE`
		// answers 42501 and the handler reports sessions_revoked=false -- which is
		// the honest answer, and the reason the field is in the response at all.
		//
		// POST /admin/users/{id}/lock has the same gap, and has had it since 009:
		// its own comment calls the revocation "what makes containment immediate",
		// and in a real deployment it revokes nothing. The fix is one grant --
		// UPDATE (revoked) on auth.refresh_tokens for vault_admin, which widens
		// nothing, since DELETE on the same table is already held -- and it is a
		// migration, so it is not smuggled in with a route. When it lands, this
		// assertion flips to true and this comment comes out.
		if out["sessions_revoked"] != false {
			t.Errorf("sessions_revoked = %v, want false: the gateway role has been granted "+
				"UPDATE on auth.refresh_tokens since this was written. Flip this assertion, "+
				"and check that POST /admin/users/{id}/lock is asserted to revoke too.",
				out["sessions_revoked"])
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.MustResetPassword {
			t.Fatal("the route answered 200 and the column Login reads is still false, so the " +
				"account it was aimed at signs in with the password the operator just distrusted")
		}

		call(t, h.ClearPasswordReset, "/admin/users/"+u.ID+"/clear-password-reset", `{"reason":"resolved"}`)
		got, err = postgres.NewUserRepo(ownerDB).GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if got.MustResetPassword {
			t.Error("the demand was reported withdrawn and the account is still refused")
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
