package integration_test

// banned and ban_reason on auth.users, under the roles the services connect as.
//
// The read side of the ban has worked since 004: Login answers 403
// account_banned, so do the OAuth2 authorize path, the MFA continuation and the
// password-reset confirm, and the frontend renders the code in every locale it
// ships. The write side had no owner. 004 granted both columns to vault_app;
// 024 revoked them, and said of ban_reason that "it has no writer either"; the
// only thing that has set either since is POST /admin/users/import, which
// carries the flag in its INSERT and never issues an UPDATE. An account could
// arrive banned from a legacy platform and never be unbanned.
//
// Migration 043 gives the columns their writer: vault_admin gains
// UPDATE (banned, ban_reason), which is what the two operator routes issue
// through UserRepo.SetBanned. This file is the test that the grant is real
// rather than assumed -- the shared fixture strips the privilege model, so
// nothing else in the suite would notice its absence -- and that 024's revoke
// still holds against the role that lost it.

import (
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestBanIsWrittenByTheAdminPlaneAndStillRefusedToTheApplicationRole(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	ownerDB := &postgres.DB{Pool: adminPool}
	appPool := appRolePool(t, adminPool)
	gatewayPool := adminRolePool(t, adminPool)
	gateway := postgres.NewUserRepo(&postgres.DB{Pool: gatewayPool})
	owner := postgres.NewUserRepo(ownerDB)

	stateOf := func(t *testing.T, id string) (bool, string) {
		t.Helper()
		var banned bool
		var reason *string
		if err := adminPool.QueryRow(ctx,
			`SELECT banned, ban_reason FROM auth.users WHERE id = $1`, id).Scan(&banned, &reason); err != nil {
			t.Fatalf("read ban state: %v", err)
		}
		if reason == nil {
			return banned, ""
		}
		return banned, *reason
	}

	t.Run("a new account is not banned and carries no reason", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-default@test.com")
		banned, reason := stateOf(t, u.ID)
		if banned || reason != "" {
			t.Errorf("a fresh account is banned=%v reason=%q", banned, reason)
		}
	})

	// The grant test. Migration 043 exists for this statement and nothing else,
	// and it is written bare rather than inside a pg_roles guard precisely so
	// applyRealGrants above picks it up -- a guarded grant is skipped by that
	// fixture, which would leave this whole file running against the owner's
	// privileges and passing whether or not the grant shipped.
	t.Run("the admin plane bans through the repository", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-repo-set@test.com")
		if err := gateway.SetBanned(ctx, u.ID, true, "payment fraud, ticket OPS-4471"); err != nil {
			t.Fatalf("the admin plane cannot ban through the repository, so POST /admin/users/{id}/ban "+
				"answers 500 in any deployment running as the real role and the ban columns keep the "+
				"no-writer state 024 left them in: %v", err)
		}
		banned, reason := stateOf(t, u.ID)
		if !banned {
			t.Error("SetBanned reported success but banned did not move, so Login never refuses the account")
		}
		if reason != "payment fraud, ticket OPS-4471" {
			t.Errorf("ban_reason = %q, want the operator's text: it is what an operator reads back "+
				"off GET /admin/users/{id} to know why the account is shut", reason)
		}
	})

	// Lifting clears both columns. A reason left behind on an account that is no
	// longer banned reads as one that is, on the record an operator consults.
	t.Run("the admin plane lifts a ban and the reason goes with it", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-repo-clear@test.com")
		if err := gateway.SetBanned(ctx, u.ID, true, "under investigation"); err != nil {
			t.Fatalf("seed the ban: %v", err)
		}
		if err := gateway.SetBanned(ctx, u.ID, false, ""); err != nil {
			t.Fatalf("the admin plane cannot lift a ban it imposed, which is the state the feature "+
				"exists to end: %v", err)
		}
		banned, reason := stateOf(t, u.ID)
		if banned {
			t.Error("the unban reported success but banned did not move")
		}
		if reason != "" {
			t.Errorf("ban_reason = %q after the ban was lifted", reason)
		}
	})

	// A reason passed on an unban is dropped by the repository rather than
	// stored, so no call site can leave an explanation attached to an account
	// that is not sanctioned.
	t.Run("a reason given on an unban is not stored", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-unban-reason@test.com")
		if err := gateway.SetBanned(ctx, u.ID, true, "spam"); err != nil {
			t.Fatalf("seed the ban: %v", err)
		}
		if err := gateway.SetBanned(ctx, u.ID, false, "appeal upheld"); err != nil {
			t.Fatalf("unban: %v", err)
		}
		if banned, reason := stateOf(t, u.ID); banned || reason != "" {
			t.Errorf("banned=%v reason=%q, want a cleared account", banned, reason)
		}
	})

	// The route bounds the operator's text at 200 runes before it reaches here.
	// The column is VARCHAR(500) and counts characters, so the bound has margin
	// -- but PostgreSQL refuses an over-long value outright rather than
	// truncating it, which would fail the whole UPDATE and lose the ban, so the
	// margin is worth holding rather than assuming.
	t.Run("a reason at the route's bound fits the column", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-long-reason@test.com")
		if err := gateway.SetBanned(ctx, u.ID, true, strings.Repeat("é", 200)); err != nil {
			t.Fatalf("a 200-rune reason was refused by ban_reason VARCHAR(500): %v", err)
		}
		if _, reason := stateOf(t, u.ID); len([]rune(reason)) != 200 {
			t.Errorf("stored reason is %d runes, want 200 -- the column truncated where it should "+
				"have fitted", len([]rune(reason)))
		}
	})

	// 043 grants the admin plane and nobody else. If it ever widens to the
	// application role, one UPDATE with no WHERE from the web server sanctions
	// every account in the deployment -- which is exactly the argument 024 made
	// when it took the privilege away.
	t.Run("the application role still cannot ban", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-app-set@test.com")
		if _, err := appPool.Exec(ctx,
			`UPDATE auth.users SET banned = TRUE WHERE id = $1`, u.ID); !permissionDenied(err) {
			t.Fatalf("vault_app banned an account: err = %v.\n"+
				"024 revoked this privilege and 043 must not have handed it back.", err)
		}
		if _, err := appPool.Exec(ctx,
			`UPDATE auth.users SET ban_reason = 'x' WHERE id = $1`, u.ID); !permissionDenied(err) {
			t.Fatalf("vault_app wrote ban_reason: err = %v", err)
		}
	})

	// The repository is the only thing that reads this column in production, so
	// the writes above prove nothing about the feature unless the read the server
	// actually issues agrees with them. This is the path Login takes to the
	// account_banned branch.
	t.Run("the ban reads back through the repository", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "ban-readback@test.com")
		if err := gateway.SetBanned(ctx, u.ID, true, "chargeback ring"); err != nil {
			t.Fatalf("ban: %v", err)
		}
		got, err := owner.GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.Banned {
			t.Fatal("SetBanned wrote the column but GetByID does not see it, so Login never will " +
				"either and the operator's ban does nothing at all")
		}
		if got.BanReason != "chargeback ring" {
			t.Errorf("BanReason = %q, want the operator's text", got.BanReason)
		}
	})
}
