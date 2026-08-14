package integration_test

// The privileged account-state columns of auth.users, under the roles the
// services connect as.
//
// 015 closed the tombstone columns (email, deleted, deleted_at) for vault_app.
// What 004 and 006 left open is the rest of the account-state set: banned,
// ban_reason, disabled, email_verified and import_pending. Every one of them
// decides whether an account may authenticate, and the login gate reads all of
// them (internal/service/auth.go: deleted and import_pending instead of the
// password check, banned, disabled and email_verified after it -- banned and
// disabled are revealed only to a caller who proved the password, so they cannot
// be used to enumerate accounts).
//
// A blanket REVOKE is wrong for two of the five, which is what makes this a
// per-transition question rather than a privilege question. UserRepo clears
// import_pending when an imported account is claimed (user.go:73) and sets
// email_verified when an address is confirmed (user.go:202). Each moves in one
// direction only, and no path anywhere moves either one back.
//
// These tests exercise the real roles with the real grants, because the shared
// fixture strips the privilege model before a test can see it. They are the pair
// to tests/attack/atk_db_*, which cannot be extended from here.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// accountStateRefused reports whether err is the transition guard refusing a
// write. It is deliberately distinct from permissionDenied: a column the role
// still holds is refused by the trigger and names the transition, while a column
// the role no longer holds is refused by PostgreSQL with 42501. Both are the
// right answer for different columns, and a test that accepted either would not
// notice the two swapping places.
func accountStateRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "account state transition denied")
}

func seedAccountStateUser(t *testing.T, ctx context.Context, owner *postgres.DB, email string) *model.User {
	t.Helper()
	u := makeUser(email)
	if err := postgres.NewUserRepo(owner).Create(ctx, u); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return u
}

func TestVaultAppCannotFlipThePrivilegedAccountStateColumns(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	ownerDB := &postgres.DB{Pool: adminPool}
	appPool := appRolePool(t, adminPool)
	app := postgres.NewUserRepo(&postgres.DB{Pool: appPool})

	// Banning and disabling have no UPDATE writer anywhere in the tree. 004
	// granted the columns to vault_app on the way past and nothing ever used
	// them, so the privilege is surplus and comes off rather than being guarded.
	t.Run("the application role cannot ban an account", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-ban@test.com")
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET banned = TRUE WHERE id = $1`, u.ID)
		if !permissionDenied(err) {
			t.Fatalf("vault_app banned an account: err = %v.\n"+
				"The same statement without a WHERE bans every account in the deployment, "+
				"and no code path writes this column by UPDATE at all.", err)
		}
	})

	t.Run("the application role cannot lift a ban", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-unban@test.com")
		if _, err := adminPool.Exec(ctx,
			`UPDATE auth.users SET banned = TRUE, ban_reason = 'abuse' WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("seed the ban: %v", err)
		}
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET banned = FALSE WHERE id = $1`, u.ID)
		if !permissionDenied(err) {
			t.Fatalf("vault_app lifted a ban: err = %v.\n"+
				"Control of password_hash does not reach a banned row, because the account-state "+
				"gate refuses it before any credential is read.", err)
		}
	})

	t.Run("the application role cannot rewrite the recorded ban reason", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-banreason@test.com")
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET ban_reason = 'nothing to see' WHERE id = $1`, u.ID)
		if !permissionDenied(err) {
			t.Fatalf("vault_app rewrote a ban reason: err = %v", err)
		}
	})

	t.Run("the application role cannot disable an account", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-disable@test.com")
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET disabled = TRUE WHERE id = $1`, u.ID)
		if !permissionDenied(err) {
			t.Fatalf("vault_app disabled an account: err = %v", err)
		}
	})

	// email_verified: the privilege stays, because confirming an address is
	// vault_app's own job. Only the direction is constrained.
	t.Run("confirming an address is still permitted", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-verify@test.com")
		if err := app.VerifyEmail(ctx, u.ID); err != nil {
			t.Fatalf("vault_app cannot verify an email, so email confirmation is dead in production: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.EmailVerified {
			t.Error("VerifyEmail reported success but the column did not move")
		}
	})

	t.Run("un-confirming a verified address is refused", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-unverify@test.com")
		if err := app.VerifyEmail(ctx, u.ID); err != nil {
			t.Fatalf("seed the verification: %v", err)
		}
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET email_verified = FALSE WHERE id = $1`, u.ID)
		if !accountStateRefused(err) {
			t.Fatalf("vault_app un-verified a confirmed address: err = %v.\n"+
				"An unverified row cannot log in and cannot be linked to a social identity, "+
				"so this is a per-account lockout with no writer behind it.", err)
		}
	})

	// import_pending: same shape, opposite direction. Claiming an imported
	// account clears it once and nothing sets it again.
	t.Run("claiming an imported account is still permitted", func(t *testing.T) {
		imported := makeUser("state-import-claim@test.com")
		imported.ImportedFrom = "legacy"
		imported.LegacyID = randomID()
		if err := postgres.NewUserRepo(ownerDB).CreateImported(ctx, imported); err != nil {
			t.Fatalf("seed imported user: %v", err)
		}
		if err := app.ClearImportPending(ctx, imported.ID); err != nil {
			t.Fatalf("vault_app cannot claim an imported account, so the import flow is dead in production: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, imported.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if got.ImportPending {
			t.Error("ClearImportPending reported success but the column did not move")
		}
	})

	t.Run("re-arming import_pending on a claimed account is refused", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-import-rearm@test.com")
		_, err := appPool.Exec(ctx, `UPDATE auth.users SET import_pending = TRUE WHERE id = $1`, u.ID)
		if !accountStateRefused(err) {
			t.Fatalf("vault_app re-armed import_pending on a claimed account: err = %v.\n"+
				"Login then ignores the password, answers every attempt with invalid_credentials "+
				"and mails a claim link, which is a lockout the account holder cannot clear.", err)
		}
	})

	// An imported account still arrives banned or disabled when the source system
	// says so. That is an INSERT by the admin gateway, which the guard does not
	// touch: the rule is about transitions, and a new row has none.
	t.Run("an imported account still arrives with the source system's ban", func(t *testing.T) {
		gatewayDB := &postgres.DB{Pool: adminRolePool(t, adminPool)}
		imported := makeUser("state-import-banned@test.com")
		imported.Banned = true
		imported.BanReason = "banned upstream"
		imported.Disabled = true
		imported.ImportedFrom = "legacy"
		imported.LegacyID = randomID()
		if err := postgres.NewUserRepo(gatewayDB).CreateImported(ctx, imported); err != nil {
			t.Fatalf("POST /admin/users/import is broken in every deployment: %v", err)
		}
		got, err := postgres.NewUserRepo(ownerDB).GetByID(ctx, imported.ID)
		if err != nil || got == nil {
			t.Fatalf("read back: %v", err)
		}
		if !got.Banned || !got.Disabled || got.BanReason != "banned upstream" {
			t.Errorf("import lost the source system's account state: banned=%v disabled=%v reason=%q",
				got.Banned, got.Disabled, got.BanReason)
		}
	})

	// locked_until is deliberately not narrowed, and this pins that decision so a
	// later change to it is a deliberate one. `vault lock-user` and
	// `vault unlock-user` (internal/cli/cli.go:263 and :277) run inside cmd/vault,
	// which connects with cfg.DatabaseURL("app"), so clearing a live lock is a
	// path vault_app genuinely takes.
	t.Run("locking and unlocking stay open to the application role", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-lock@test.com")
		if err := app.LockUntil(ctx, u.ID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("vault lock-user is broken in every deployment: %v", err)
		}
		if err := app.Unlock(ctx, u.ID); err != nil {
			t.Fatalf("vault unlock-user is broken in every deployment: %v", err)
		}
	})

	// The admin plane keeps the lock/unlock pair 001 documents as its only write
	// to this table outside erasure, and gains nothing else here.
	t.Run("the admin plane keeps lock and unlock and no more", func(t *testing.T) {
		u := seedAccountStateUser(t, ctx, ownerDB, "state-gateway-lock@test.com")
		gatewayPool := adminRolePool(t, adminPool)
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET locked_until = NOW() + INTERVAL '1 hour' WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("POST /admin/users/{id}/lock is broken in every deployment: %v", err)
		}
		if _, err := gatewayPool.Exec(ctx,
			`UPDATE auth.users SET locked_until = NULL, failed_login_count = 0 WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("POST /admin/users/{id}/unlock is broken in every deployment: %v", err)
		}
		if _, err := gatewayPool.Exec(ctx, `UPDATE auth.users SET banned = TRUE WHERE id = $1`, u.ID); !permissionDenied(err) {
			t.Fatalf("vault_admin banned an account: 004 granted the column to vault_app only: err = %v", err)
		}
	})
}
