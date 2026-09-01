package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestVaultAppCannotHardDeleteAUser proves migration 041 holds against the real
// role with the real grants.
//
// It has to run here rather than in a unit test, and it has to run as vault_app
// rather than as the container owner, because the thing being asserted is a
// privilege and nothing else. There is no Go code to break: UserRepo has no
// Delete method, so a mock cannot express this and a repository test cannot
// reach it. The statement below is the one an attacker with SQL injection or the
// application credentials would send, and the only thing standing in front of it
// is the grant.
//
// The suite's default fixture is exactly the wrong tool for that. It connects as
// the container owner, a superuser no grant applies to, and stripRoleGrants()
// deletes every GRANT and REVOKE before applying the migrations -- so the
// privilege model is not merely untested there, it is absent. applyRealGrants
// puts it back and appRolePool connects as the role it constrains. That
// combination is what caught a dead erasure path once already.
func TestVaultAppCannotHardDeleteAUser(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)
	ctx := context.Background()

	victim := randomID()
	if _, err := adminPool.Exec(ctx,
		`INSERT INTO auth.users (id, email, display_name, created_at)
		 VALUES ($1, $2, $3, $4)`,
		victim, "victim-"+victim+"@example.com", "Real Name", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The whole point: one statement, no escrow, no tombstone, no audit entry,
	// and the ON DELETE CASCADE that the erasure path is written to avoid.
	_, err := appPool.Exec(ctx, `DELETE FROM auth.users WHERE id = $1`, victim)
	if err == nil {
		t.Fatal("vault_app deleted a user row outright. That destroys the account with no " +
			"recovery escrow, no tombstone for the login and refresh paths to check, no " +
			"AccountErased audit entry, and it fires the ON DELETE CASCADE onto " +
			"totp_secrets, webauthn_credentials, backup_codes and login_countries that " +
			"ErasureService deletes explicitly precisely because the cascade never runs " +
			"on its UPDATE. Migration 041 revokes this.")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("DELETE failed, but not on privilege: %v. The test proves nothing unless "+
			"the refusal comes from the grant.", err)
	}

	// A refusal that also loses the row would be the wrong kind of pass.
	var alive bool
	if err := adminPool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.users WHERE id = $1)`, victim).Scan(&alive); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !alive {
		t.Error("the DELETE was refused and the row is gone anyway")
	}

	// The privileges the application actually uses have to survive the revoke, or
	// this migration trades one outage for one defect. INSERT and SELECT stay.
	newUser := randomID()
	if _, err := appPool.Exec(ctx,
		`INSERT INTO auth.users (id, email, created_at) VALUES ($1, $2, $3)`,
		newUser, "new-"+newUser+"@example.com", time.Now()); err != nil {
		t.Fatalf("vault_app can no longer INSERT a user, so 041 revoked too much: %v", err)
	}
	var readable bool
	if err := appPool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.users WHERE id = $1)`, newUser).Scan(&readable); err != nil {
		t.Fatalf("vault_app can no longer SELECT a user, so 041 revoked too much: %v", err)
	}
	if !readable {
		t.Error("vault_app inserted a user it cannot read back")
	}
}
