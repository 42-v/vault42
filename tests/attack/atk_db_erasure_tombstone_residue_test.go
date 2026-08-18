package attack

// Finding: the erasure tombstone leaves credentials and PII on the auth.users row.
//
// Erasure keeps the account row on purpose — every table above it carries a
// foreign key into auth.users, and the account-state gate refuses deleted rows at
// login — so the row is scrubbed in place by auth.erase_user_identity()
// (migration 015). That function writes six columns: email (to the tombstone),
// display_name, avatar_url, deleted, deleted_at, updated_at.
//
// auth.users has grown since. It carries, and kept across every erasure:
//
//   password_hash  the Argon2id hash of the person's password. A credential, and
//                  one people reuse; keeping it after an Art. 17 request is the
//                  single worst item on this list.
//   ban_reason     free text an admin wrote about the person (migration 004).
//   last_login_at  when they last used the service (migration 004).
//   imported_from  which system their account came from (migration 006).
//   legacy_id      their identifier in THAT system — an identifier for the same
//                  person in somebody else's database (migration 006).
//   roles          what they were entitled to; "staff" or a paid tier is a fact
//                  about the person, not about the tombstone (migration 003).
//
// This is the same class as the login-country defect and it arrived the same way:
// columns were added to a table years after the one function that scrubs it was
// written, and nothing tied the two together. It is not caught by asking whether
// erasure REACHES the table — it does — only by asking what it leaves there.
//
// The test tombstones a fully-populated account through the real cascade and then
// reads the row back as the owner. It FAILS before migration 031.

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestErasureTombstoneLeavesCredentialsAndPII(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	appDB := &postgres.DB{Pool: atkDBRolePool(t, owner, "vault_app")}
	user := atkDBSeedUser(t, owner, "victim-tombstone-residue@test.com")

	// Fill in everything the seed helper does not: the columns later migrations
	// added, written as the owner because no application role may set them.
	if _, err := owner.Exec(ctx, `
		UPDATE auth.users
		   SET ban_reason    = 'harassment report filed by another member',
		       last_login_at = NOW(),
		       imported_from = 'legacy',
		       legacy_id     = $2,
		       roles         = ARRAY['user', 'staff']
		 WHERE id = $1`, user.ID, atkDBRandomID(t)); err != nil {
		t.Fatalf("populate late-added columns: %v", err)
	}

	svc := atkDBNewErasureLikeSelfService(appDB)
	if err := svc.DeleteAccount(ctx, user.ID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	var (
		email        string
		deleted      bool
		passwordHash *string
		banReason    *string
		lastLogin    *string
		importedFrom *string
		legacyID     *string
		roles        []string
	)
	if err := owner.QueryRow(ctx, `
		SELECT email, deleted, password_hash, ban_reason, last_login_at::text,
		       imported_from, legacy_id::text, roles
		  FROM auth.users WHERE id = $1`, user.ID).
		Scan(&email, &deleted, &passwordHash, &banReason, &lastLogin,
			&importedFrom, &legacyID, &roles); err != nil {
		t.Fatalf("read tombstoned row: %v", err)
	}

	// Control: the row must still be there, still tombstoned. A "fix" that deleted
	// the row would break every foreign key the tombstone exists to keep valid.
	if !deleted {
		t.Fatalf("the account is not tombstoned; the erasure did not happen and the "+
			"assertions below would prove nothing (email = %q)", email)
	}

	for _, c := range []struct {
		column string
		got    *string
		why    string
	}{
		{"password_hash", passwordHash, "a credential the person may have reused elsewhere"},
		{"ban_reason", banReason, "free text an admin wrote about the person"},
		{"last_login_at", lastLogin, "when the person last used the service"},
		{"imported_from", importedFrom, "which system the person's account came from"},
		{"legacy_id", legacyID, "the person's identifier in another system"},
	} {
		if c.got != nil {
			t.Errorf("auth.users.%s survived the erasure (%s). "+
				"auth.erase_user_identity() scrubs six columns and this is not one of them.",
				c.column, c.why)
		}
	}
	if len(roles) != 0 {
		t.Errorf("auth.users.roles survived the erasure as %v; entitlements such as "+
			"\"staff\" or a paid tier are facts about the person, and the erased account "+
			"cannot authenticate to use them", roles)
	}
}

// TestErasureTombstoneKeepsWhatItMust is the other half. Widening the scrub must
// not touch the columns that keep an erased account erased, or that the state
// trigger from migration 024 refuses to see move backwards.
func TestErasureTombstoneKeepsWhatItMust(t *testing.T) {
	owner, cleanup := atkDBSetupPG(t)
	defer cleanup()
	ctx := context.Background()

	appDB := &postgres.DB{Pool: atkDBRolePool(t, owner, "vault_app")}
	user := atkDBSeedUser(t, owner, "victim-tombstone-keeps@test.com")
	if _, err := owner.Exec(ctx,
		`UPDATE auth.users SET banned = TRUE, email_verified = TRUE WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("seed account state: %v", err)
	}

	svc := atkDBNewErasureLikeSelfService(appDB)
	if err := svc.DeleteAccount(ctx, user.ID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	var banned, emailVerified, deleted bool
	var createdAt string
	if err := owner.QueryRow(ctx, `
		SELECT banned, email_verified, deleted, created_at::text
		  FROM auth.users WHERE id = $1`, user.ID).
		Scan(&banned, &emailVerified, &deleted, &createdAt); err != nil {
		t.Fatalf("read tombstoned row: %v", err)
	}

	if !deleted {
		t.Error("deleted was cleared: the account would authenticate again")
	}
	if !banned {
		t.Error("banned was cleared: erasing an account must not lift its ban, or erasure " +
			"becomes the way out of one")
	}
	// Migration 024's trigger raises on TRUE -> FALSE for this column, so clearing
	// it would not merely be wrong, it would abort every erasure of a verified
	// account. Assert the value rather than trusting the trigger to have fired.
	if !emailVerified {
		t.Error("email_verified was cleared, which migration 024's transition trigger denies")
	}
	if createdAt == "" {
		t.Error("created_at was cleared; the escrow record and the audit trail are dated from it")
	}
}
