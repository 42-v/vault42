package integration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestTombstoneEmailInsertGuard proves the erasure tombstone address is terminal
// against a direct INSERT, not only against the UPDATE that migration 015 closed.
//
// 015's whole thesis is that auth.users.email in the tombstone domain has exactly
// one legitimate writer, auth.erase_user_identity(), and that the application role
// must not be able to point an account at that address by any other means. It
// revoked UPDATE (email) from vault_app and vault_admin to enforce that. It left
// INSERT alone: 001 grants vault_app INSERT on auth.users for registration, and
// email is a UNIQUE column.
//
// That is the residual squat. A holder of the vault_app role (SQL injection that
// reaches an INSERT, or a compromised app node) can pre-occupy a victim's future
// tombstone address:
//
//	INSERT INTO auth.users (id, email) VALUES (<random>, 'deleted-<victim>@deleted.invalid')
//
// When the victim is later erased, auth.erase_user_identity() runs
//
//	UPDATE auth.users SET email = 'deleted-<victim>@deleted.invalid' WHERE id = <victim>
//
// which now collides on the unique email index and fails. The Art. 17 request
// cannot complete and the victim's PII is retained: an erasure denial of service.
// The app-layer sanitize.Email fix refuses the deleted.invalid domain at Register,
// the OAuth callback and import, but sanitize runs in Go, and this write reaches
// the database as vault_app without passing through it. The database must enforce
// the same rule the app already does.
//
// The guard is a BEFORE INSERT trigger, so the erasure UPDATE never sees it: this
// test also proves a legitimate registration still inserts and a legitimate
// erasure still tombstones through the function.
func TestTombstoneEmailInsertGuard(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)

	// The address a future erasure of victimID will write. email is UNIQUE, so a
	// row already sitting on it turns that erasure into a 23505 unique violation.
	victimID := randomID()
	squatEmail := "deleted-" + victimID + "@deleted.invalid"

	t.Run("vault_app cannot INSERT a row squatting the tombstone domain", func(t *testing.T) {
		squatID := randomID()
		_, err := appPool.Exec(ctx,
			`INSERT INTO auth.users (id, email) VALUES ($1, $2)`, squatID, squatEmail)
		if err == nil {
			t.Fatalf("vault_app inserted a row on the tombstone address %q; a later erasure of %s "+
				"will fail on the unique email constraint (Art. 17 denial of service)", squatEmail, victimID)
		}
		// The refusal must be the guard, not an unrelated failure that would mask a
		// regression the day the message changes.
		if !strings.Contains(strings.ToLower(err.Error()), "tombstone") {
			t.Fatalf("insert of a tombstone-domain email was refused, but not by the tombstone guard: %v", err)
		}
	})

	t.Run("the guard turns away no legitimate registration", func(t *testing.T) {
		okID := randomID()
		if _, err := appPool.Exec(ctx,
			`INSERT INTO auth.users (id, email) VALUES ($1, $2)`, okID, "legit-"+okID+"@example.com"); err != nil {
			t.Fatalf("guard rejected a legitimate registration email: %v", err)
		}
	})

	t.Run("legitimate erasure still tombstones through the function", func(t *testing.T) {
		seed := postgres.NewUserRepo(&postgres.DB{Pool: adminPool})
		u := makeUser("erase-me-" + randomID() + "@example.com")
		if err := seed.Create(ctx, u); err != nil {
			t.Fatalf("seed user: %v", err)
		}

		appUsers := postgres.NewUserRepo(&postgres.DB{Pool: appPool})
		tombstone := "deleted-" + u.ID + "@deleted.invalid"
		if err := appUsers.SoftDeleteScrub(ctx, u.ID, tombstone); err != nil {
			t.Fatalf("guard broke legitimate erasure: SoftDeleteScrub via auth.erase_user_identity() failed: %v", err)
		}

		got, err := seed.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID after erasure: %v", err)
		}
		if !got.Deleted || got.Email != tombstone {
			t.Errorf("row not tombstoned: deleted=%v email=%q, want deleted=true email=%q",
				got.Deleted, got.Email, tombstone)
		}
	})
}
