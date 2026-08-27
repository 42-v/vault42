package integration_test

// A password write must not land on a tombstone.
//
// The erasure scrub NULLs auth.users.password_hash, and migration 031 explains
// why it is the item worth removing: it is "still crackable offline and still
// tells an attacker what to try elsewhere". Nothing kept it NULL.
//
// UserRepo.Update carries `WHERE id = $1 AND deleted = FALSE` with a comment
// saying a handler check is a decision made from a row read a moment earlier
// while the statement is what actually writes. UpdatePassword, twelve lines
// below it in the same file, carried neither the clause nor the check -- so a
// password-reset link minted before an erasure wrote a live Argon2id hash back
// onto the erased row.
//
// The handler refuses that request now. This is the other half: the statement
// refuses it too, against a real PostgreSQL, so the invariant does not depend
// on every present and future caller remembering.

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestUpdatePasswordRefusesAnErasedRow(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	ownerDB := &postgres.DB{Pool: adminPool}
	repo := postgres.NewUserRepo(ownerDB)

	live := seedAccountStateUser(t, ctx, ownerDB, "pw-tombstone@test.com")

	// The live account is unaffected, which is the half a fix like this breaks.
	if err := repo.UpdatePassword(ctx, live.ID, "$argon2id$v=19$live"); err != nil {
		t.Fatalf("a live account could not change its password: %v", err)
	}

	if err := repo.SoftDeleteScrub(ctx, live.ID, "deleted-"+live.ID+"@deleted.invalid"); err != nil {
		t.Fatalf("scrub: %v", err)
	}

	var hash *string
	if err := adminPool.QueryRow(ctx,
		`SELECT password_hash FROM auth.users WHERE id = $1`, live.ID).Scan(&hash); err != nil {
		t.Fatalf("read back after scrub: %v", err)
	}
	if hash != nil {
		t.Fatalf("the scrub left password_hash = %q; migration 031 NULLs it on purpose", *hash)
	}

	err := repo.UpdatePassword(ctx, live.ID, "$argon2id$v=19$writtenBackAfterErasure")
	if !errors.Is(err, repository.ErrUserNotUpdatable) {
		t.Fatalf("UpdatePassword on a tombstone returned %v, want ErrUserNotUpdatable. A reset "+
			"link minted before the erasure would otherwise put a live, crackable hash back on "+
			"the erased row -- after the account_erased audit row was written.", err)
	}

	if err := adminPool.QueryRow(ctx,
		`SELECT password_hash FROM auth.users WHERE id = $1`, live.ID).Scan(&hash); err != nil {
		t.Fatalf("read back after the refused write: %v", err)
	}
	if hash != nil {
		t.Fatalf("password_hash = %q after a refused write; the statement reported a refusal and "+
			"wrote anyway", *hash)
	}
}
