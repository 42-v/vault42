package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// The user repository is the account-state store: it is what login consults to decide
// whether an account is locked, banned or erased. Every write here must report a
// database failure rather than return nil.
//
// The lockout counters are the sharpest case. If IncrementFailedLogin quietly did
// nothing, the counter would never advance and the account would never lock — brute
// force with no ceiling and no error in the logs. LockUntil is the same bug from the
// other side: an operator locks an account, is told it worked, and it did not.
//
// SoftDeleteScrub is the erasure scrub itself. A silent failure there is an account
// reported as erased whose real email address is still in the table.
func TestUserRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewUserRepo(deadPool(t))
	ctx := context.Background()
	user := &model.User{ID: "u-1", Email: "u@example.com", PasswordHash: "$argon2id$h"}

	if err := repo.Create(ctx, user); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if err := repo.CreateImported(ctx, user); err == nil {
		t.Error("CreateImported reported success against an unreachable database")
	}
	if err := repo.ClearImportPending(ctx, "u-1"); err == nil {
		t.Error("ClearImportPending reported success — the account would stay stuck in import-claim forever")
	}
	if _, err := repo.GetByID(ctx, "u-1"); err == nil {
		t.Error("GetByID returned no error against an unreachable database")
	}
	if _, err := repo.GetByEmail(ctx, "u@example.com"); err == nil {
		t.Error("GetByEmail returned no error against an unreachable database")
	}
	if err := repo.Update(ctx, user); err == nil {
		t.Error("Update reported success against an unreachable database")
	}
	if err := repo.SoftDeleteScrub(ctx, "u-1", "deleted-u-1@deleted.invalid"); err == nil {
		t.Error("SoftDeleteScrub reported success — erasure would report an account scrubbed with its email still in the table")
	}
	if err := repo.UpdatePassword(ctx, "u-1", "$argon2id$new"); err == nil {
		t.Error("UpdatePassword reported success — the user would be told their password changed when it did not")
	}
	if err := repo.IncrementFailedLogin(ctx, "u-1"); err == nil {
		t.Error("IncrementFailedLogin reported success — the lockout counter would never advance")
	}
	if err := repo.ResetFailedLogin(ctx, "u-1"); err == nil {
		t.Error("ResetFailedLogin reported success against an unreachable database")
	}
	if err := repo.LockUntil(ctx, "u-1", time.Now().Add(time.Hour)); err == nil {
		t.Error("LockUntil reported success — an account believed locked would still accept logins")
	}
	if err := repo.Unlock(ctx, "u-1"); err == nil {
		t.Error("Unlock reported success against an unreachable database")
	}
	if err := repo.SetLastLogin(ctx, "u-1"); err == nil {
		t.Error("SetLastLogin reported success against an unreachable database")
	}
	if err := repo.VerifyEmail(ctx, "u-1"); err == nil {
		t.Error("VerifyEmail reported success — an unverified address would be treated as verified")
	}
}

// Blobs are the user's encrypted documents. A List that returned an empty slice on a
// database failure would tell the user they have nothing stored, and a
// DeleteAllForPseudonym that reported success without deleting would leave every blob
// behind on an erasure that claimed to have removed them.
func TestBlobRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewBlobRepo(deadPool(t))
	ctx := context.Background()

	if err := repo.Create(ctx, &model.Blob{ID: "b-1", PseudonymID: "p-1"}); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByIDAndPseudonym(ctx, "b-1", "p-1"); err == nil {
		t.Error("GetByIDAndPseudonym returned no error against an unreachable database")
	}
	if _, err := repo.GetByRefAndPseudonym(ctx, "ref", "p-1"); err == nil {
		t.Error("GetByRefAndPseudonym returned no error against an unreachable database")
	}
	if err := repo.DeleteByRefAndPseudonym(ctx, "ref", "p-1"); err == nil {
		t.Error("DeleteByRefAndPseudonym reported success against an unreachable database")
	}
	if _, err := repo.ListByPseudonym(ctx, "p-1"); err == nil {
		t.Error("ListByPseudonym returned no error — the user would be told they have no documents stored")
	}
	if _, err := repo.GetQuota(ctx, "p-1"); err == nil {
		t.Error("GetQuota returned no error against an unreachable database")
	}
	if err := repo.Delete(ctx, "b-1", "p-1"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
	if err := repo.DeleteAllForPseudonym(ctx, "p-1"); err == nil {
		t.Error("DeleteAllForPseudonym reported success — erasure would leave every blob behind")
	}
}
