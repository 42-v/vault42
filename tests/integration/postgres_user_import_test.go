package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresUserImport(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewUserRepo(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	legacy := randomID()
	u := &model.User{
		ID: randomID(), Email: "imported@legacy.test", DisplayName: "Imported",
		Locale: "en", Roles: []string{"moderator"}, Banned: true, BanReason: "spam",
		ImportedFrom: "legacy", LegacyID: legacy, CreatedAt: now, UpdatedAt: now,
	}

	t.Run("CreateImported sets import_pending + no password", func(t *testing.T) {
		if err := repo.CreateImported(ctx, u); err != nil {
			t.Fatalf("CreateImported: %v", err)
		}
		got, err := repo.GetByEmail(ctx, u.Email)
		if err != nil || got == nil {
			t.Fatalf("GetByEmail: %v / %v", got, err)
		}
		if !got.ImportPending {
			t.Error("imported account must be import_pending")
		}
		if got.PasswordHash != "" {
			t.Errorf("imported account must have no password, got %q", got.PasswordHash)
		}
		if !got.EmailVerified {
			t.Error("imported account email should be pre-verified")
		}
		if got.ImportedFrom != "legacy" || got.LegacyID != legacy {
			t.Errorf("import provenance lost: from=%q legacy=%q", got.ImportedFrom, got.LegacyID)
		}
		if !got.Banned || got.BanReason != "spam" {
			t.Error("imported account flags lost")
		}
	})

	t.Run("CreateImported is idempotent on email", func(t *testing.T) {
		dup := *u
		dup.ID = randomID()
		if err := repo.CreateImported(ctx, &dup); err != nil {
			t.Fatalf("re-import: %v", err)
		}
		got, _ := repo.GetByEmail(ctx, u.Email)
		if got.ID != u.ID {
			t.Error("idempotent re-import must not replace the original row")
		}
	})

	t.Run("ClearImportPending claims the account", func(t *testing.T) {
		if err := repo.ClearImportPending(ctx, u.ID); err != nil {
			t.Fatalf("ClearImportPending: %v", err)
		}
		got, _ := repo.GetByEmail(ctx, u.Email)
		if got.ImportPending {
			t.Error("import_pending should be cleared after claim")
		}
	})
}
