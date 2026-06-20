package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresAppRoleRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewAppRoleRepo(db)
	ctx := context.Background()

	t.Run("List returns seeded catalog", func(t *testing.T) {
		roles, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		names := map[string]bool{}
		for _, r := range roles {
			names[r.Name] = true
		}
		for _, want := range []string{"user", "viewer", "operator", "moderator", "premium_user", "business", "creator"} {
			if !names[want] {
				t.Errorf("seeded role %q missing from catalog", want)
			}
		}
	})

	t.Run("Get reserved + non-reserved", func(t *testing.T) {
		u, _ := repo.Get(ctx, "user")
		if u == nil || !u.Reserved {
			t.Fatalf("user role should exist and be reserved: %+v", u)
		}
		m, _ := repo.Get(ctx, "moderator")
		if m == nil || m.Reserved {
			t.Fatalf("moderator should exist and be non-reserved: %+v", m)
		}
		if absent, _ := repo.Get(ctx, "no_such_role"); absent != nil {
			t.Fatalf("absent role should return nil, got %+v", absent)
		}
	})

	t.Run("Create then Delete a custom role", func(t *testing.T) {
		if err := repo.Create(ctx, &model.AppRole{Name: "beta_tester", Namespace: "legacy", Description: "Beta program"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, _ := repo.Get(ctx, "beta_tester")
		if got == nil || got.Namespace != "legacy" {
			t.Fatalf("created role not found/namespaced: %+v", got)
		}
		if err := repo.Delete(ctx, "beta_tester"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if gone, _ := repo.Get(ctx, "beta_tester"); gone != nil {
			t.Fatal("role should be deleted")
		}
	})

	t.Run("Delete reserved role is refused", func(t *testing.T) {
		if err := repo.Delete(ctx, "user"); !errors.Is(err, repository.ErrRoleReserved) {
			t.Fatalf("deleting reserved role should return ErrRoleReserved, got %v", err)
		}
		if still, _ := repo.Get(ctx, "user"); still == nil {
			t.Fatal("reserved role must survive a delete attempt")
		}
	})

	t.Run("Delete missing role is a no-op", func(t *testing.T) {
		if err := repo.Delete(ctx, "ghost_role"); err != nil {
			t.Fatalf("deleting a missing role should be a no-op, got %v", err)
		}
	})
}
