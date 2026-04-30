package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresClientRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewClientRepo(db)
	ctx := context.Background()

	makeClient := func(name string) *model.Client {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.Client{
			ID:           randomID(),
			Name:         name,
			SecretHash:   "$argon2id$v=19$m=47104,t=1,p=1$c2VjcmV0$clienthash",
			Role:         "frontend",
			Scopes:       []string{"user:read", "user:write"},
			RedirectURIs: []string{"https://example.com/callback"},
			Active:       true,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
	}

	t.Run("Create and GetByID", func(t *testing.T) {
		c := makeClient("test-client-getbyid")
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByID returned nil")
		}
		if got.ID != c.ID {
			t.Errorf("ID = %q, want %q", got.ID, c.ID)
		}
		if got.Name != "test-client-getbyid" {
			t.Errorf("Name = %q, want %q", got.Name, "test-client-getbyid")
		}
		if got.SecretHash != c.SecretHash {
			t.Errorf("SecretHash = %q, want %q", got.SecretHash, c.SecretHash)
		}
		if got.Role != "frontend" {
			t.Errorf("Role = %q, want %q", got.Role, "frontend")
		}
		if len(got.Scopes) != 2 {
			t.Errorf("len(Scopes) = %d, want 2", len(got.Scopes))
		}
		if len(got.RedirectURIs) != 1 {
			t.Errorf("len(RedirectURIs) = %d, want 1", len(got.RedirectURIs))
		}
		if !got.Active {
			t.Error("Active = false, want true")
		}
	})

	t.Run("GetByID not found returns nil", func(t *testing.T) {
		got, err := repo.GetByID(ctx, randomID())
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("GetByName", func(t *testing.T) {
		c := makeClient("test-client-getbyname")
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByName(ctx, "test-client-getbyname")
		if err != nil {
			t.Fatalf("GetByName: %v", err)
		}
		if got == nil {
			t.Fatal("GetByName returned nil")
		}
		if got.ID != c.ID {
			t.Errorf("ID = %q, want %q", got.ID, c.ID)
		}
	})

	t.Run("GetByName not found returns nil", func(t *testing.T) {
		got, err := repo.GetByName(ctx, "nonexistent-client")
		if err != nil {
			t.Fatalf("GetByName: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("List", func(t *testing.T) {
		// Count how many exist before
		before, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List before: %v", err)
		}

		c1 := makeClient("alist-client-alpha")
		c2 := makeClient("alist-client-beta")
		if err := repo.Create(ctx, c1); err != nil {
			t.Fatalf("Create c1: %v", err)
		}
		if err := repo.Create(ctx, c2); err != nil {
			t.Fatalf("Create c2: %v", err)
		}

		after, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List after: %v", err)
		}
		if len(after) != len(before)+2 {
			t.Errorf("len(after) = %d, want %d", len(after), len(before)+2)
		}

		// Verify ordering is by name
		for i := 1; i < len(after); i++ {
			if after[i].Name < after[i-1].Name {
				t.Errorf("list not sorted by name: %q before %q", after[i-1].Name, after[i].Name)
			}
		}
	})

	t.Run("Update", func(t *testing.T) {
		c := makeClient("test-client-update")
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}

		c.Name = "test-client-updated"
		c.Role = "backend"
		c.Scopes = []string{"admin:read", "admin:write", "user:read"}
		c.RedirectURIs = []string{"https://new.example.com/callback", "https://alt.example.com/callback"}

		if err := repo.Update(ctx, c); err != nil {
			t.Fatalf("Update: %v", err)
		}

		got, err := repo.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.Name != "test-client-updated" {
			t.Errorf("Name = %q, want %q", got.Name, "test-client-updated")
		}
		if got.Role != "backend" {
			t.Errorf("Role = %q, want %q", got.Role, "backend")
		}
		if len(got.Scopes) != 3 {
			t.Errorf("len(Scopes) = %d, want 3", len(got.Scopes))
		}
		if len(got.RedirectURIs) != 2 {
			t.Errorf("len(RedirectURIs) = %d, want 2", len(got.RedirectURIs))
		}
	})

	t.Run("Deactivate", func(t *testing.T) {
		c := makeClient("test-client-deactivate")
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Deactivate(ctx, c.ID); err != nil {
			t.Fatalf("Deactivate: %v", err)
		}
		got, err := repo.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.Active {
			t.Error("Active = true after Deactivate, want false")
		}
	})

	t.Run("Create with empty scopes and redirect URIs", func(t *testing.T) {
		c := &model.Client{
			ID:           randomID(),
			Name:         "test-client-empty-arrays",
			SecretHash:   "$argon2id$v=19$m=47104,t=1,p=1$c2VjcmV0$hash",
			Role:         "service",
			Scopes:       []string{},
			RedirectURIs: []string{},
			Active:       true,
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
			UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if len(got.Scopes) != 0 {
			t.Errorf("len(Scopes) = %d, want 0", len(got.Scopes))
		}
	})

	t.Run("Deactivate idempotent", func(t *testing.T) {
		c := makeClient("test-client-deact-idempotent")
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Deactivate(ctx, c.ID); err != nil {
			t.Fatalf("Deactivate first: %v", err)
		}
		if err := repo.Deactivate(ctx, c.ID); err != nil {
			t.Fatalf("Deactivate second: %v", err)
		}
		got, _ := repo.GetByID(ctx, c.ID)
		if got.Active {
			t.Error("Active should remain false")
		}
	})
}
