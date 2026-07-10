package integration_test

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestPostgresEmailBrandingRepo exercises the per-app white-label branding repo
// (auth.email_branding) end-to-end against a real Postgres.
func TestPostgresEmailBrandingRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewEmailBrandingRepo(db)
	ctx := context.Background()

	t.Run("Get absent returns nil", func(t *testing.T) {
		got, err := repo.Get(ctx, "ghost")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != nil {
			t.Fatalf("Get(absent) = %+v, want nil", got)
		}
	})

	t.Run("Upsert then Get", func(t *testing.T) {
		b := &model.EmailBranding{
			App: "acme", AppName: "Acme", LogoURL: "https://cdn.acme.test/l.png",
			PrimaryColor: "#00FF42", FromName: "Acme", FromAddress: "noreply@acme.test", UpdatedBy: "root",
		}
		if err := repo.Upsert(ctx, b); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		got, err := repo.Get(ctx, "acme")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got == nil || got.AppName != "Acme" || got.FromAddress != "noreply@acme.test" {
			t.Fatalf("Get = %+v, want the upserted branding", got)
		}
		if got.UpdatedAt.IsZero() {
			t.Error("UpdatedAt not populated by the DB default")
		}
	})

	t.Run("Upsert replaces in place", func(t *testing.T) {
		if err := repo.Upsert(ctx, &model.EmailBranding{App: "acme", AppName: "Acme Renamed", UpdatedBy: "root2"}); err != nil {
			t.Fatalf("Upsert (replace): %v", err)
		}
		got, err := repo.Get(ctx, "acme")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.AppName != "Acme Renamed" {
			t.Fatalf("AppName = %q, want the replacement", got.AppName)
		}
		// PRIMARY KEY on app: still exactly one row.
		list, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 1 {
			t.Fatalf("List returned %d rows after replace, want 1", len(list))
		}
	})

	t.Run("List multiple ordered", func(t *testing.T) {
		if err := repo.Upsert(ctx, &model.EmailBranding{App: "beta", AppName: "Beta"}); err != nil {
			t.Fatalf("Upsert beta: %v", err)
		}
		list, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("List = %d rows, want 2", len(list))
		}
	})

	t.Run("Delete is idempotent", func(t *testing.T) {
		if err := repo.Delete(ctx, "beta"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got, _ := repo.Get(ctx, "beta"); got != nil {
			t.Fatal("row still present after Delete")
		}
		// Deleting an absent app must not error.
		if err := repo.Delete(ctx, "beta"); err != nil {
			t.Fatalf("Delete (absent) errored: %v", err)
		}
	})
}

// TestPostgresEmailTemplateRepo exercises the per-app template override repo
// (auth.email_templates).
func TestPostgresEmailTemplateRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewEmailTemplateRepo(db)
	ctx := context.Background()

	mk := func(app, name, subject string) *model.EmailTemplate {
		return &model.EmailTemplate{
			ID: randomID(), App: app, TemplateName: name, Subject: subject,
			HTMLContent: "<p>Hi</p>", Enabled: true, CreatedBy: "root", UpdatedBy: "root",
		}
	}

	t.Run("Get absent returns nil", func(t *testing.T) {
		got, err := repo.Get(ctx, "acme", "verification")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != nil {
			t.Fatalf("Get(absent) = %+v, want nil", got)
		}
	})

	t.Run("Upsert then Get", func(t *testing.T) {
		if err := repo.Upsert(ctx, mk("acme", "verification", "Verify")); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		got, err := repo.Get(ctx, "acme", "verification")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got == nil || got.Subject != "Verify" || !got.Enabled {
			t.Fatalf("Get = %+v, want the upserted template", got)
		}
	})

	t.Run("Upsert replaces by (app,name)", func(t *testing.T) {
		if err := repo.Upsert(ctx, mk("acme", "verification", "Verify v2")); err != nil {
			t.Fatalf("Upsert (replace): %v", err)
		}
		got, err := repo.Get(ctx, "acme", "verification")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Subject != "Verify v2" {
			t.Fatalf("Subject = %q, want the replacement", got.Subject)
		}
	})

	t.Run("ListByApp and List", func(t *testing.T) {
		if err := repo.Upsert(ctx, mk("acme", "password_reset", "Reset")); err != nil {
			t.Fatalf("Upsert password_reset: %v", err)
		}
		if err := repo.Upsert(ctx, mk("beta", "verification", "Beta Verify")); err != nil {
			t.Fatalf("Upsert beta: %v", err)
		}
		byApp, err := repo.ListByApp(ctx, "acme")
		if err != nil {
			t.Fatalf("ListByApp: %v", err)
		}
		if len(byApp) != 2 {
			t.Fatalf("ListByApp(acme) = %d, want 2", len(byApp))
		}
		all, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(all) != 3 {
			t.Fatalf("List = %d, want 3", len(all))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := repo.Delete(ctx, "beta", "verification"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got, _ := repo.Get(ctx, "beta", "verification"); got != nil {
			t.Fatal("row still present after Delete")
		}
	})
}
