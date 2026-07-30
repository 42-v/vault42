package integration_test

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// A partially applied migration, or a column relaxed by hand during an incident,
// leaves rows the repository cannot decode. Both of these listings are read by an
// operator to answer a security question — who holds privileged access, and what
// is this vault configured to do — so a row that fails to decode has to abort the
// listing. Returning the rows that happened to decode would answer the question
// with a shorter list that looks complete.
func TestPostgresAdminRepos_UndecodableRowAbortsTheListing(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	t.Run("admin config", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `ALTER TABLE auth.admin_config ALTER COLUMN value DROP NOT NULL`); err != nil {
			t.Fatalf("relax value constraint: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO auth.admin_config (key, value) VALUES ('drifted.key', NULL)`); err != nil {
			t.Fatalf("insert undecodable row: %v", err)
		}

		entries, err := postgres.NewAdminConfigRepo(db).List(ctx)

		if err == nil {
			t.Fatal("List reported success over a row it could not decode")
		}
		if entries != nil {
			t.Errorf("a partial config map was returned alongside the error: %v", entries)
		}
	})

	t.Run("admin users", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `ALTER TABLE auth.admin_users ALTER COLUMN password_hash DROP NOT NULL`); err != nil {
			t.Fatalf("relax password_hash constraint: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO auth.admin_users (id, username, password_hash, role)
			 VALUES (gen_random_uuid(), 'drifted', NULL, 'viewer')`); err != nil {
			t.Fatalf("insert undecodable row: %v", err)
		}

		admins, err := postgres.NewAdminUserRepo(db).List(ctx)

		if err == nil {
			t.Fatal("List reported success over a row it could not decode")
		}
		if admins != nil {
			t.Errorf("a truncated admin list was returned alongside the error: %d rows", len(admins))
		}
	})
}
