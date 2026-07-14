package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestPostgresAccountRecoveryRepo covers the append-only escrow repository that
// backs GDPR account erasure (records decryptable only by the offline key).
func TestPostgresAccountRecoveryRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewAccountRecoveryRepo(db)
	ctx := context.Background()

	mk := func(pseudonym string, when time.Time) model.AccountRecovery {
		return model.AccountRecovery{
			ID:        randomID(),
			Pseudonym: pseudonym,
			Payload:   []byte("encrypted-recovery-blob-" + pseudonym),
			DeletedAt: when,
			DeletedBy: "admin-1",
			Reason:    "gdpr-erasure",
		}
	}

	t.Run("Append then List round-trips all fields", func(t *testing.T) {
		rec := mk("pseudo-a", time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond))
		if err := repo.Append(ctx, &rec); err != nil {
			t.Fatalf("Append: %v", err)
		}
		got, err := repo.List(ctx, 10, 0)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("List = %d rows, want 1", len(got))
		}
		if got[0].Pseudonym != "pseudo-a" || string(got[0].Payload) != string(rec.Payload) ||
			got[0].DeletedBy != "admin-1" || got[0].Reason != "gdpr-erasure" {
			t.Fatalf("round-trip mismatch: %+v", got[0])
		}
	})

	t.Run("Append tolerates empty deleted_by and reason", func(t *testing.T) {
		rec := mk("pseudo-b", time.Now().UTC().Truncate(time.Microsecond))
		rec.DeletedBy = ""
		rec.Reason = ""
		if err := repo.Append(ctx, &rec); err != nil {
			t.Fatalf("Append with empty optional fields: %v", err)
		}
	})

	t.Run("List orders by deleted_at desc and paginates", func(t *testing.T) {
		// pseudo-a is 1h old, pseudo-b is ~now; a newer and an oldest bracket them.
		newest := mk("pseudo-newest", time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond))
		oldest := mk("pseudo-oldest", time.Now().Add(-24*time.Hour).UTC().Truncate(time.Microsecond))
		if err := repo.Append(ctx, &newest); err != nil {
			t.Fatalf("Append newest: %v", err)
		}
		if err := repo.Append(ctx, &oldest); err != nil {
			t.Fatalf("Append oldest: %v", err)
		}

		all, err := repo.List(ctx, 100, 0)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(all) < 4 {
			t.Fatalf("List = %d rows, want >= 4", len(all))
		}
		if all[0].Pseudonym != "pseudo-newest" {
			t.Errorf("first row = %q, want pseudo-newest (desc by deleted_at)", all[0].Pseudonym)
		}
		if all[len(all)-1].Pseudonym != "pseudo-oldest" {
			t.Errorf("last row = %q, want pseudo-oldest", all[len(all)-1].Pseudonym)
		}

		// LIMIT/OFFSET paginate.
		page, err := repo.List(ctx, 2, 1)
		if err != nil {
			t.Fatalf("List page: %v", err)
		}
		if len(page) != 2 {
			t.Fatalf("paged List = %d rows, want 2", len(page))
		}
		if page[0].Pseudonym != all[1].Pseudonym {
			t.Errorf("offset paging wrong: page[0]=%q, want %q", page[0].Pseudonym, all[1].Pseudonym)
		}
	})

	t.Run("append-only: direct UPDATE is denied by trigger", func(t *testing.T) {
		// The row cannot be rewritten; the deny_modify trigger raises on UPDATE.
		_, err := pool.Exec(ctx, `UPDATE auth.account_recovery SET reason = 'tampered'`)
		if err == nil {
			t.Fatal("UPDATE on append-only account_recovery succeeded; trigger should deny it")
		}
	})
}
