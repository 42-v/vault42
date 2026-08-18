package postgres

import (
	"context"
	"testing"
)

// The login-country repository is where "is this a new country for the user?"
// stops being a Go decision and becomes a single SQL statement: the `prior` CTE
// reads the pre-INSERT snapshot for had_any while the `ins` CTE reports whether
// the ON CONFLICT DO NOTHING actually added a row for was_new. Those two facts,
// read against one snapshot, are the whole contract, and only a real PostgreSQL
// can demonstrate that the CTE ordering holds. A fake would just replay whatever
// booleans it was told to.

// TestLoginCountryRepo_SurfacesDatabaseFailures pins the error branch: a query
// failure must surface, never degrade into a silent (false, false) that reads as
// "known country, nothing to notify" and suppresses a real new-location notice.
func TestLoginCountryRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewLoginCountryRepo(deadPool(t))
	wasNew, hadAny, err := repo.UpsertAndWasNew(context.Background(),
		"11111111-0000-4000-8000-000000000001", "DE")
	if err == nil {
		t.Fatal("UpsertAndWasNew reported success against an unreachable database")
	}
	if wasNew || hadAny {
		t.Errorf("a failed upsert returned wasNew=%v hadAny=%v; both must be false on error", wasNew, hadAny)
	}
}

// TestLoginCountryRepo_DeleteSurfacesDatabaseFailures pins the erasure branch. A
// swallowed failure here is worse than a swallowed read: DeleteAccount would
// carry on and report a completed Art. 17 erasure with the country history still
// on disk.
func TestLoginCountryRepo_DeleteSurfacesDatabaseFailures(t *testing.T) {
	repo := NewLoginCountryRepo(deadPool(t))
	if err := repo.DeleteAllForUser(context.Background(),
		"11111111-0000-4000-8000-000000000001"); err == nil {
		t.Fatal("DeleteAllForUser reported success against an unreachable database")
	}
}

// TestLoginCountryRepo_ErasureAgainstPostgres exercises the erasure step against
// the real function migration 030 installs. Two properties matter and neither can
// be shown without a database: a tombstoned account's countries actually go, and
// a LIVE account's countries cannot be cleared through the same call. The second
// is what keeps the fix from handing out a way to silence the new-location notice
// by wiping an account's baseline just before signing in from somewhere new.
func TestLoginCountryRepo_ErasureAgainstPostgres(t *testing.T) {
	db := svcDocPostgres(t)
	repo := NewLoginCountryRepo(db)
	ctx := context.Background()

	const userID = "cccccccc-0000-4000-8000-00000000c003"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO auth.users (id, email) VALUES ($1, $2)`,
		userID, "erase-login-country@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, cc := range []string{"DE", "FR"} {
		if _, _, err := repo.UpsertAndWasNew(ctx, userID, cc); err != nil {
			t.Fatalf("seed country %s: %v", cc, err)
		}
	}

	// A live account is refused. The cascade never asks for this, so an error here
	// is the guard working rather than a broken erasure.
	if err := repo.DeleteAllForUser(ctx, userID); err == nil {
		t.Fatal("cleared a live account's login countries: the tombstone guard in " +
			"auth.erase_login_countries() is not holding, and clearing the baseline " +
			"suppresses the new-location notice for the next sign-in")
	}
	if n := countCountries(t, ctx, db, userID); n != 2 {
		t.Fatalf("the refused call still removed rows: %d left, want 2", n)
	}

	// Tombstone the row exactly as SoftDeleteScrub does, then erase.
	if _, err := db.Pool.Exec(ctx, `SELECT auth.erase_user_identity($1, $2)`,
		userID, "deleted-"+userID+"@deleted.invalid"); err != nil {
		t.Fatalf("tombstone user: %v", err)
	}
	if err := repo.DeleteAllForUser(ctx, userID); err != nil {
		t.Fatalf("DeleteAllForUser after tombstone: %v", err)
	}
	if n := countCountries(t, ctx, db, userID); n != 0 {
		t.Errorf("%d login-country row(s) survived erasure, want 0", n)
	}

	// Idempotent: an interrupted erasure is re-run from the top, and a user who
	// never had a country recorded must not fail the cascade.
	if err := repo.DeleteAllForUser(ctx, userID); err != nil {
		t.Errorf("re-running the erasure step failed: %v", err)
	}
	if err := repo.DeleteAllForUser(ctx, "dddddddd-0000-4000-8000-00000000c004"); err != nil {
		t.Errorf("erasing a user with no rows (and no user row) failed: %v", err)
	}
}

func countCountries(t *testing.T, ctx context.Context, db *DB, userID string) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.login_countries WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count login countries: %v", err)
	}
	return n
}

func TestLoginCountryRepo_AgainstPostgres(t *testing.T) {
	db := svcDocPostgres(t) // brings up PostgreSQL and applies every migration, incl. 028
	repo := NewLoginCountryRepo(db)
	ctx := context.Background()

	const userID = "aaaaaaaa-0000-4000-8000-00000000c001"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO auth.users (id, email) VALUES ($1, $2)`,
		userID, "login-country@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// The user has no recorded country yet: the very first login seeds silently,
	// so wasNew is true (a row was inserted) but hadAny is false (nothing before).
	wasNew, hadAny, err := repo.UpsertAndWasNew(ctx, userID, "DE")
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !wasNew || hadAny {
		t.Errorf("first-ever country: wasNew=%v hadAny=%v, want true/false", wasNew, hadAny)
	}

	// The same country again: no row is inserted, so wasNew is false; the user now
	// has a prior country, so hadAny is true.
	wasNew, hadAny, err = repo.UpsertAndWasNew(ctx, userID, "DE")
	if err != nil {
		t.Fatalf("duplicate upsert: %v", err)
	}
	if wasNew || !hadAny {
		t.Errorf("repeat of a known country: wasNew=%v hadAny=%v, want false/true", wasNew, hadAny)
	}

	// A genuinely new country for a user who already had one: this is the exact
	// condition that fires the new-location notice — wasNew AND hadAny.
	wasNew, hadAny, err = repo.UpsertAndWasNew(ctx, userID, "FR")
	if err != nil {
		t.Fatalf("new-country upsert: %v", err)
	}
	if !wasNew || !hadAny {
		t.Errorf("a new country for a returning user: wasNew=%v hadAny=%v, want true/true", wasNew, hadAny)
	}

	// Re-recording that new country is idempotent: wasNew false, hadAny still true.
	wasNew, hadAny, err = repo.UpsertAndWasNew(ctx, userID, "FR")
	if err != nil {
		t.Fatalf("duplicate new-country upsert: %v", err)
	}
	if wasNew || !hadAny {
		t.Errorf("repeat of the second country: wasNew=%v hadAny=%v, want false/true", wasNew, hadAny)
	}

	// Countries are scoped per user: a different user's first country is new to
	// them and they have no prior, regardless of the first user's set.
	const otherID = "bbbbbbbb-0000-4000-8000-00000000c002"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO auth.users (id, email) VALUES ($1, $2)`,
		otherID, "other-login-country@example.com"); err != nil {
		t.Fatalf("seed other user: %v", err)
	}
	wasNew, hadAny, err = repo.UpsertAndWasNew(ctx, otherID, "DE")
	if err != nil {
		t.Fatalf("other user upsert: %v", err)
	}
	if !wasNew || hadAny {
		t.Errorf("another user's first country: wasNew=%v hadAny=%v, want true/false", wasNew, hadAny)
	}
}
