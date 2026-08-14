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
