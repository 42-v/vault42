package postgres

import (
	"context"
	"fmt"
)

// LoginCountryRepo implements repository.LoginCountryRepository using
// PostgreSQL (auth.login_countries, migration 028).
type LoginCountryRepo struct {
	db *DB
}

// NewLoginCountryRepo creates a new PostgreSQL-backed login-country repository.
func NewLoginCountryRepo(db *DB) *LoginCountryRepo {
	return &LoginCountryRepo{db: db}
}

// UpsertAndWasNew records (userID, cc) and reports whether cc is new for the
// user and whether the user already had at least one recorded country.
//
// Both facts and the insert are one statement so they read the same snapshot:
// the `prior` CTE counts the rows as they were before this statement's INSERT
// (Postgres evaluates every CTE against the snapshot taken at statement start),
// so had_any reflects the pre-login state, and was_new reports whether the
// INSERT actually added a row (ON CONFLICT DO NOTHING returns nothing when cc
// was already present). vault_app holds only SELECT and INSERT on the table
// (migration 028), which is exactly what this needs.
func (r *LoginCountryRepo) UpsertAndWasNew(ctx context.Context, userID, cc string) (bool, bool, error) {
	var wasNew, hadAny bool
	err := r.db.Pool.QueryRow(ctx, `
		WITH prior AS (
			SELECT count(*) AS n FROM auth.login_countries WHERE user_id = $1
		), ins AS (
			INSERT INTO auth.login_countries (user_id, country_code)
			VALUES ($1, $2)
			ON CONFLICT (user_id, country_code) DO NOTHING
			RETURNING 1
		)
		SELECT
			(SELECT count(*) FROM ins) > 0 AS was_new,
			(SELECT n FROM prior) > 0     AS had_any`,
		userID, cc,
	).Scan(&wasNew, &hadAny)
	if err != nil {
		return false, false, fmt.Errorf("upsert login country: %w", err)
	}
	return wasNew, hadAny, nil
}
