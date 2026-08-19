package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// AdminConfigRepo implements repository.AdminConfigRepository using PostgreSQL.
type AdminConfigRepo struct {
	db *DB
}

// NewAdminConfigRepo creates a new PostgreSQL-backed admin configuration repository.
func NewAdminConfigRepo(db *DB) *AdminConfigRepo {
	return &AdminConfigRepo{db: db}
}

// List returns all configuration key-value pairs.
func (r *AdminConfigRepo) List(ctx context.Context) (map[string]string, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT key, value FROM auth.admin_config ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("list admin config: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan admin config: %w", err)
		}
		result[k] = v
	}
	return result, rows.Err()
}

// Get retrieves a configuration value by key. Returns empty string if not found.
func (r *AdminConfigRepo) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := r.db.Pool.QueryRow(ctx, `SELECT value FROM auth.admin_config WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get admin config: %w", err)
	}
	return value, nil
}

// Set creates or updates a configuration key-value pair with an upsert.
func (r *AdminConfigRepo) Set(ctx context.Context, key, value string) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.admin_config (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, key, value)
	if err != nil {
		return fmt.Errorf("set admin config: %w", err)
	}
	return nil
}

// Delete removes a configuration entry by key.
func (r *AdminConfigRepo) Delete(ctx context.Context, key string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.admin_config WHERE key = $1`, key)
	if err != nil {
		return fmt.Errorf("delete admin config: %w", err)
	}
	return nil
}

// ClaimIfAbsent records value under key when the key holds nothing yet, and
// returns whatever the key holds afterwards.
//
// One statement rather than Get followed by Set, because the callers are two
// processes that can boot at the same moment. With a read then a write, both
// would find the key empty and the second write would overwrite the first, so
// two planes holding different HMAC secrets would each conclude they had
// recorded theirs and neither would notice the disagreement. ON CONFLICT makes
// the claim atomic.
//
// The DO UPDATE is a no-op assignment of the column to itself. It is there
// because ON CONFLICT DO NOTHING returns no row at all on a conflict, which is
// the one case the caller most needs an answer for: RETURNING then yields the
// incumbent value instead of nothing.
func (r *AdminConfigRepo) ClaimIfAbsent(ctx context.Context, key, value string) (string, error) {
	var stored string
	err := r.db.Pool.QueryRow(ctx, `
		INSERT INTO auth.admin_config (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = auth.admin_config.value
		RETURNING value`, key, value).Scan(&stored)
	if err != nil {
		return "", fmt.Errorf("claim admin config: %w", err)
	}
	return stored, nil
}
