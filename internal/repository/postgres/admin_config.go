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
