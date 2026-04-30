package cache

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresCache implements Cache using PostgreSQL as a fallback.
type PostgresCache struct {
	pool *pgxpool.Pool
}

// NewPostgresCache creates a PostgreSQL-backed cache (fallback).
// The cache table must exist via migration (017_create_cache_table.sql).
func NewPostgresCache(pool *pgxpool.Pool) (*PostgresCache, error) {
	return &PostgresCache{pool: pool}, nil
}

// Get retrieves a value by key, filtering out expired entries. Returns ErrNotFound if missing.
func (p *PostgresCache) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := p.pool.QueryRow(ctx, `
		SELECT value FROM auth.cache WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())
	`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return value, nil
}

// Set stores a key-value pair with an optional TTL using an upsert.
func (p *PostgresCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3
	`, key, value, expiresAt)
	return err
}

// Delete removes a key from the cache table.
func (p *PostgresCache) Delete(ctx context.Context, key string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM auth.cache WHERE key = $1`, key)
	return err
}

// GetAndDelete atomically retrieves and removes a key using DELETE ... RETURNING.
func (p *PostgresCache) GetAndDelete(ctx context.Context, key string) (string, error) {
	var value string
	err := p.pool.QueryRow(ctx, `
		DELETE FROM auth.cache WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW()) RETURNING value
	`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return value, nil
}

// SetIfNotExists atomically inserts a key only if it does not already exist (or has expired).
// Returns true if the key was inserted, false if it already existed and is still valid.
// Uses a single atomic SQL statement to avoid TOCTOU race conditions.
func (p *PostgresCache) SetIfNotExists(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}
	// Single atomic statement: insert if key is missing OR has expired.
	// The CTE deletes expired entries and the INSERT uses ON CONFLICT DO NOTHING
	// for non-expired keys, avoiding the previous TOCTOU race.
	tag, err := p.pool.Exec(ctx, `
		WITH cleanup AS (
			DELETE FROM auth.cache WHERE key = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()
		)
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO NOTHING
	`, key, value, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Increment atomically increments a counter key using an upsert and returns the new value.
// If the existing key has expired, the counter resets to 1 with a fresh TTL.
func (p *PostgresCache) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}
	var count int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, '1', $2)
		ON CONFLICT (key) DO UPDATE SET
			value = CASE
				WHEN auth.cache.expires_at IS NOT NULL AND auth.cache.expires_at <= NOW() THEN '1'
				ELSE (COALESCE(auth.cache.value, '0')::int + 1)::text
			END,
			expires_at = CASE
				WHEN auth.cache.expires_at IS NOT NULL AND auth.cache.expires_at > NOW()
					THEN auth.cache.expires_at
				ELSE EXCLUDED.expires_at
			END
		RETURNING value::int
	`, key, expiresAt).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Exists checks whether a non-expired key exists in the cache table.
func (p *PostgresCache) Exists(ctx context.Context, key string) (bool, error) {
	_, err := p.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Close is a no-op because the connection pool is managed externally.
func (p *PostgresCache) Close() error {
	return nil // Pool is managed externally
}
