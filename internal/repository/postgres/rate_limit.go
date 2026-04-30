package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/repository"
)

// RateLimitRepo implements repository.RateLimitRepository using PostgreSQL.
type RateLimitRepo struct{ db *DB }

// NewRateLimitRepo creates a new PostgreSQL-backed rate limit repository.
func NewRateLimitRepo(db *DB) repository.RateLimitRepository { return &RateLimitRepo{db: db} }

// Increment atomically increments the counter for a key in the given time window using upsert.
func (r *RateLimitRepo) Increment(ctx context.Context, key string, window time.Time) (int, error) {
	var count int
	err := r.db.Pool.QueryRow(ctx,
		`INSERT INTO auth.rate_limits (key, count, window_start)
		 VALUES ($1, 1, $2)
		 ON CONFLICT (key, window_start) DO UPDATE SET count = auth.rate_limits.count + 1
		 RETURNING count`,
		key, window).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("increment rate limit: %w", err)
	}
	return count, nil
}

// Get returns the current counter value for a key in the given time window. Returns 0 if no entry exists.
func (r *RateLimitRepo) Get(ctx context.Context, key string, window time.Time) (int, error) {
	var count int
	err := r.db.Pool.QueryRow(ctx,
		`SELECT count FROM auth.rate_limits WHERE key=$1 AND window_start = $2`,
		key, window).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get rate limit: %w", err)
	}
	return count, nil
}

// DeleteExpired removes rate limit entries with windows older than the given time.
func (r *RateLimitRepo) DeleteExpired(ctx context.Context, before time.Time) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.rate_limits WHERE window_start < $1`, before)
	if err != nil {
		return fmt.Errorf("delete expired rate limits: %w", err)
	}
	return nil
}
