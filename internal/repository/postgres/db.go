// Package postgres implements the repository interfaces using PostgreSQL via pgx.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB holds the connection pool for the application.
type DB struct {
	Pool *pgxpool.Pool
}

// New creates a new DB with a connection pool.
func New(ctx context.Context, connString string, maxConns int) (*DB, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if maxConns > 0 && maxConns <= 1000 {
		config.MaxConns = int32(maxConns) // #nosec G115 -- bounded to [1, 1000]
	}
	config.MaxConnIdleTime = 15 * time.Minute
	config.MaxConnLifetime = 1 * time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close closes the connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}
