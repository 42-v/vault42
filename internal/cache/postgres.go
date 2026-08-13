package cache

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sweep tuning for the expired-row reaper. Variables rather than constants so
// tests can drive a sweep without waiting out the production period.
var (
	pgSweepInterval = time.Minute
	// Delete in bounded batches: an existing deployment can already hold
	// millions of dead rows, and one unbounded DELETE against the live auth
	// database on the first tick after rollout is its own outage.
	pgSweepBatch      = 2000
	pgSweepMaxBatches = 20
	pgSweepTimeout    = 30 * time.Second
)

// PostgresCache implements Cache using PostgreSQL as a fallback.
type PostgresCache struct {
	pool      *pgxpool.Pool
	done      chan struct{}
	closeOnce sync.Once
}

// NewPostgresCache creates a PostgreSQL-backed cache (fallback).
// The cache table must exist via migration (017_create_cache_table.sql).
func NewPostgresCache(pool *pgxpool.Pool) (*PostgresCache, error) {
	p := &PostgresCache{pool: pool, done: make(chan struct{})}
	if pool != nil {
		go p.sweep(pgSweepInterval)
	}
	return p, nil
}

// sweep reclaims expired rows on a period.
//
// The read paths filter on expires_at but never delete, so without this the
// table only grows. Every request through the IP rate limiter mints a key with
// a TTL measured in seconds, which makes the growth rate the request rate and
// makes the eventual failure a write failure on the auth database. The memory
// backend and Redis both reclaim, so this is what keeps the three backends
// interchangeable rather than one of them being a slow disk leak.
func (p *PostgresCache) sweep(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.reapExpired()
		}
	}
}

// reapExpired deletes expired rows in bounded batches so a backlog is worked
// off over several ticks instead of in one statement that holds locks on the
// live table for as long as it takes.
func (p *PostgresCache) reapExpired() {
	ctx, cancel := context.WithTimeout(context.Background(), pgSweepTimeout)
	defer cancel()

	for i := 0; i < pgSweepMaxBatches; i++ {
		select {
		case <-p.done:
			return
		default:
		}
		tag, err := p.pool.Exec(ctx, `
			DELETE FROM auth.cache WHERE key IN (
				SELECT key FROM auth.cache
				WHERE expires_at IS NOT NULL AND expires_at <= NOW()
				LIMIT $1
			)
		`, pgSweepBatch)
		if err != nil {
			log.Printf("cache: expired-entry sweep failed: %v", err)
			return
		}
		if tag.RowsAffected() < int64(pgSweepBatch) {
			return
		}
	}
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
	// Single atomic statement, and one that needs no reasoning about what a
	// sub-statement can see. Deleting the expired row from a data-modifying CTE
	// and letting the INSERT fall through does not work: the arbiter index
	// resolves against the pre-command snapshot, so the INSERT conflicts with the
	// very row the same statement is deleting, DO NOTHING suppresses it, and the
	// call reports 0 rows. The caller is then told an expired key is still held
	// while the row backing that claim has just been deleted.
	//
	// Reclaiming the expired row in place keeps the whole decision in one index
	// probe under one row lock, which is also what makes concurrent callers
	// serialize: the loser re-evaluates the predicate against the winner's
	// committed row, finds a live expiry, and is refused.
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
		WHERE auth.cache.expires_at IS NOT NULL AND auth.cache.expires_at <= NOW()
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
	// bigint rather than int throughout: the Cache interface returns int64 and
	// the memory and Redis backends count in int64, so an int4 cast here would
	// make one backend raise "integer out of range" where the other two keep
	// counting, and Increment's error return is what sends a fail-closed rate
	// limiter to 503.
	var count int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO auth.cache (key, value, expires_at) VALUES ($1, '1', $2)
		ON CONFLICT (key) DO UPDATE SET
			value = CASE
				WHEN auth.cache.expires_at IS NOT NULL AND auth.cache.expires_at <= NOW() THEN '1'
				ELSE (COALESCE(auth.cache.value, '0')::bigint + 1)::text
			END,
			expires_at = CASE
				WHEN auth.cache.expires_at IS NOT NULL AND auth.cache.expires_at > NOW()
					THEN auth.cache.expires_at
				ELSE EXCLUDED.expires_at
			END
		RETURNING value::bigint
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

// Close stops the background sweep. The connection pool itself is managed
// externally and is deliberately left open. Safe to call multiple times.
func (p *PostgresCache) Close() error {
	p.closeOnce.Do(func() {
		if p.done != nil {
			close(p.done)
		}
	})
	return nil
}
