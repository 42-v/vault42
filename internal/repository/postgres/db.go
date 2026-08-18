// Package postgres implements the repository interfaces using PostgreSQL via pgx.
package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// idleInTransactionTimeout bounds a session that has opened a transaction and
// then stopped talking. Not configurable: no path in this service holds a
// transaction open across a network wait, so a session that does is a bug or a
// stalled peer, and either way it is holding row locks the rest of the pool
// needs.
const idleInTransactionTimeout = 30 * time.Second

// Options are the pool bounds a caller may set. The zero value is valid and
// means "no server-side ceiling", which is what this package did before.
type Options struct {
	// MaxConns is the pool size. Values outside [1, 1000] are ignored.
	MaxConns int
	// StatementTimeout is the server-side ceiling on a single statement.
	//
	// It is set as a startup runtime parameter, so every connection the pool
	// opens carries it. Client-side context cancellation is not a substitute:
	// it needs a round trip to a server that may itself be the thing that is
	// stuck, and it does not cover the background sweepers at all. Without a
	// ceiling, MaxConns pathological queries — a missing index after a data
	// shape change, a lock wait, a sequential scan on a grown audit table —
	// pin the entire pool until MaxConnLifetime an hour later, and the service
	// stops serving with no error anywhere.
	StatementTimeout time.Duration
	// LockTimeout is the server-side ceiling on waiting for a lock. Shorter
	// than StatementTimeout on purpose: a statement that is merely slow should
	// be allowed to finish, while one queued behind somebody else's lock should
	// give up early and let its caller retry.
	LockTimeout time.Duration
}

// DB holds the connection pool for the application.
type DB struct {
	Pool *pgxpool.Pool
}

// New creates a new DB with a connection pool and the default ceilings.
func New(ctx context.Context, connString string, maxConns int) (*DB, error) {
	return NewWithOptions(ctx, connString, Options{MaxConns: maxConns})
}

// NewWithOptions creates a pool with explicit server-side ceilings.
func NewWithOptions(ctx context.Context, connString string, opts Options) (*DB, error) {
	config, err := poolConfig(connString, opts)
	if err != nil {
		return nil, err
	}

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

// poolConfig builds the pgx configuration. Separate from NewWithOptions so the
// bounds can be asserted without a live server.
func poolConfig(connString string, opts Options) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if opts.MaxConns > 0 && opts.MaxConns <= 1000 {
		config.MaxConns = int32(opts.MaxConns) // #nosec G115 -- bounded to [1, 1000]
	}
	config.MaxConnIdleTime = 15 * time.Minute
	config.MaxConnLifetime = 1 * time.Hour
	// Without jitter every connection opened at startup expires at the same
	// instant, and the whole pool reconnects in lockstep once an hour, forever.
	config.MaxConnLifetimeJitter = config.MaxConnLifetime / 5

	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	setTimeoutParam(config.ConnConfig.RuntimeParams, "statement_timeout", opts.StatementTimeout)
	setTimeoutParam(config.ConnConfig.RuntimeParams, "lock_timeout", opts.LockTimeout)
	setTimeoutParam(config.ConnConfig.RuntimeParams, "idle_in_transaction_session_timeout", idleInTransactionTimeout)
	return config, nil
}

// setTimeoutParam writes a Postgres timeout runtime parameter in milliseconds.
// A non-positive duration leaves the parameter unset, so an operator who turns
// a ceiling off gets the server's own default rather than a value this package
// invented for them.
func setTimeoutParam(params map[string]string, name string, d time.Duration) {
	if d <= 0 {
		return
	}
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	params[name] = strconv.FormatInt(ms, 10)
}

// Close closes the connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}
