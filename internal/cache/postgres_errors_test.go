package cache

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The Postgres cache is the fallback when Redis is absent, and it backs the same things
// Redis does: rate-limit counters, one-time reset tokens, OAuth state, email OTPs.
//
// Every one of these must report a database failure rather than return a zero value,
// because the zero values are indistinguishable from legitimate answers. A Get that
// returned ("", nil) reads as a cache miss. A SetNX that returned (true, nil) reads as
// "I took the lock" — and that bool is the single-use guarantee behind OTP redemption
// and OAuth state consumption. Fail it open and a one-time token becomes replayable.
func TestPostgresCache_SurfacesDatabaseFailures(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)

	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	if _, err := c.Get(ctx, "k"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if err := c.Set(ctx, "k", "v", time.Minute); err == nil {
		t.Error("Set reported success — the value was never stored and nothing said so")
	}
	if _, err := c.GetAndDelete(ctx, "k"); err == nil {
		t.Error("GetAndDelete returned no error — a single-use token would read as consumed")
	}

	ok, err := c.SetIfNotExists(ctx, "lock", "v", time.Minute)
	if err == nil {
		t.Error("SetIfNotExists reported success — the single-use guarantee would silently vanish")
	}
	if ok {
		t.Error("SetIfNotExists claimed it took the lock while the database was unreachable")
	}

	n, err := c.Increment(ctx, "rl:203.0.113.1", time.Minute)
	if err == nil {
		t.Error("Increment reported success — the rate limiter would fail open")
	}
	if n > 0 {
		t.Errorf("a failed Increment returned a count of %d", n)
	}

	if _, err := c.Exists(ctx, "k"); err == nil {
		t.Error("Exists returned no error against an unreachable database")
	}
	if err := c.Delete(ctx, "k"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
}
