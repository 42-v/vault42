package cache

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewCache creates a cache backend based on the given type.
//
// An empty name is the caller declining to choose and gets the in-process
// cache. Any other unrecognized name is an error rather than a quiet fallback:
// the cache holds the lockout counters, the TOTP and DPoP replay guards, the
// MFA challenge single-use set and the rate-limit buckets, all of which stop
// being shared the moment a replica answers from its own memory. A typo in
// CACHE_BACKEND must not be the difference between one lockout threshold and
// one per replica, and the caller can only report the degradation it is told
// about.
//
// tlsOpts is forwarded to the Redis backend and ignored by the other two, which
// have no network link of their own to protect: the memory cache is in-process,
// and the Postgres one rides the pool the caller already opened under
// DB_SSLMODE.
func NewCache(backend string, redisAddr, redisPass string, pgPool *pgxpool.Pool, tlsOpts ...RedisTLS) (Cache, error) {
	switch backend {
	case "redis":
		return NewRedisCache(redisAddr, redisPass, 0, tlsOpts...)
	case "memory", "":
		return NewMemoryCache(), nil
	case "postgres":
		if pgPool == nil {
			return nil, fmt.Errorf("cache: postgres backend requires a connection pool")
		}
		return NewPostgresCache(pgPool)
	default:
		return nil, fmt.Errorf("cache: unknown backend %q (want redis, memory or postgres)", backend)
	}
}
