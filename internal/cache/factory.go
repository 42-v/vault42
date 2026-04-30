package cache

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewCache creates a cache backend based on the given type.
func NewCache(backend string, redisAddr, redisPass string, pgPool *pgxpool.Pool) (Cache, error) {
	switch backend {
	case "redis":
		return NewRedisCache(redisAddr, redisPass, 0)
	case "memory":
		return NewMemoryCache(), nil
	case "postgres":
		if pgPool == nil {
			return nil, fmt.Errorf("cache: postgres backend requires a connection pool")
		}
		return NewPostgresCache(pgPool)
	default:
		return NewMemoryCache(), nil
	}
}
