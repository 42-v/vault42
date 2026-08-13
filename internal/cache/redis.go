package cache

import (
	"context"
	"errors"
	"strconv"
	"time"

	vredis "github.com/42-v/vault42/internal/redis"
)

// RedisCache implements Cache using Redis.
type RedisCache struct {
	client *vredis.Client
}

// NewRedisCache creates a Redis-backed cache.
func NewRedisCache(addr, password string, db int) (*RedisCache, error) {
	client := vredis.NewClient(&vredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		// Cleanup after failed ping; error is non-actionable.
		_ = client.Close()
		return nil, err
	}

	return &RedisCache{client: client}, nil
}

// Get retrieves a value by key from Redis. Returns ErrNotFound if the key does not exist.
func (r *RedisCache) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key)
	if errors.Is(err, vredis.Nil) {
		return "", ErrNotFound
	}
	return val, err
}

// Set stores a key-value pair in Redis with the given TTL.
func (r *RedisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl)
}

// Delete removes a key from Redis.
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	_, err := r.client.Del(ctx, key)
	return err
}

// GetAndDelete atomically retrieves and removes a key using Redis GETDEL.
func (r *RedisCache) GetAndDelete(ctx context.Context, key string) (string, error) {
	val, err := r.client.GetDel(ctx, key)
	if errors.Is(err, vredis.Nil) {
		return "", ErrNotFound
	}
	return val, err
}

// SetIfNotExists atomically sets a key only if it does not already exist using Redis SET NX.
func (r *RedisCache) SetIfNotExists(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl)
}

// incrWithExpireScript atomically increments a key and sets expiry only on the
// first increment (when the value transitions from 0 to 1). This eliminates
// the race condition between separate INCR and EXPIRE commands where a key
// could be incremented but never expire (causing permanent rate limiting).
//
// ARGV[1] is milliseconds, and a non-positive value leaves the counter with no
// expiry rather than deleting it, which is what PEXPIRE with a zero or negative
// argument would do.
const incrWithExpireScript = `local v=redis.call('INCR',KEYS[1]) if v==1 then local ms=tonumber(ARGV[1]) if ms and ms>0 then redis.call('PEXPIRE',KEYS[1],ms) end end return v`

// Increment atomically increments a counter and sets expiry on the first
// increment using a Lua script to avoid the INCR+EXPIRE race condition.
//
// The TTL travels in milliseconds. Converting through whole seconds floored the
// window, so a caller asking for anything under a second reached a clamp and a
// fractional window lost its remainder, while the memory and Postgres backends
// applied the duration as given. The counter's lifetime is the lockout and the
// rate-limit window, so the three backends have to measure it the same way.
func (r *RedisCache) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	val, err := r.client.Eval(ctx, incrWithExpireScript, 1, key, strconv.FormatInt(ttl.Milliseconds(), 10))
	if err != nil {
		return 0, err
	}
	return val, nil
}

// Exists checks whether a key exists in Redis.
func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	return r.client.Exists(ctx, key)
}

// Close closes the underlying Redis client connection.
func (r *RedisCache) Close() error {
	return r.client.Close()
}
