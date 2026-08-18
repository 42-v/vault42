// Package cache provides a pluggable key-value cache interface with Redis, in-memory, and PostgreSQL backends.
package cache

import (
	"context"
	"time"
)

// Cache is the pluggable cache interface used across The Vault.
type Cache interface {
	// Get retrieves a value by key. Returns ErrNotFound if the key does not exist or has expired.
	Get(ctx context.Context, key string) (string, error)
	// Set stores a key-value pair with an optional TTL. A zero TTL means no expiration.
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	// Delete removes a key from the cache.
	Delete(ctx context.Context, key string) error
	// GetAndDelete atomically retrieves a value and deletes the key.
	// Returns ErrNotFound if the key does not exist.
	GetAndDelete(ctx context.Context, key string) (string, error)
	// SetIfNotExists atomically sets a key only if it does not already exist.
	// Returns true if the key was set, false if it already existed.
	SetIfNotExists(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
	// Increment atomically increments a counter key and returns the new value. Sets expiry on first increment.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// Exists checks whether a key exists and has not expired.
	Exists(ctx context.Context, key string) (bool, error)
	// Close releases any resources held by the cache backend.
	Close() error
}

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "cache: key not found" }

// ErrCacheFull is returned when a backend refuses a NEW key because it has
// reached its entry cap.
//
// It is deliberately not ErrNotFound. Callers treat a miss as "no counter yet",
// which for a rate limiter or a lockout means "admit this request" — the last
// answer a saturated cache should give. A distinct error reaches the
// fail-closed limiters as the 503 they already emit for an unavailable cache,
// and reaches the lockout as the cache failure that falls back to the durable
// failed-login count.
var ErrCacheFull = errCacheFull{}

type errCacheFull struct{}

func (errCacheFull) Error() string { return "cache: entry cap reached" }
