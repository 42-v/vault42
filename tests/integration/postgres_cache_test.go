package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

func TestPostgresCache(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	t.Run("NewPostgresCache", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if c == nil {
			t.Fatal("expected non-nil cache")
		}
	})

	t.Run("Get", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "pg-get-exist", "world", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "pg-get-exist")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "world" {
				t.Fatalf("expected 'world', got %q", val)
			}
		})

		t.Run("missing key returns ErrNotFound", func(t *testing.T) {
			_, err := c.Get(ctx, "pg-no-key")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})

		t.Run("expired key returns ErrNotFound", func(t *testing.T) {
			// Insert a key with a very short TTL
			if err := c.Set(ctx, "pg-get-expired", "temp", 50*time.Millisecond); err != nil {
				t.Fatalf("set: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			_, err := c.Get(ctx, "pg-get-expired")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound for expired key, got %v", err)
			}
		})
	})

	t.Run("Set", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("simple value", func(t *testing.T) {
			if err := c.Set(ctx, "pg-set-simple", "val1", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "pg-set-simple")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "val1" {
				t.Fatalf("expected 'val1', got %q", val)
			}
		})

		t.Run("with TTL", func(t *testing.T) {
			if err := c.Set(ctx, "pg-set-ttl", "expires", 5*time.Second); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "pg-set-ttl")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "expires" {
				t.Fatalf("expected 'expires', got %q", val)
			}
		})

		t.Run("update existing", func(t *testing.T) {
			if err := c.Set(ctx, "pg-set-update", "original", 0); err != nil {
				t.Fatalf("set original: %v", err)
			}
			if err := c.Set(ctx, "pg-set-update", "updated", 0); err != nil {
				t.Fatalf("set updated: %v", err)
			}
			val, err := c.Get(ctx, "pg-set-update")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "updated" {
				t.Fatalf("expected 'updated', got %q", val)
			}
		})
	})

	t.Run("Delete", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "pg-del-exist", "deleteme", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			if err := c.Delete(ctx, "pg-del-exist"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			_, err := c.Get(ctx, "pg-del-exist")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound after delete, got %v", err)
			}
		})

		t.Run("non-existent key no error", func(t *testing.T) {
			if err := c.Delete(ctx, "pg-del-nonexistent"); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	})

	t.Run("GetAndDelete", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "pg-gad-exist", "onetime", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.GetAndDelete(ctx, "pg-gad-exist")
			if err != nil {
				t.Fatalf("get and delete: %v", err)
			}
			if val != "onetime" {
				t.Fatalf("expected 'onetime', got %q", val)
			}
			// Verify key is gone
			_, err = c.Get(ctx, "pg-gad-exist")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound after GetAndDelete, got %v", err)
			}
		})

		t.Run("missing key returns ErrNotFound", func(t *testing.T) {
			_, err := c.GetAndDelete(ctx, "pg-gad-missing")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})
	})

	t.Run("Increment", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("first increment sets to 1", func(t *testing.T) {
			val, err := c.Increment(ctx, "pg-inc-first", 0)
			if err != nil {
				t.Fatalf("increment: %v", err)
			}
			if val != 1 {
				t.Fatalf("expected 1, got %d", val)
			}
		})

		t.Run("multiple increments", func(t *testing.T) {
			for i := int64(1); i <= 5; i++ {
				val, err := c.Increment(ctx, "pg-inc-multi", 0)
				if err != nil {
					t.Fatalf("increment %d: %v", i, err)
				}
				if val != i {
					t.Fatalf("increment %d: expected %d, got %d", i, i, val)
				}
			}
		})

		t.Run("with TTL", func(t *testing.T) {
			val, err := c.Increment(ctx, "pg-inc-ttl", 5*time.Second)
			if err != nil {
				t.Fatalf("increment: %v", err)
			}
			if val != 1 {
				t.Fatalf("expected 1, got %d", val)
			}
			// Verify it exists before expiry
			exists, err := c.Exists(ctx, "pg-inc-ttl")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if !exists {
				t.Fatal("expected key to exist before expiry")
			}
		})
	})

	t.Run("Exists", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "pg-exists-yes", "here", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			exists, err := c.Exists(ctx, "pg-exists-yes")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if !exists {
				t.Fatal("expected key to exist")
			}
		})

		t.Run("missing key", func(t *testing.T) {
			exists, err := c.Exists(ctx, "pg-exists-no")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if exists {
				t.Fatal("expected key to not exist")
			}
		})
	})

	t.Run("Set with zero TTL persists indefinitely", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		if err := c.Set(ctx, "pg-no-ttl", "forever", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		val, err := c.Get(ctx, "pg-no-ttl")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "forever" {
			t.Fatalf("expected 'forever', got %q", val)
		}
	})

	t.Run("Get empty string value", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		if err := c.Set(ctx, "pg-empty-val", "", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "pg-empty-val")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "" {
			t.Fatalf("expected empty string, got %q", val)
		}
	})

	t.Run("Increment then Get returns string count", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		if _, err := c.Increment(ctx, "pg-inc-get", 0); err != nil {
			t.Fatalf("increment: %v", err)
		}
		if _, err := c.Increment(ctx, "pg-inc-get", 0); err != nil {
			t.Fatalf("increment: %v", err)
		}
		val, err := c.Get(ctx, "pg-inc-get")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "2" {
			t.Fatalf("expected '2', got %q", val)
		}
	})

	t.Run("Delete then Exists returns false", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		ctx := context.Background()

		if err := c.Set(ctx, "pg-del-exists", "val", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		if err := c.Delete(ctx, "pg-del-exists"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		exists, err := c.Exists(ctx, "pg-del-exists")
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if exists {
			t.Fatal("expected key to not exist after delete")
		}
	})

	t.Run("Close", func(t *testing.T) {
		c, err := cache.NewPostgresCache(pool)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		// Close is a no-op (pool managed externally)
		if err := c.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// After close, operations should still work (pool is still open)
		ctx := context.Background()
		if err := c.Set(ctx, "pg-after-close", "stillworks", 0); err != nil {
			t.Fatalf("set after close: %v", err)
		}
		val, err := c.Get(ctx, "pg-after-close")
		if err != nil {
			t.Fatalf("get after close: %v", err)
		}
		if val != "stillworks" {
			t.Fatalf("expected 'stillworks', got %q", val)
		}
	})
}
