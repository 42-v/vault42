package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

func TestRedisCache(t *testing.T) {
	_, addr, cleanup := setupRedis(t)
	defer cleanup()

	t.Run("NewRedisCache", func(t *testing.T) {
		t.Run("successful connection", func(t *testing.T) {
			c, err := cache.NewRedisCache(addr, "", 0)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			defer c.Close()
		})

		t.Run("bad address", func(t *testing.T) {
			_, err := cache.NewRedisCache("localhost:1", "", 0)
			if err == nil {
				t.Fatal("expected error for bad address, got nil")
			}
		})
	})

	t.Run("Get", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "get-exist", "hello", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "get-exist")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "hello" {
				t.Fatalf("expected 'hello', got %q", val)
			}
		})

		t.Run("missing key returns ErrNotFound", func(t *testing.T) {
			_, err := c.Get(ctx, "no-such-key")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})

		t.Run("expired key returns ErrNotFound", func(t *testing.T) {
			if err := c.Set(ctx, "get-expire", "temp", 50*time.Millisecond); err != nil {
				t.Fatalf("set: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			_, err := c.Get(ctx, "get-expire")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound for expired key, got %v", err)
			}
		})
	})

	t.Run("Set", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("simple value", func(t *testing.T) {
			if err := c.Set(ctx, "set-simple", "value1", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "set-simple")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "value1" {
				t.Fatalf("expected 'value1', got %q", val)
			}
		})

		t.Run("with TTL", func(t *testing.T) {
			if err := c.Set(ctx, "set-ttl", "expires", 1*time.Second); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.Get(ctx, "set-ttl")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "expires" {
				t.Fatalf("expected 'expires', got %q", val)
			}
		})

		t.Run("overwrite existing", func(t *testing.T) {
			if err := c.Set(ctx, "set-overwrite", "first", 0); err != nil {
				t.Fatalf("set first: %v", err)
			}
			if err := c.Set(ctx, "set-overwrite", "second", 0); err != nil {
				t.Fatalf("set second: %v", err)
			}
			val, err := c.Get(ctx, "set-overwrite")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if val != "second" {
				t.Fatalf("expected 'second', got %q", val)
			}
		})
	})

	t.Run("Delete", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "del-exist", "deleteme", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			if err := c.Delete(ctx, "del-exist"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			_, err := c.Get(ctx, "del-exist")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound after delete, got %v", err)
			}
		})

		t.Run("non-existent key no error", func(t *testing.T) {
			if err := c.Delete(ctx, "del-nonexistent"); err != nil {
				t.Fatalf("expected no error deleting non-existent key, got %v", err)
			}
		})
	})

	t.Run("GetAndDelete", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "gad-exist", "onetime", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			val, err := c.GetAndDelete(ctx, "gad-exist")
			if err != nil {
				t.Fatalf("get and delete: %v", err)
			}
			if val != "onetime" {
				t.Fatalf("expected 'onetime', got %q", val)
			}
			// Verify key is gone
			_, err = c.Get(ctx, "gad-exist")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound after GetAndDelete, got %v", err)
			}
		})

		t.Run("missing key returns ErrNotFound", func(t *testing.T) {
			_, err := c.GetAndDelete(ctx, "gad-missing")
			if !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})
	})

	t.Run("Increment", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("first increment sets to 1", func(t *testing.T) {
			val, err := c.Increment(ctx, "inc-first", 0)
			if err != nil {
				t.Fatalf("increment: %v", err)
			}
			if val != 1 {
				t.Fatalf("expected 1, got %d", val)
			}
		})

		t.Run("multiple increments", func(t *testing.T) {
			for i := int64(1); i <= 5; i++ {
				val, err := c.Increment(ctx, "inc-multi", 0)
				if err != nil {
					t.Fatalf("increment %d: %v", i, err)
				}
				if val != i {
					t.Fatalf("increment %d: expected %d, got %d", i, i, val)
				}
			}
		})

		t.Run("with TTL", func(t *testing.T) {
			val, err := c.Increment(ctx, "inc-ttl", 1*time.Second)
			if err != nil {
				t.Fatalf("increment: %v", err)
			}
			if val != 1 {
				t.Fatalf("expected 1, got %d", val)
			}
			// Verify it exists before expiry
			exists, err := c.Exists(ctx, "inc-ttl")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if !exists {
				t.Fatal("expected key to exist before expiry")
			}
		})
	})

	t.Run("Exists", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		t.Run("existing key", func(t *testing.T) {
			if err := c.Set(ctx, "exists-yes", "here", 0); err != nil {
				t.Fatalf("set: %v", err)
			}
			exists, err := c.Exists(ctx, "exists-yes")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if !exists {
				t.Fatal("expected key to exist")
			}
		})

		t.Run("missing key", func(t *testing.T) {
			exists, err := c.Exists(ctx, "exists-no")
			if err != nil {
				t.Fatalf("exists: %v", err)
			}
			if exists {
				t.Fatal("expected key to not exist")
			}
		})
	})

	t.Run("Set with zero TTL persists indefinitely", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		if err := c.Set(ctx, "no-ttl-key", "forever", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		// Sleep briefly and confirm key still exists
		time.Sleep(100 * time.Millisecond)
		val, err := c.Get(ctx, "no-ttl-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "forever" {
			t.Fatalf("expected 'forever', got %q", val)
		}
	})

	t.Run("Get empty string value", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		if err := c.Set(ctx, "empty-val", "", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "empty-val")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "" {
			t.Fatalf("expected empty string, got %q", val)
		}
	})

	t.Run("Increment then Get returns string count", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		if _, err := c.Increment(ctx, "inc-then-get", 0); err != nil {
			t.Fatalf("increment: %v", err)
		}
		if _, err := c.Increment(ctx, "inc-then-get", 0); err != nil {
			t.Fatalf("increment: %v", err)
		}
		val, err := c.Get(ctx, "inc-then-get")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "2" {
			t.Fatalf("expected '2', got %q", val)
		}
	})

	t.Run("Delete then Exists returns false", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		if err := c.Set(ctx, "del-then-exists", "val", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		if err := c.Delete(ctx, "del-then-exists"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		exists, err := c.Exists(ctx, "del-then-exists")
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if exists {
			t.Fatal("expected key to not exist after delete")
		}
	})

	t.Run("Set large value", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		defer c.Close()
		ctx := context.Background()

		largeVal := string(make([]byte, 10000))
		if err := c.Set(ctx, "large-val", largeVal, 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "large-val")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(val) != 10000 {
			t.Fatalf("expected value of length 10000, got %d", len(val))
		}
	})

	t.Run("Close", func(t *testing.T) {
		c, err := cache.NewRedisCache(addr, "", 0)
		if err != nil {
			t.Fatalf("create cache: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// After close, operations should fail
		_, err = c.Get(context.Background(), "any")
		if err == nil {
			t.Fatal("expected error after close, got nil")
		}
	})
}
