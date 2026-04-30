package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
)

func TestNewCache(t *testing.T) {
	t.Run("memory backend", func(t *testing.T) {
		skipIfNoDocker(t) // consistent skip logic across the file

		c, err := cache.NewCache("memory", "", "", nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer c.Close()

		ctx := context.Background()
		if err := c.Set(ctx, "mem-factory-key", "value", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "mem-factory-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "value" {
			t.Fatalf("expected 'value', got %q", val)
		}
	})

	t.Run("memory backend is default for unknown type", func(t *testing.T) {
		skipIfNoDocker(t)

		c, err := cache.NewCache("unknown-backend", "", "", nil)
		if err != nil {
			t.Fatalf("expected no error for unknown backend (should default to memory), got %v", err)
		}
		defer c.Close()

		ctx := context.Background()
		if err := c.Set(ctx, "default-key", "val", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "default-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "val" {
			t.Fatalf("expected 'val', got %q", val)
		}
	})

	t.Run("redis backend with real Redis", func(t *testing.T) {
		_, addr, cleanup := setupRedis(t)
		defer cleanup()

		c, err := cache.NewCache("redis", addr, "", nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer c.Close()

		ctx := context.Background()
		if err := c.Set(ctx, "redis-factory-key", "redis-value", 5*time.Second); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "redis-factory-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "redis-value" {
			t.Fatalf("expected 'redis-value', got %q", val)
		}
	})

	t.Run("redis backend with bad address", func(t *testing.T) {
		skipIfNoDocker(t)

		_, err := cache.NewCache("redis", "localhost:1", "", nil)
		if err == nil {
			t.Fatal("expected error for redis with bad address, got nil")
		}
	})

	t.Run("postgres backend with real PostgreSQL", func(t *testing.T) {
		pool, _, cleanup := setupPostgres(t)
		defer cleanup()

		c, err := cache.NewCache("postgres", "", "", pool)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer c.Close()

		ctx := context.Background()
		if err := c.Set(ctx, "pg-factory-key", "pg-value", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "pg-factory-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "pg-value" {
			t.Fatalf("expected 'pg-value', got %q", val)
		}
	})

	t.Run("postgres backend with nil pool", func(t *testing.T) {
		skipIfNoDocker(t)

		_, err := cache.NewCache("postgres", "", "", nil)
		if err == nil {
			t.Fatal("expected error for postgres with nil pool, got nil")
		}
	})

	t.Run("empty backend defaults to memory", func(t *testing.T) {
		skipIfNoDocker(t)

		c, err := cache.NewCache("", "", "", nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer c.Close()

		ctx := context.Background()
		if err := c.Set(ctx, "empty-backend-key", "val", 0); err != nil {
			t.Fatalf("set: %v", err)
		}
		val, err := c.Get(ctx, "empty-backend-key")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if val != "val" {
			t.Fatalf("expected 'val', got %q", val)
		}
	})
}
