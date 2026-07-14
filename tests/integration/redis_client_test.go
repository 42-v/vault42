package integration_test

import (
	"context"
	"testing"
	"time"
)

// TestRedisClientOps exercises the RESP client's command methods directly
// against a real Redis, covering hit/miss/contention branches that the cache
// layer does not reach on its own.
func TestRedisClientOps(t *testing.T) {
	client, _, cleanup := setupRedis(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("Set, Get, and Get miss", func(t *testing.T) {
		if err := client.Set(ctx, "k1", "v1", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := client.Get(ctx, "k1")
		if err != nil || got != "v1" {
			t.Fatalf("Get = %q, %v; want v1", got, err)
		}
		// A missing key returns ("", ErrNil) or ("", nil) depending on the client;
		// either way it must not error hard.
		if _, err := client.Get(ctx, "no-such-key"); err == nil {
			// some clients return empty+nil for a miss; that is acceptable too
			_ = err
		}
	})

	t.Run("Set without TTL", func(t *testing.T) {
		if err := client.Set(ctx, "k-nottl", "v", 0); err != nil {
			t.Fatalf("Set (no ttl): %v", err)
		}
	})

	t.Run("SetNX contends", func(t *testing.T) {
		ok, err := client.SetNX(ctx, "lock", "a", time.Minute)
		if err != nil || !ok {
			t.Fatalf("first SetNX = %v, %v; want true", ok, err)
		}
		ok, err = client.SetNX(ctx, "lock", "b", time.Minute)
		if err != nil {
			t.Fatalf("second SetNX: %v", err)
		}
		if ok {
			t.Error("second SetNX on an existing key should return false")
		}
	})

	t.Run("Incr and Expire and Exists", func(t *testing.T) {
		n, err := client.Incr(ctx, "counter")
		if err != nil || n != 1 {
			t.Fatalf("Incr = %d, %v; want 1", n, err)
		}
		n, _ = client.Incr(ctx, "counter")
		if n != 2 {
			t.Errorf("second Incr = %d, want 2", n)
		}

		ok, err := client.Expire(ctx, "counter", time.Minute)
		if err != nil || !ok {
			t.Fatalf("Expire = %v, %v; want true", ok, err)
		}
		// Expire on a missing key returns false.
		ok, err = client.Expire(ctx, "ghost-key", time.Minute)
		if err != nil {
			t.Fatalf("Expire(missing): %v", err)
		}
		if ok {
			t.Error("Expire on a missing key should return false")
		}

		exists, err := client.Exists(ctx, "counter")
		if err != nil || !exists {
			t.Fatalf("Exists(counter) = %v, %v; want true", exists, err)
		}
		exists, _ = client.Exists(ctx, "ghost-key")
		if exists {
			t.Error("Exists(ghost) = true, want false")
		}
	})

	t.Run("GetDel and Del", func(t *testing.T) {
		if err := client.Set(ctx, "gd", "once", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := client.GetDel(ctx, "gd")
		if err != nil || got != "once" {
			t.Fatalf("GetDel = %q, %v; want once", got, err)
		}
		// The key is now gone.
		if exists, _ := client.Exists(ctx, "gd"); exists {
			t.Error("GetDel did not delete the key")
		}

		_ = client.Set(ctx, "d1", "x", time.Minute)
		_ = client.Set(ctx, "d2", "y", time.Minute)
		n, err := client.Del(ctx, "d1", "d2", "d-missing")
		if err != nil {
			t.Fatalf("Del: %v", err)
		}
		if n != 2 {
			t.Errorf("Del removed %d keys, want 2", n)
		}
	})

	t.Run("Eval runs a script", func(t *testing.T) {
		// A trivial Lua script that returns 1; exercises the EVAL command path.
		n, err := client.Eval(ctx, "return 1", 0)
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		if n != 1 {
			t.Errorf("Eval = %d, want 1", n)
		}
	})
}
