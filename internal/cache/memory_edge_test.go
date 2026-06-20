package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Negative TTL edge case
// ---------------------------------------------------------------------------

func TestMemory_NegativeTTL_TreatedAsNoExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	// Negative TTL is not > 0, so the code sets exp to zero time (no expiry).
	// This means the entry persists indefinitely, same as TTL=0.
	err := c.Set(ctx, "neg", "val", -1*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Get returns value for negative TTL (treated as no expiry)", func(t *testing.T) {
		val, err := c.Get(ctx, "neg")
		if err != nil {
			t.Errorf("expected value, got error: %v", err)
		}
		if val != "val" {
			t.Errorf("got %q, want val", val)
		}
	})

	t.Run("Exists returns true for negative TTL", func(t *testing.T) {
		exists, err := c.Exists(ctx, "neg")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("negative TTL entry should exist (treated as no expiry)")
		}
	})
}

// ---------------------------------------------------------------------------
// Very short TTL race condition
// ---------------------------------------------------------------------------

func TestMemory_VeryShortTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "flash", "val", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	t.Run("expired after 1ms TTL", func(t *testing.T) {
		_, err := c.Get(ctx, "flash")
		if !errors.Is(err, ErrNotFound) {
			t.Error("1ms TTL entry should be expired")
		}
	})
}

// ---------------------------------------------------------------------------
// Key patterns
// ---------------------------------------------------------------------------

func TestMemory_SpecialKeyPatterns(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	keys := []struct {
		name string
		key  string
	}{
		{"empty key", ""},
		{"space key", " "},
		{"tab key", "\t"},
		{"newline key", "\n"},
		{"null byte key", "\x00"},
		{"unicode key", "\u00e4\u00f6\u00fc\u00df"},
		{"emoji key", "\U0001f512\U0001f511"},
		{"colon-separated", "rate:limit:user:123"},
		{"dot-separated", "session.token.hash"},
		{"slash key", "user/profile/123"},
		{"backslash key", "path\\to\\key"},
	}

	for _, tt := range keys {
		t.Run(tt.name, func(t *testing.T) {
			err := c.Set(ctx, tt.key, "value-for-"+tt.name, time.Minute)
			if err != nil {
				t.Fatalf("Set error: %v", err)
			}

			val, err := c.Get(ctx, tt.key)
			if err != nil {
				t.Fatalf("Get error: %v", err)
			}
			if val != "value-for-"+tt.name {
				t.Errorf("got %q, want %q", val, "value-for-"+tt.name)
			}
		})
	}
}

func TestMemory_VeryLongKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	longKey := strings.Repeat("k", 10000)

	t.Run("set and get long key", func(t *testing.T) {
		err := c.Set(ctx, longKey, "long-key-value", time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		val, err := c.Get(ctx, longKey)
		if err != nil {
			t.Fatal(err)
		}
		if val != "long-key-value" {
			t.Errorf("got %q, want %q", val, "long-key-value")
		}
	})

	t.Run("delete long key", func(t *testing.T) {
		err := c.Delete(ctx, longKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.Get(ctx, longKey)
		if !errors.Is(err, ErrNotFound) {
			t.Error("deleted long key should not be found")
		}
	})
}

// ---------------------------------------------------------------------------
// Large value
// ---------------------------------------------------------------------------

func TestMemory_VeryLargeValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	// 1 MB value
	largeVal := strings.Repeat("x", 1<<20)

	t.Run("set and get 1MB value", func(t *testing.T) {
		err := c.Set(ctx, "large", largeVal, time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		val, err := c.Get(ctx, "large")
		if err != nil {
			t.Fatal(err)
		}
		if len(val) != 1<<20 {
			t.Errorf("value length = %d, want %d", len(val), 1<<20)
		}
	})
}

// ---------------------------------------------------------------------------
// Empty value
// ---------------------------------------------------------------------------

func TestMemory_EmptyStringValue(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	t.Run("set and get empty string", func(t *testing.T) {
		c.Set(ctx, "empty-val", "", time.Minute)
		val, err := c.Get(ctx, "empty-val")
		if err != nil {
			t.Fatal(err)
		}
		if val != "" {
			t.Errorf("got %q, want empty string", val)
		}
	})

	t.Run("exists returns true for empty value", func(t *testing.T) {
		exists, err := c.Exists(ctx, "empty-val")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("key with empty value should exist")
		}
	})
}

// ---------------------------------------------------------------------------
// Concurrent stress tests
// ---------------------------------------------------------------------------

func TestMemory_ConcurrentSetGetDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	goroutines := 100
	iterations := 50

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("conc_%d", id)
			for i := 0; i < iterations; i++ {
				c.Set(ctx, key, fmt.Sprintf("val_%d_%d", id, i), time.Minute)
				c.Get(ctx, key)
				c.Exists(ctx, key)
				if i%10 == 0 {
					c.Delete(ctx, key)
				}
			}
		}(g)
	}
	wg.Wait()
	// No panic or data race = success
}

func TestMemory_ConcurrentIncrement_Correctness(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	goroutines := 200
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Increment(ctx, "atomic-counter", time.Minute)
		}()
	}
	wg.Wait()

	t.Run("counter equals goroutine count", func(t *testing.T) {
		val, err := c.Get(ctx, "atomic-counter")
		if err != nil {
			t.Fatal(err)
		}
		if val != fmt.Sprintf("%d", goroutines) {
			t.Errorf("counter = %s, want %d", val, goroutines)
		}
	})
}

func TestMemory_ConcurrentGetAndDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	rounds := 50
	winners := 0

	for r := 0; r < rounds; r++ {
		c.Set(ctx, "race-key", "prize", time.Minute)

		var wg sync.WaitGroup
		wins := make(chan struct{}, 5)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := c.GetAndDelete(ctx, "race-key")
				if err == nil {
					wins <- struct{}{}
				}
			}()
		}
		wg.Wait()
		close(wins)

		count := 0
		for range wins {
			count++
		}
		if count != 1 {
			t.Errorf("round %d: expected exactly 1 winner, got %d", r, count)
		}
		winners += count
	}

	t.Run("all rounds had exactly one winner", func(t *testing.T) {
		if winners != rounds {
			t.Errorf("total winners = %d, want %d", winners, rounds)
		}
	})
}

// ---------------------------------------------------------------------------
// Overwrite with different TTL
// ---------------------------------------------------------------------------

func TestMemory_OverwriteExtendsExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	t.Run("short TTL overwritten with longer TTL", func(t *testing.T) {
		c.Set(ctx, "extend", "v1", 30*time.Millisecond)
		c.Set(ctx, "extend", "v2", time.Minute) // Extend

		time.Sleep(50 * time.Millisecond)

		val, err := c.Get(ctx, "extend")
		if err != nil {
			t.Fatal("should still exist after original TTL would have expired")
		}
		if val != "v2" {
			t.Errorf("got %q, want v2", val)
		}
	})
}

func TestMemory_OverwriteShortensExpiry(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	t.Run("long TTL overwritten with shorter TTL", func(t *testing.T) {
		c.Set(ctx, "shorten", "v1", time.Minute)
		c.Set(ctx, "shorten", "v2", 20*time.Millisecond) // Shorten

		time.Sleep(40 * time.Millisecond)

		_, err := c.Get(ctx, "shorten")
		if !errors.Is(err, ErrNotFound) {
			t.Error("should be expired after shortened TTL")
		}
	})
}

// ---------------------------------------------------------------------------
// Increment edge cases
// ---------------------------------------------------------------------------

func TestMemory_IncrementAfterDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Increment(ctx, "del-inc", time.Minute)
	c.Increment(ctx, "del-inc", time.Minute)
	c.Delete(ctx, "del-inc")

	t.Run("restarts from 1 after delete", func(t *testing.T) {
		v, err := c.Increment(ctx, "del-inc", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if v != 1 {
			t.Errorf("increment after delete = %d, want 1", v)
		}
	})
}

func TestMemory_IncrementManyKeys(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	keyCount := 100
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		for j := 0; j <= i; j++ {
			c.Increment(ctx, key, time.Minute)
		}
	}

	t.Run("each key has correct count", func(t *testing.T) {
		for i := 0; i < keyCount; i++ {
			key := fmt.Sprintf("key-%d", i)
			val, err := c.Get(ctx, key)
			if err != nil {
				t.Fatalf("key %s: %v", key, err)
			}
			want := fmt.Sprintf("%d", i+1)
			if val != want {
				t.Errorf("key %s = %s, want %s", key, val, want)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Zero TTL means no expiry
// ---------------------------------------------------------------------------

func TestMemory_ZeroTTL_NeverExpires(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "permanent", "forever", 0)

	// Even after some time, it should persist
	time.Sleep(50 * time.Millisecond)

	t.Run("still exists after delay", func(t *testing.T) {
		val, err := c.Get(ctx, "permanent")
		if err != nil {
			t.Fatalf("zero TTL key should not expire: %v", err)
		}
		if val != "forever" {
			t.Errorf("got %q, want forever", val)
		}
	})

	t.Run("exists returns true", func(t *testing.T) {
		exists, err := c.Exists(ctx, "permanent")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("zero TTL key should exist")
		}
	})
}

// ---------------------------------------------------------------------------
// GetAndDelete on expired entries
// ---------------------------------------------------------------------------

func TestMemory_GetAndDelete_NegativeTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	// Negative TTL is treated as no expiry (same as zero TTL)
	c.Set(ctx, "neg-gad", "val", -1*time.Second)

	t.Run("returns value for negative TTL (treated as no expiry)", func(t *testing.T) {
		val, err := c.GetAndDelete(ctx, "neg-gad")
		if err != nil {
			t.Errorf("expected value, got error: %v", err)
		}
		if val != "val" {
			t.Errorf("got %q, want val", val)
		}
	})

	t.Run("key is deleted after GetAndDelete", func(t *testing.T) {
		_, err := c.Get(ctx, "neg-gad")
		if !errors.Is(err, ErrNotFound) {
			t.Error("key should be deleted after GetAndDelete")
		}
	})
}

// ---------------------------------------------------------------------------
// Increment with zero TTL
// ---------------------------------------------------------------------------

func TestMemory_IncrementZeroTTL_Persists(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	c.Increment(ctx, "perm-cnt", 0)
	c.Increment(ctx, "perm-cnt", 0)
	c.Increment(ctx, "perm-cnt", 0)

	time.Sleep(50 * time.Millisecond)

	t.Run("persists after delay", func(t *testing.T) {
		val, err := c.Get(ctx, "perm-cnt")
		if err != nil {
			t.Fatal(err)
		}
		if val != "3" {
			t.Errorf("got %q, want 3", val)
		}
	})
}

// ---------------------------------------------------------------------------
// Mixed operations on same key
// ---------------------------------------------------------------------------

func TestMemory_MixedOperationsSameKey(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	t.Run("set then increment reads incremented value", func(t *testing.T) {
		c.Set(ctx, "mixed", "5", time.Minute)
		v, err := c.Increment(ctx, "mixed", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if v != 6 {
			t.Errorf("increment after set(5) = %d, want 6", v)
		}
	})

	t.Run("increment then set overwrites", func(t *testing.T) {
		c.Increment(ctx, "mixed2", time.Minute)
		c.Set(ctx, "mixed2", "hello", time.Minute)
		val, err := c.Get(ctx, "mixed2")
		if err != nil {
			t.Fatal(err)
		}
		if val != "hello" {
			t.Errorf("got %q, want hello", val)
		}
	})
}

// ---------------------------------------------------------------------------
// Close idempotency edge case
// ---------------------------------------------------------------------------

func TestMemory_OperationsAfterClose(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	// Pre-populate
	c.Set(ctx, "before-close", "val", time.Minute)
	c.Close()

	// Operations after close should still work on the map (no panic)
	t.Run("Set after close no panic", func(t *testing.T) {
		err := c.Set(ctx, "after-close", "val", time.Minute)
		if err != nil {
			t.Errorf("Set after close should not error: %v", err)
		}
	})

	t.Run("Get after close no panic", func(t *testing.T) {
		_, _ = c.Get(ctx, "before-close")
		// Just verifying no panic
	})

	t.Run("Delete after close no panic", func(t *testing.T) {
		_ = c.Delete(ctx, "before-close")
		// Just verifying no panic
	})
}

// TestMemory_IncrementExists_Table covers Increment and Exists paths.
func TestMemory_IncrementExists_Table(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	v, err := c.Increment(ctx, "inc1", time.Minute)
	if err != nil || v != 1 {
		t.Errorf("inc1: got %d err=%v", v, err)
	}
	v, err = c.Increment(ctx, "inc1", time.Minute)
	if err != nil || v != 2 {
		t.Errorf("inc1 again: got %d", v)
	}

	exists1, e1 := c.Exists(ctx, "inc1")
	if e1 != nil || !exists1 {
		t.Errorf("exists after inc: %v %v", exists1, e1)
	}
	exists2, e2 := c.Exists(ctx, "nope")
	if e2 != nil || exists2 {
		t.Errorf("exists missing: %v", exists2)
	}
}
