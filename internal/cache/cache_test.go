package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	vredis "github.com/42-v/vault42/internal/redis"
)

// ---------------------------------------------------------------------------
// ErrNotFound tests
// ---------------------------------------------------------------------------

func TestErrNotFound_Error(t *testing.T) {
	msg := ErrNotFound.Error()
	if msg != "cache: key not found" {
		t.Errorf("ErrNotFound.Error() = %q, want %q", msg, "cache: key not found")
	}
}

func TestErrNotFound_WrappedErrorsIs(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("errors.Is on wrapped ErrNotFound should be true")
	}
}

// ---------------------------------------------------------------------------
// NewCache factory tests
// ---------------------------------------------------------------------------

func TestNewCache_Memory(t *testing.T) {
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache(memory) error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "fk", "fv", time.Minute); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	val, err := c.Get(ctx, "fk")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if val != "fv" {
		t.Errorf("got %q, want %q", val, "fv")
	}
}

// An unrecognized backend name is rejected rather than answered with a
// per-process cache. See
// TestNewCacheRejectsAnUnrecognizedBackendRatherThanSilentlyUsingPerProcessMemory
// for what a silent fallback costs in a multi-replica deployment.
func TestNewCache_UnknownBackendIsAnError(t *testing.T) {
	c, err := NewCache("unknown_backend", "", "", nil)
	if err == nil {
		if c != nil {
			_ = c.Close()
		}
		t.Fatal("NewCache(unknown_backend) must not return a cache")
	}
}

func TestNewCache_EmptyStringDefault(t *testing.T) {
	c, err := NewCache("", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache('') error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "ek", "ev", time.Minute); err != nil {
		t.Fatal(err)
	}
	val, err := c.Get(ctx, "ek")
	if err != nil {
		t.Fatal(err)
	}
	if val != "ev" {
		t.Errorf("got %q, want %q", val, "ev")
	}
}

func TestNewCache_RedisInvalidAddr(t *testing.T) {
	// Invalid address should fail to ping and return an error.
	_, err := NewCache("redis", "invalid:99999", "", nil)
	if err == nil {
		t.Fatal("NewCache(redis, invalid addr) should return error")
	}
}

func TestNewCache_PostgresNilPool(t *testing.T) {
	_, err := NewCache("postgres", "", "", nil)
	if err == nil || !strings.Contains(err.Error(), "postgres backend requires") {
		t.Errorf("expected postgres pool error, got %v", err)
	}
}

func TestNewPostgresCache(t *testing.T) {
	pc, err := NewPostgresCache(nil)
	if err != nil {
		t.Fatalf("NewPostgresCache(nil): %v", err)
	}
	if pc == nil {
		t.Fatal("nil")
	}
	if err := pc.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestMemoryCache_AllMethods(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"set", func() error { return c.Set(ctx, "k1", "v1", 0) }},
		{"set_ttl", func() error { return c.Set(ctx, "k2", "v2", time.Second) }},
		{"get", func() error { _, err := c.Get(ctx, "k1"); return err }},
		{"get_miss", func() error { _, err := c.Get(ctx, "nope"); return err }},
		{"getanddelete", func() error { _, err := c.GetAndDelete(ctx, "k1"); return err }},
		{"getanddelete_miss", func() error { _, err := c.GetAndDelete(ctx, "nope"); return err }},
		{"setifnotexists_new", func() error { _, err := c.SetIfNotExists(ctx, "k3", "v3", 0); return err }},
		{"setifnotexists_exists", func() error { _, err := c.SetIfNotExists(ctx, "k3", "xx", 0); return err }},
		{"exists", func() error { _, err := c.Exists(ctx, "k2"); return err }},
		{"exists_miss", func() error { _, err := c.Exists(ctx, "nope"); return err }},
		{"incr", func() error { _, err := c.Increment(ctx, "ctr", time.Minute); return err }},
		{"delete", func() error { return c.Delete(ctx, "k2") }},
		{"close_again", func() error { return c.Close() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("%s err=%v", tt.name, err)
			}
		})
	}
}

// An unreachable Redis has to look like a failure, not like an empty cache. The
// distinction is the whole of the fail-closed story: ErrNotFound tells the rate
// limiter and the lockout counter "no attempts recorded yet", so a wrapper that
// mapped a dead socket onto a miss would open the login endpoint every time the
// cache went down. Every method here must return a non-nil error that is not
// ErrNotFound.
func TestRedisCache_Methods_ErrorPaths(t *testing.T) {
	// Construct directly to bypass New's ping; use invalid client to exercise wrapper error paths.
	rc := &RedisCache{client: vredis.NewClient(&vredis.Options{Addr: "127.0.0.1:0"})}
	defer rc.Close()
	ctx := context.Background()

	// Both TTL spellings for the two methods that carry one: zero means "no
	// expiry" and travels a different path through the client than a real
	// duration does.
	cases := []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := rc.Get(ctx, "k"); return err }},
		{"Set", func() error { return rc.Set(ctx, "k", "v", 0) }},
		{"Delete", func() error { return rc.Delete(ctx, "k") }},
		{"GetAndDelete", func() error { _, err := rc.GetAndDelete(ctx, "k"); return err }},
		{"SetIfNotExists no ttl", func() error { _, err := rc.SetIfNotExists(ctx, "k", "v", 0); return err }},
		{"SetIfNotExists with ttl", func() error { _, err := rc.SetIfNotExists(ctx, "k", "v", time.Second); return err }},
		{"Increment no ttl", func() error { _, err := rc.Increment(ctx, "ctr", 0); return err }},
		{"Increment with ttl", func() error { _, err := rc.Increment(ctx, "ctr", time.Second); return err }},
		{"Exists", func() error { _, err := rc.Exists(ctx, "k"); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertOutageNotMiss(t, tc.name, tc.call())
		})
	}

	if err := rc.Close(); err != nil {
		t.Errorf("Close on a never-connected client = %v, want nil", err)
	}
}

// assertOutageNotMiss reports that a call against an unreachable backend failed,
// and failed as an outage rather than as a cache miss.
func assertOutageNotMiss(t *testing.T, name string, err error) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s against an unreachable Redis returned no error, so the caller is told the operation succeeded", name)
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("%s reported the outage as ErrNotFound (%v); a miss means \"no attempts yet\" and opens the endpoint", name, err)
	}
}

func TestNewCache_PostgresNilPoolMessage(t *testing.T) {
	_, err := NewCache("postgres", "", "", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	want := "cache: postgres backend requires a connection pool"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestNewCache_MemoryImplementsInterface(t *testing.T) {
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Verify the returned value satisfies Cache interface.
	_ = c
}

func TestNewCache_MemoryCloseIdempotent(t *testing.T) {
	// Close from factory-created cache should work.
	c, err := NewCache("memory", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
}

// Table driven for NewCache backends and defaults.
func TestNewCache_Table(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		redisA  string
		redisP  string
		pg      *struct{}
		wantErr bool
	}{
		{"memory explicit", "memory", "", "", nil, false},
		{"empty defaults memory", "", "", "", nil, false},
		{"unknown backend rejected", "foo", "", "", nil, true},
		{"redis bad", "redis", "bad:1", "", nil, true},
		{"postgres nil err", "postgres", "", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCache(tt.backend, tt.redisA, tt.redisP, nil)
			if tt.wantErr {
				if err == nil {
					t.Error("expected err")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if c == nil {
				t.Fatal("nil cache")
			}
			_ = c.Close()
		})
	}
}

// Table-driven coverage for Cache interface methods on memory backend (error paths + edges).
func TestMemoryCache_Methods_Table(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()

	tests := []struct {
		name         string
		run          func() (interface{}, error)
		wantNotFound bool
	}{
		{"Get missing", func() (interface{}, error) { return c.Get(ctx, "nope") }, true},
		{"GetAndDelete missing", func() (interface{}, error) { return c.GetAndDelete(ctx, "nope") }, true},
		{"Exists missing", func() (interface{}, error) { return c.Exists(ctx, "nope") }, false},
		{"Delete missing", func() (interface{}, error) { return nil, c.Delete(ctx, "nope") }, false},
		{"Set zero ttl", func() (interface{}, error) { return nil, c.Set(ctx, "z", "v", 0) }, false},
		{"Set pos ttl", func() (interface{}, error) { return nil, c.Set(ctx, "p", "v", time.Second) }, false},
		{"Increment", func() (interface{}, error) { return c.Increment(ctx, "ic", time.Second) }, false},
		{"SetIfNotExists new", func() (interface{}, error) { return c.SetIfNotExists(ctx, "sinew", "v", 0) }, false},
		{"Get after set", func() (interface{}, error) {
			c.Set(ctx, "g", "val", 0)
			return c.Get(ctx, "g")
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.run()
			if tt.wantNotFound {
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("want ErrNotFound got %v (got=%v)", err, got)
				}
			} else if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			_ = got
		})
	}
}

// The zero-value cache, with a zero TTL on every write. TestPostgresCache_Methods_NilPool
// runs the same methods through the constructor with a real TTL; the pair covers
// both sides of the "did the caller ask for an expiry" branch. The assertion is
// the same one and it is the point of both: with no pool behind it a method must
// fail rather than answer, because an answer here is a cache miss to the caller
// and a miss opens the rate limiter.
func TestPostgresCache_ZeroValueNeverAnswers(t *testing.T) {
	tests := []struct {
		name string
		run  func()
	}{
		{"Get", func() { _, _ = (&PostgresCache{}).Get(context.Background(), "k") }},
		{"Set ttl0", func() { _ = (&PostgresCache{}).Set(context.Background(), "k", "v", 0) }},
		{"Delete", func() { _ = (&PostgresCache{}).Delete(context.Background(), "k") }},
		{"GetAndDelete", func() { _, _ = (&PostgresCache{}).GetAndDelete(context.Background(), "k") }},
		{"SetIfNotExists ttl0", func() { _, _ = (&PostgresCache{}).SetIfNotExists(context.Background(), "k", "v", 0) }},
		{"Increment ttl0", func() { _, _ = (&PostgresCache{}).Increment(context.Background(), "k", 0) }},
		{"Exists", func() { _, _ = (&PostgresCache{}).Exists(context.Background(), "k") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s returned a value with no pool behind it; a caller cannot tell that from a real cache miss", tt.name)
				}
			}()
			tt.run()
		})
	}

	// A cache that never started a sweeper has a nil done channel, which is the
	// branch Close guards and the one the constructed cache never reaches.
	if err := (&PostgresCache{}).Close(); err != nil {
		t.Errorf("Close on a zero-value cache = %v, want nil", err)
	}
}
