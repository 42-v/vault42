package cache

import (
	"strings"
	"testing"
)

// A backend name the factory does not recognize used to fall through to the
// per-process memory cache, returning no error and logging nothing.
//
// In the production profile CACHE_BACKEND defaults to "redis", and the only
// config-level check on it compares against the exact string "redis". A
// one-character typo ("Redis", "rediss", "valkey") therefore passed validation,
// skipped the "redis backend requires REDIS_ADDR" guard, and left every replica
// holding a private copy of the shared security state: the account-lockout
// counters, the TOTP replay guard, the MFA challenge single-use set, the DPoP
// JTI replay set and every rate-limit bucket. With four replicas that is four
// times the login attempts before lockout, and one captured TOTP code can be
// redeemed once per replica inside its 90-second reuse window. main.go already
// knows how to report this (it warns and flips /readyz to cache=degraded) but
// only when the constructor returns an error, so the silent fallback was
// invisible everywhere including the startup banner, which echoes the typo back
// as if it were the live backend.
func TestNewCacheRejectsAnUnrecognizedBackendRatherThanSilentlyUsingPerProcessMemory(t *testing.T) {
	for _, name := range []string{"Redis", "rediss", "valkey", "memcached", "unknown_backend", "redis "} {
		t.Run(name, func(t *testing.T) {
			c, err := NewCache(name, "", "", nil)
			if c != nil {
				_ = c.Close()
			}
			if err == nil {
				t.Fatalf("NewCache(%q) returned a usable cache and no error; an unrecognized backend must not silently become a per-process memory cache", name)
			}
			if c != nil {
				t.Errorf("NewCache(%q) returned a cache alongside the error %v; the caller must not be handed a backend it did not ask for", name, err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("NewCache(%q) error %q does not name the rejected value; the operator needs to see the typo to fix it", name, err)
			}
		})
	}
}

// An empty backend name is not a typo. The embedded profile leaves
// CACHE_BACKEND unset on purpose and expects the in-process cache, and a
// library caller that passes "" is asking for the default rather than naming a
// backend that does not exist. Rejecting it would break single-process
// deployments that never wanted a shared cache in the first place.
func TestNewCacheStillTreatsAnEmptyBackendNameAsTheInProcessDefault(t *testing.T) {
	c, err := NewCache("", "", "", nil)
	if err != nil {
		t.Fatalf("NewCache(\"\") returned %v, want the in-process default", err)
	}
	defer c.Close() //nolint:errcheck // teardown
	if _, ok := c.(*MemoryCache); !ok {
		t.Fatalf("NewCache(\"\") returned %T, want *MemoryCache", c)
	}
}
