package config

import (
	"strings"
	"testing"
)

// productionCacheConfig reuses the package's existing valid production fixture
// and selects the redis cache on top of it, so this file asserts the cache
// check rather than re-deriving every other production requirement.
func productionCacheConfig() *Config {
	c := prodConfig()
	c.CacheBackend = "redis"
	c.RedisAddr = "redis.internal:6379"
	return c
}

// TestProductionRefusesRedisWithNoAddress closes the front half of a silent
// downgrade.
//
// The production profile defaults CACHE_BACKEND to "redis", and docs/config.md
// marks REDIS_ADDR as required when it is. Nothing checked. An unset REDIS_ADDR
// reached cache.NewCache, the ping failed, main logged one line and substituted
// an in-process memory cache, and the server came up reporting itself healthy.
//
// The cache is not a performance detail here. Every control the code
// deliberately routes through shared state becomes per-pod: with four replicas
// the login limiter admits four times its configured attempts, password reset
// and the KMS unwrap oracle likewise. Correctness breaks alongside it, because
// OAuth state written on the pod that served /authorize is read back on
// whichever pod serves the callback, and the TOTP replay guard only blocks a
// replay that lands on the same pod that saw the first use.
//
// Failing at boot is the only place this is cheap to notice.
func TestProductionRefusesRedisWithNoAddress(t *testing.T) {
	cfg := productionCacheConfig()
	cfg.RedisAddr = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a production config selecting the redis cache with no REDIS_ADDR was accepted; " +
			"it starts, silently falls back to a per-pod memory cache, and every shared-state " +
			"control degrades by the replica count")
	}
	if !strings.Contains(err.Error(), "REDIS_ADDR") {
		t.Errorf("error does not name REDIS_ADDR, so an operator cannot act on it: %v", err)
	}
}

// TestProductionAcceptsRedisWithAnAddress is the negative control. The check
// must not fire on the ordinary correct configuration.
func TestProductionAcceptsRedisWithAnAddress(t *testing.T) {
	if err := productionCacheConfig().Validate(); err != nil {
		t.Fatalf("a correct production config was rejected: %v", err)
	}
}

// TestProductionAcceptsANonRedisBackendWithNoRedisAddress keeps the check
// scoped to the backend that needs it. An operator who deliberately selects the
// postgres-backed cache, which is also shared across pods, must not be forced
// to set an address for a service they are not using.
func TestProductionAcceptsANonRedisBackendWithNoRedisAddress(t *testing.T) {
	for _, backend := range []string{"postgres", "memory"} {
		t.Run(backend, func(t *testing.T) {
			cfg := productionCacheConfig()
			cfg.CacheBackend = backend
			cfg.RedisAddr = ""

			if err := cfg.Validate(); err != nil {
				t.Fatalf("CACHE_BACKEND=%s with no REDIS_ADDR was rejected: %v", backend, err)
			}
		})
	}
}

// TestNonProductionProfilesStillAllowAnUnsetRedisAddress protects the local
// workflow. dev and embedded default to a memory cache, and someone who sets
// CACHE_BACKEND=redis there is experimenting rather than deploying; the
// fallback is a convenience for exactly that case.
func TestNonProductionProfilesStillAllowAnUnsetRedisAddress(t *testing.T) {
	for _, profile := range []Profile{ProfileDev, ProfileEmbedded} {
		t.Run(string(profile), func(t *testing.T) {
			cfg := productionCacheConfig()
			cfg.Profile = profile
			cfg.RedisAddr = ""

			if err := cfg.Validate(); err != nil {
				t.Fatalf("%s profile rejected an unset REDIS_ADDR: %v", profile, err)
			}
		})
	}
}
