package cache

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"
)

type memEntry struct {
	value     string
	expiresAt time.Time
}

// memoryMaxEntries caps how many keys this cache holds.
//
// Every key here is attacker-chosen in practice. The rate limiter writes
// rl:<limiter>:ip:<addr> on every request including the ones it rejects, OAuth
// authorize writes one oauth_state:<nonce> per call, and the lockout and reset
// counters are keyed on identifiers a caller supplies. An IPv6 source has a /64
// to spend, so a million distinct keys at roughly 150 bytes each is ~150 MiB
// living for the window of whichever limiter was hit first — up to an hour —
// inside a 512 MiB pod. This backend is also what the process falls back to
// when Redis is unavailable, so the flood lands during an outage.
//
// 200k entries is generous for the legitimate working set (live sessions,
// reset tokens, in-flight OAuth states) and bounds the map to tens of MiB.
const memoryMaxEntries = 200_000

// MemoryCache is an in-memory cache with TTL expiry.
type MemoryCache struct {
	mu         sync.RWMutex
	data       map[string]memEntry
	maxEntries int
	// atCap latches the first refusal so a sustained flood logs once rather
	// than once per request, on the request path it is already saturating.
	atCap     bool
	done      chan struct{}
	closeOnce sync.Once
}

// NewMemoryCache creates a new in-memory cache with a cleanup goroutine.
func NewMemoryCache() *MemoryCache {
	return newMemoryCacheWithCap(memoryMaxEntries)
}

// newMemoryCacheWithCap builds a cache with an explicit entry cap, so a test
// can reach the cap without allocating the production one.
func newMemoryCacheWithCap(maxEntries int) *MemoryCache {
	mc := &MemoryCache{
		data:       make(map[string]memEntry),
		maxEntries: maxEntries,
		done:       make(chan struct{}),
	}
	go mc.cleanup(30 * time.Second)
	return mc
}

// admit reports whether a NEW key may be stored. Called with the write lock
// held.
//
// At the cap a new key is refused and an existing one still updates. Evicting
// instead would be worse than refusing: the entries worth keeping are the
// lockout, login-limiter and OTP keys, and an eviction policy driven by the
// flood is a policy the attacker writes. A refusal surfaces as ErrCacheFull,
// which the fail-closed limiters already answer with a 503 and the lockout
// already answers from the durable count.
func (m *MemoryCache) admit(key string) bool {
	if m.maxEntries <= 0 || len(m.data) < m.maxEntries {
		return true
	}
	if _, exists := m.data[key]; exists {
		return true
	}
	if !m.atCap {
		m.atCap = true
		log.Printf("WARNING: memory cache at %d entries; new keys are refused until the sweep frees space", m.maxEntries)
	}
	return false
}

// Get retrieves a value by key. Returns ErrNotFound if the key is missing or expired.
func (m *MemoryCache) Get(_ context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		return "", ErrNotFound
	}
	return e.value, nil
}

// Set stores a key-value pair with an optional TTL.
func (m *MemoryCache) Set(_ context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	if !m.admit(key) {
		return ErrCacheFull
	}
	m.data[key] = memEntry{value: value, expiresAt: exp}
	return nil
}

// Delete removes a key from the in-memory store.
func (m *MemoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// GetAndDelete atomically retrieves and removes a key. Returns ErrNotFound if missing or expired.
func (m *MemoryCache) GetAndDelete(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		return "", ErrNotFound
	}
	delete(m.data, key)
	return e.value, nil
}

// SetIfNotExists atomically sets a key only if it does not already exist. Returns true if set.
func (m *MemoryCache) SetIfNotExists(_ context.Context, key string, value string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if ok && (e.expiresAt.IsZero() || time.Now().Before(e.expiresAt)) {
		return false, nil // key already exists and is not expired
	}
	if !m.admit(key) {
		return false, ErrCacheFull
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.data[key] = memEntry{value: value, expiresAt: exp}
	return true, nil
}

// Increment atomically increments a counter stored as a string value and returns the new count.
// The TTL is only set on the first increment (or after expiry) to create a fixed window,
// matching the behavior of the Redis cache backend.
func (m *MemoryCache) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e, ok := m.data[key]
	var count int64
	var exp time.Time
	if ok && (e.expiresAt.IsZero() || now.Before(e.expiresAt)) {
		// Key exists and is not expired — increment and preserve original expiry
		count, _ = strconv.ParseInt(e.value, 10, 64)
		exp = e.expiresAt
	} else if ttl > 0 {
		// Key is new or expired — start fresh window with new TTL
		exp = now.Add(ttl)
	}
	if !m.admit(key) {
		return 0, ErrCacheFull
	}
	count++
	m.data[key] = memEntry{value: strconv.FormatInt(count, 10), expiresAt: exp}
	return count, nil
}

// Exists checks whether a key exists and has not expired.
func (m *MemoryCache) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		return false, nil
	}
	return true, nil
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (m *MemoryCache) Close() error {
	m.closeOnce.Do(func() { close(m.done) })
	return nil
}

func (m *MemoryCache) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for k, e := range m.data {
				if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		}
	}
}
