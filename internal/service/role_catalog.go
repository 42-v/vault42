package service

import (
	"context"
	"sync"
	"time"

	"github.com/42-v/vault42/internal/repository"
)

// RoleCatalog caches the set of valid user role names from the auth.app_roles
// catalog and filters user role lists down to catalog members. It refreshes
// lazily on a TTL and fails open: if the catalog has never loaded and a refresh
// errors, Filter returns its input unchanged (the admin-reserved filter applied
// upstream still prevents privilege escalation).
type RoleCatalog struct {
	repo repository.AppRoleRepository
	ttl  time.Duration

	mu       sync.RWMutex
	names    map[string]struct{}
	loadedAt time.Time
}

// NewRoleCatalog creates a catalog cache backed by repo, refreshing every ttl
// (default 60s when ttl <= 0).
func NewRoleCatalog(repo repository.AppRoleRepository, ttl time.Duration) *RoleCatalog {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &RoleCatalog{repo: repo, ttl: ttl}
}

// current returns the cached name set, refreshing it if stale. On refresh error
// it returns the last known set (possibly nil if never loaded).
func (c *RoleCatalog) current(ctx context.Context) map[string]struct{} {
	c.mu.RLock()
	fresh := c.names != nil && time.Since(c.loadedAt) < c.ttl
	cached := c.names
	c.mu.RUnlock()
	if fresh {
		return cached
	}

	list, err := c.repo.ListNames(ctx)
	if err != nil {
		return cached // fail-open: keep last known
	}
	set := make(map[string]struct{}, len(list))
	for _, n := range list {
		set[n] = struct{}{}
	}
	c.mu.Lock()
	c.names = set
	c.loadedAt = time.Now()
	c.mu.Unlock()
	return set
}

// Valid reports whether name is a catalog role (refreshing the cache if stale).
func (c *RoleCatalog) Valid(ctx context.Context, name string) bool {
	set := c.current(ctx)
	if set == nil {
		return true // fail-open
	}
	_, ok := set[name]
	return ok
}

// Filter keeps only roles present in the catalog, preserving order. Fails open
// (returns roles unchanged) when the catalog is unavailable.
func (c *RoleCatalog) Filter(ctx context.Context, roles []string) []string {
	if len(roles) == 0 {
		return roles
	}
	set := c.current(ctx)
	if set == nil {
		return roles
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if _, ok := set[r]; ok {
			out = append(out, r)
		}
	}
	return out
}
