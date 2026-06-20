package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

func catalogOf(names ...string) *RoleCatalog {
	return NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) { return names, nil },
	}, time.Minute)
}

func TestRoleCatalog_Filter(t *testing.T) {
	c := catalogOf("user", "moderator", "premium_user")
	got := c.Filter(context.Background(), []string{"moderator", "bogus", "premium_user"})
	if len(got) != 2 || got[0] != "moderator" || got[1] != "premium_user" {
		t.Fatalf("Filter kept wrong roles: %v", got)
	}
}

func TestRoleCatalog_FailsOpenWhenNeverLoaded(t *testing.T) {
	c := NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) { return nil, errors.New("db down") },
	}, time.Minute)
	in := []string{"moderator", "anything"}
	got := c.Filter(context.Background(), in)
	if len(got) != 2 {
		t.Fatalf("should fail open (return input) when catalog never loaded, got %v", got)
	}
}

func TestRoleCatalog_CachesWithinTTL(t *testing.T) {
	var calls int32
	c := NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) {
			atomic.AddInt32(&calls, 1)
			return []string{"user"}, nil
		},
	}, time.Hour)
	for i := 0; i < 5; i++ {
		c.Valid(context.Background(), "user")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("catalog should load once within TTL, loaded %d times", n)
	}
}

func TestEffectiveRoles_NoCatalog(t *testing.T) {
	s := &AuthService{} // no catalog
	// admin-reserved stripped, non-empty preserved
	if got := s.effectiveRoles(context.Background(), []string{"moderator", "admin"}); len(got) != 1 || got[0] != "moderator" {
		t.Fatalf("admin should be stripped, moderator kept: %v", got)
	}
	// all stripped → ["user"] fallback
	if got := s.effectiveRoles(context.Background(), []string{"admin", "super_admin"}); len(got) != 1 || got[0] != "user" {
		t.Fatalf("expected [user] fallback, got %v", got)
	}
}

func TestEffectiveRoles_WithCatalog(t *testing.T) {
	s := &AuthService{roleCatalog: catalogOf("user", "moderator")}
	// bogus dropped (not in catalog), moderator kept
	if got := s.effectiveRoles(context.Background(), []string{"moderator", "bogus"}); len(got) != 1 || got[0] != "moderator" {
		t.Fatalf("non-catalog role should be dropped: %v", got)
	}
	// only non-catalog roles → ["user"] fallback
	if got := s.effectiveRoles(context.Background(), []string{"bogus"}); len(got) != 1 || got[0] != "user" {
		t.Fatalf("expected [user] fallback, got %v", got)
	}
	// admin stripped before catalog filtering too
	if got := s.effectiveRoles(context.Background(), []string{"admin", "moderator"}); len(got) != 1 || got[0] != "moderator" {
		t.Fatalf("admin must be stripped: %v", got)
	}
}
