package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// The role catalog sits on the hot path: every token issued and every profile
// update runs its roles through Filter, and Filter consults a cache that is
// refreshed lazily whenever the TTL has passed.
//
// A lazily-refreshed cache with no coordination is a cache stampede waiting to
// happen. The moment the TTL expires, every caller in flight sees a stale entry
// at the same instant, and every one of them independently issues its own
// ListNames query. Under the load this service is built for that is not one
// refresh per minute, it is one refresh per concurrent login per minute, all
// arriving on the database in the same millisecond, against a table whose whole
// purpose is to be tiny and cached. Nothing about it is incorrect, which is why
// it survives a review: the answers are all the same. It is an availability
// problem, and the connection pool is the thing that fails first.
//
// This test pins the refresh count, not the timing. It fails if the catalog
// goes back to letting every concurrent caller issue its own query at the
// expiry boundary.

const (
	roleStampedeCallers = 32
	// roleStampedeTTL is short enough for the test to cross the expiry
	// deliberately, and long enough that the burst below finishes well inside
	// the following window rather than tripping a second refresh by accident.
	roleStampedeTTL = 2 * time.Second
	// roleStampedeQueryCost widens the refresh window so that, without
	// coordination, all the callers really are inside ListNames at once. It is
	// what makes the failure deterministic rather than a matter of luck.
	roleStampedeQueryCost = 20 * time.Millisecond
	// roleStampedeMaxRefreshes is the bound. One refresh is the goal; the extra
	// one is slack for a caller that reached the staleness check just before the
	// refresher published, which is legitimate and not a stampede.
	roleStampedeMaxRefreshes = 2
)

func TestRoleCatalog_ExpiryDoesNotStampedeTheRepository(t *testing.T) {
	var calls atomic.Int32
	repo := &mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) {
			calls.Add(1)
			time.Sleep(roleStampedeQueryCost)
			return []string{"user", "moderator"}, nil
		},
	}
	c := NewRoleCatalog(repo, roleStampedeTTL)
	ctx := context.Background()

	// Prime the cache, then discard that load from the count: what is under test
	// is the refresh at expiry, not the cold start.
	c.Filter(ctx, []string{"user"})
	if got := calls.Load(); got != 1 {
		t.Fatalf("priming the catalog issued %d queries, want 1", got)
	}
	calls.Store(0)

	// Cross the expiry boundary, then release every caller at once so they all
	// observe the same stale entry.
	expire(c)

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([][]string, roleStampedeCallers)
	for i := 0; i < roleStampedeCallers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = c.Filter(ctx, []string{"moderator", "not_a_catalog_role"})
		}(i)
	}
	close(start)
	wg.Wait()

	if got := calls.Load(); got > roleStampedeMaxRefreshes {
		t.Errorf("%d concurrent callers at the expiry boundary issued %d ListNames queries, want at most %d: the refresh is stampeding the catalog table",
			roleStampedeCallers, got, roleStampedeMaxRefreshes)
	}
	if got := calls.Load(); got == 0 {
		t.Error("no refresh happened at all, so the cache never expired and the bound above proves nothing")
	}

	// The point of coordinating the refresh is that every caller still gets the
	// refreshed answer. A caller served a nil set would fail open and keep a
	// role the catalog does not list, which is the one outcome worse than the
	// stampede.
	for i, got := range results {
		if len(got) != 1 || got[0] != "moderator" {
			t.Fatalf("caller %d got %v, want [moderator]: a coordinated refresh must not hand back a stale or empty catalog", i, got)
		}
	}
}

// expire backdates the cache so the next call crosses the TTL boundary without
// the test having to sleep for it.
func expire(c *RoleCatalog) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadedAt = time.Now().Add(-2 * roleStampedeTTL)
}
