package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// resetKeyRecorder is a real memory cache that also remembers every reset
// token key written through it, so a test can name a link it never saw mailed.
type resetKeyRecorder struct {
	*cache.MemoryCache
	resetKeys []string
}

func (c *resetKeyRecorder) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if strings.HasPrefix(key, "reset:") {
		c.resetKeys = append(c.resetKeys, key)
	}
	return c.MemoryCache.Set(ctx, key, value, ttl)
}

// A second reset request must retire the first link.
//
// The reverse mapping pwreset_user:<id> holds one hash. ResetRequest used to
// overwrite it without deleting the token it named, so the first link stayed
// valid for its hour and was out of reach of every later invalidation: a
// completed reset and a password change both delete only the token the mapping
// names. Someone who had read one superseded mail kept a working link through
// the user's own attempts to contain it.
func TestResetRequestRetiresTheLinkItSupersedes(t *testing.T) {
	store := &resetKeyRecorder{MemoryCache: cache.NewMemoryCache()}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, e string) (*model.User, error) {
			return &model.User{ID: "u-1", Email: e}, nil
		},
	}
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		nil, newTestAuditLogger(), store,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/auth/password/reset",
			strings.NewReader(`{"email":"rider@example.test"}`))
		rec := httptest.NewRecorder()
		h.ResetRequest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}

	if len(store.resetKeys) != 2 {
		t.Fatalf("stored %d reset tokens over two requests, want 2", len(store.resetKeys))
	}
	ctx := context.Background()
	if v, _ := store.Get(ctx, store.resetKeys[0]); v != "" {
		t.Errorf("the first link still resolves to %q after a second request; it must be "+
			"retired, because nothing later can reach it", v)
	}
	if v, _ := store.Get(ctx, store.resetKeys[1]); v != "u-1" {
		t.Errorf("the newest link resolves to %q, want u-1", v)
	}
}
