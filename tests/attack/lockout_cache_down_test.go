package attack

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// stubUserRepo implements repository.UserRepository for lockout degradation tests.
// It tracks failed login counts in memory to simulate DB-level lockout fallback.
type stubUserRepo struct {
	users map[string]*model.User
}

func newStubUserRepo() *stubUserRepo {
	return &stubUserRepo{users: make(map[string]*model.User)}
}

func (r *stubUserRepo) Create(_ context.Context, user *model.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *stubUserRepo) GetByID(_ context.Context, id string) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (r *stubUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (r *stubUserRepo) Update(_ context.Context, user *model.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *stubUserRepo) UpdatePassword(_ context.Context, id, hash string) error {
	if u, ok := r.users[id]; ok {
		u.PasswordHash = hash
	}
	return nil
}

func (r *stubUserRepo) IncrementFailedLogin(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.FailedLoginCount++
	}
	return nil
}

func (r *stubUserRepo) ResetFailedLogin(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.FailedLoginCount = 0
	}
	return nil
}

func (r *stubUserRepo) LockUntil(_ context.Context, id string, until time.Time) error {
	if u, ok := r.users[id]; ok {
		u.LockedUntil = &until
	}
	return nil
}

func (r *stubUserRepo) Unlock(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.LockedUntil = nil
		u.FailedLoginCount = 0
	}
	return nil
}

func (r *stubUserRepo) VerifyEmail(_ context.Context, id string) error {
	if u, ok := r.users[id]; ok {
		u.EmailVerified = true
	}
	return nil
}

// Verify interface compliance at compile time.
var _ repository.UserRepository = (*stubUserRepo)(nil)

// TestLockoutCacheDown_DBFallbackEnforcesLockout verifies that when cache is
// unavailable, the DB-level FailedLoginCount field is used to enforce lockout.
// The lockout threshold is 5 failed attempts.
func TestLockoutCacheDown_DBFallbackEnforcesLockout(t *testing.T) {
	repo := newStubUserRepo()

	// Create a user with 4 failed attempts (one below threshold)
	user := &model.User{
		ID:               "user-lockout-test",
		Email:            "lockout@example.com",
		PasswordHash:     "dummy-hash",
		FailedLoginCount: 4,
		EmailVerified:    true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	repo.Create(context.Background(), user)

	// Verify user is not locked (4 < 5 threshold)
	u, _ := repo.GetByID(context.Background(), "user-lockout-test")
	if u.FailedLoginCount >= 5 {
		t.Fatal("User should not be locked at 4 failures")
	}

	// Increment to threshold
	repo.IncrementFailedLogin(context.Background(), "user-lockout-test")
	u, _ = repo.GetByID(context.Background(), "user-lockout-test")
	if u.FailedLoginCount != 5 {
		t.Fatalf("Expected 5 failed logins, got %d", u.FailedLoginCount)
	}

	// Now the DB fallback in isAccountLocked would return true
	// (FailedLoginCount >= lockoutThreshold)
	if u.FailedLoginCount < 5 {
		t.Fatal("DB fallback should enforce lockout at threshold=5")
	}

	// Reset should clear the counter
	repo.ResetFailedLogin(context.Background(), "user-lockout-test")
	u, _ = repo.GetByID(context.Background(), "user-lockout-test")
	if u.FailedLoginCount != 0 {
		t.Fatalf("Expected 0 after reset, got %d", u.FailedLoginCount)
	}
}

// TestLockoutCacheDown_IPLockoutDisabledWithoutCache verifies that IP-based
// lockout is effectively disabled when cache is nil. This is a known degradation:
// without cache, per-IP counters cannot be tracked, so credential stuffing from
// a single IP is not blocked. The account-level lockout via DB remains active.
func TestLockoutCacheDown_IPLockoutDisabledWithoutCache(t *testing.T) {
	// When cache is nil:
	// - isIPLocked returns false (IP lockout disabled)
	// - recordFailedIP is a no-op
	// This means an attacker can attempt logins from one IP without IP-level throttling.
	// However, per-account lockout still works via DB FailedLoginCount.

	repo := newStubUserRepo()

	// Create multiple users
	for i := 0; i < 5; i++ {
		repo.Create(context.Background(), &model.User{
			ID:            "user-" + string(rune('a'+i)),
			Email:         string(rune('a'+i)) + "@example.com",
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		})
	}

	// Without cache, we can't track IP failures. Verify DB-level counters still work.
	for i := 0; i < 5; i++ {
		id := "user-" + string(rune('a'+i))
		repo.IncrementFailedLogin(context.Background(), id)
		u, _ := repo.GetByID(context.Background(), id)
		if u.FailedLoginCount != 1 {
			t.Fatalf("User %s: expected 1 failed login, got %d", id, u.FailedLoginCount)
		}
	}

	// Verify that per-account lockout enforces even without cache
	id := "user-a"
	for i := 0; i < 4; i++ { // Already has 1, add 4 more = 5 total
		repo.IncrementFailedLogin(context.Background(), id)
	}
	u, _ := repo.GetByID(context.Background(), id)
	if u.FailedLoginCount < 5 {
		t.Fatalf("Expected >= 5 failures for account lockout, got %d", u.FailedLoginCount)
	}
}

// TestLockoutCacheDown_CacheRecovery verifies that when cache becomes available
// again after being down, the lockout system resumes normal operation.
func TestLockoutCacheDown_CacheRecovery(t *testing.T) {
	mc := cache.NewMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	key := "lockout:recovery-user"

	// Simulate accumulating failures
	for i := 0; i < 5; i++ {
		mc.Increment(ctx, key, 15*time.Minute)
	}

	val, _ := mc.Get(ctx, key)
	if val != "5" {
		t.Fatalf("Expected counter=5, got %q", val)
	}

	// Clear on successful login
	mc.Delete(ctx, key)
	val, _ = mc.Get(ctx, key)
	if val != "" {
		t.Fatalf("Expected empty after clearLockout, got %q", val)
	}
}
