package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// TestLockoutFallsBackToTheDatabaseWhenTheCacheErrors closes a gap between two
// fallbacks that already existed.
//
// isAccountLocked has a durable fallback: when there is no cache at all it reads
// users.FailedLoginCount and enforces the threshold from the database, with a
// comment saying it exists to prevent unlimited brute force. That path was
// reached only when the cache was nil. A cache that was present and failing took
// the other branch, where any error answered "not locked" and the durable count
// was never consulted.
//
// So lockout held with no cache configured and did not hold when the configured
// cache broke, which is the case it was written for. During a Redis outage the
// pods stay in rotation, because a degraded cache still reports ready, and every
// account is unlocked no matter how many failures the database has recorded.
//
// An absent key is still not locked. That is a successful read returning no
// counter, which is what an account with no recent failures looks like; only an
// error falls back.
func TestLockoutFallsBackToTheDatabaseWhenTheCacheErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failures   int
		wantLocked bool
	}{
		{"database says the threshold was reached", lockoutThreshold, true},
		{"database says one short of it", lockoutThreshold - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
				o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, FailedLoginCount: tc.failures}, nil
				}
			})
			o.cache.GetFn = func(context.Context, string) (string, error) {
				return "", errors.New("redis: connection refused")
			}

			if got := svc.isAccountLocked(context.Background(), "user-1"); got != tc.wantLocked {
				t.Errorf("isAccountLocked = %v, want %v. A failing cache answered without "+
					"consulting users.FailedLoginCount, so during a cache outage the lockout "+
					"does not hold even though the database recorded %d failures.",
					got, tc.wantLocked, tc.failures)
			}
		})
	}
}

// TestLockoutTreatsAnAbsentKeyAsUnlocked keeps the common case cheap.
//
// Falling back on a missing key rather than on an error would put a database
// read in front of every login that has never failed, which is nearly all of
// them, to learn something the cache already answered correctly.
func TestLockoutTreatsAnAbsentKeyAsUnlocked(t *testing.T) {
	var dbReads int
	svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			dbReads++
			return &model.User{ID: id, FailedLoginCount: lockoutThreshold}, nil
		}
	})
	o.cache.GetFn = func(context.Context, string) (string, error) { return "", nil }

	if svc.isAccountLocked(context.Background(), "user-1") {
		t.Error("an account with no lockout counter was reported locked")
	}
	if dbReads != 0 {
		t.Errorf("the database was read %d time(s) for a cache hit that said no counter exists; "+
			"only an error should fall back", dbReads)
	}
}

// TestLockoutStillReadsTheCacheWhenItWorks is the negative control: the cache
// remains the authority when it can answer.
func TestLockoutStillReadsTheCacheWhenItWorks(t *testing.T) {
	svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, FailedLoginCount: 0}, nil
		}
	})
	o.cache.GetFn = func(context.Context, string) (string, error) { return "9", nil }

	if !svc.isAccountLocked(context.Background(), "user-1") {
		t.Error("a cache counter above the threshold did not lock the account, so the cache is " +
			"no longer the authority when it can answer")
	}
}
