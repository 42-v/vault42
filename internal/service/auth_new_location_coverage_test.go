package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

// These two tests close the remaining branches in notifyNewCountry that the
// behavior-focused tests in auth_new_location_test.go do not reach: the
// country-store error path, and the fail-open guard for a missing cache or email
// sender. Both must degrade to "no notice" without disturbing the login.

// TestNotifyNewCountry_UpsertErrorNoNotice drives the country store failing. The
// notice must be silently abandoned (logged, not surfaced) and nothing sent.
func TestNotifyNewCountry_UpsertErrorNoNotice(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			return false, false, errors.New("login-country store is down")
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	// 192.0.2.50 resolves to FR in the test table, so the country is non-empty and
	// the store is actually consulted (and fails).
	svc.notifyNewCountry("user-1", "user@example.com", "192.0.2.50", "")
	expectNoEmail(t, ch)
}

// TestNotifyNewCountry_NoCacheNoNotice drives a genuinely-new country for a user
// who already had one (so the throttle gate is reached) but with no cache wired.
// The fail-open guard must return before any send.
func TestNotifyNewCountry_NoCacheNoNotice(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			return true, true, nil // new country, user already had at least one
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	// Drop the cache the throttle gate needs; the notice must fail open to no-op.
	svc.cache = nil
	svc.notifyNewCountry("user-1", "user@example.com", "192.0.2.50", "") // FR
	expectNoEmail(t, ch)
}
