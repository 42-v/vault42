package service

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// CompleteMFALogin happy path: issues a token pair after a verified 2FA step.
func TestCompleteMFALoginSuccess(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user", "admin"}}, nil
	}

	res, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "127.0.0.1", "UA", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("expected a populated token pair")
	}
}

// A reused challenge token (single-use cache key already present) is rejected.
func TestCompleteMFALoginChallengeConsumed(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.cache.SetIfNotExistsFn = func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return false, nil
	}

	_, err := svc.CompleteMFALogin(context.Background(), "u", "fp", "ip", "ua", "jti-1")
	if !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("want ErrChallengeConsumed, got %v", err)
	}
}

// SECURITY: a cache failure during the single-use check must fail closed.
func TestCompleteMFALoginCacheFailsClosed(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.cache.SetIfNotExistsFn = func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return false, errors.New("redis unavailable")
	}

	if _, err := svc.CompleteMFALogin(context.Background(), "u", "fp", "ip", "ua", "jti-1"); err == nil {
		t.Fatal("expected fail-closed error when cache is unavailable")
	}
}

// A subject the repository cannot resolve after the second factor gets no
// session: a nil user (deleted inside the challenge window) and a read fault
// (which would otherwise hide a banned/disabled state and skip the account gate)
// both fail closed with ErrTokenInvalid, matching how Refresh treats the same
// reads. Previously a nil user fell back to a default-role session, and a read
// fault reached that same nil path, so a transient error minted tokens for an
// account whose banned state it hid.
func TestCompleteMFALoginRefusesUnresolvableUser(t *testing.T) {
	for _, tc := range []struct {
		name string
		get  func(context.Context, string) (*model.User, error)
	}{
		{name: "nil user", get: func(context.Context, string) (*model.User, error) { return nil, nil }},
		{name: "read error", get: func(context.Context, string) (*model.User, error) {
			return nil, errors.New("transient db read fault")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, o := newMockAuthService(t)
			o.userRepo.GetByIDFn = tc.get
			stored := false
			o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error { stored = true; return nil }

			res, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "127.0.0.1", "UA", "")
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("err = %v, want ErrTokenInvalid: an unresolvable subject must not get a session", err)
			}
			if res != nil {
				t.Error("a token pair was issued for an unresolvable subject")
			}
			if stored {
				t.Error("a refresh token was stored for an unresolvable subject")
			}
		})
	}
}

// A refresh-token store failure after MFA verification aborts the login.
func TestCompleteMFALoginStoreTokenError(t *testing.T) {
	dbErr := errors.New("token storage failed")
	svc, o := newMockAuthService(t)
	o.tokenRepo.CreateFn = func(_ context.Context, _ *model.RefreshToken) error {
		return dbErr
	}

	if _, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "ip", "ua", ""); !errors.Is(err, dbErr) {
		t.Fatalf("want the store error, got %v", err)
	}
}

// A SetLastLogin failure is logged but must not block the MFA completion.
func TestCompleteMFALoginSetLastLoginNonFatal(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.userRepo.SetLastLoginFn = func(_ context.Context, _ string) error {
		return errors.New("db down")
	}

	res, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "ip", "ua", "")
	if err != nil {
		t.Fatalf("SetLastLogin error must not block MFA completion, got %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected access token despite SetLastLogin error")
	}
}

// A successful MFA completion with a collector wired in bumps the login-success
// and tokens-issued counters, same as the password login path.
func TestCompleteMFALoginMetricsRecorded(t *testing.T) {
	svc, _ := newMockAuthService(t)
	zero := func() int64 { return 0 }
	collector := metrics.NewCollector(zero, zero, func() int { return 0 })
	svc.SetMetrics(collector)

	if _, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "ip", "ua", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	collector.Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "vault_login_success_total 1") {
		t.Error("login success counter not recorded on MFA completion")
	}
	if !strings.Contains(body, "vault_tokens_issued_total 1") {
		t.Error("tokens issued counter not recorded on MFA completion")
	}
}

// Hitting the per-user session cap during MFA completion returns ErrTooManySessions.
func TestCompleteMFALoginSessionLimit(t *testing.T) {
	svc, o := newMockAuthService(t)
	svc.SetMaxSessionsPerUser(1)
	o.tokenRepo.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 5, nil
	}

	if _, err := svc.CompleteMFALogin(context.Background(), "u", "fp", "ip", "ua", ""); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("want ErrTooManySessions, got %v", err)
	}
}

// checkSessionLimit: disabled (0), fail-open on query error, and over-limit.
func TestCheckSessionLimit(t *testing.T) {
	svc, o := newMockAuthService(t)
	ctx := context.Background()

	if err := svc.checkSessionLimit(ctx, "u"); err != nil {
		t.Fatalf("disabled limit should be nil, got %v", err)
	}

	svc.SetMaxSessionsPerUser(3)
	o.tokenRepo.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 0, errors.New("count query failed")
	}
	if err := svc.checkSessionLimit(ctx, "u"); err != nil {
		t.Fatalf("query error should fail open (nil), got %v", err)
	}

	o.tokenRepo.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 3, nil
	}
	if err := svc.checkSessionLimit(ctx, "u"); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("at limit should return ErrTooManySessions, got %v", err)
	}
}

// isAccountLocked falls back to the DB failed-login counter when cache is nil.
func TestIsAccountLockedDBFallback(t *testing.T) {
	svc, o := newMockAuthService(t)
	svc.cache = nil
	ctx := context.Background()

	o.userRepo.GetByIDFn = func(_ context.Context, _ string) (*model.User, error) {
		return nil, errors.New("db down")
	}
	if svc.isAccountLocked(ctx, "u", "203.0.113.9") {
		t.Fatal("lookup error should report not-locked")
	}

	o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, FailedLoginCount: 1000}, nil
	}
	if !svc.isAccountLocked(ctx, "u", "203.0.113.9") {
		t.Fatal("failed-login count over threshold should lock via DB fallback")
	}
}

// isIPLocked: empty IP, cache-nil with no repo, and the rate-limit repo fallback.
func TestIsIPLockedFallback(t *testing.T) {
	svc, _ := newMockAuthService(t)
	ctx := context.Background()

	if svc.isIPLocked(ctx, "") {
		t.Fatal("empty IP should never be locked")
	}

	svc.cache = nil
	if svc.isIPLocked(ctx, "1.2.3.4") {
		t.Fatal("cache nil + no rate-limit repo should report not-locked")
	}

	svc.SetRateLimitRepo(&mocks.MockRateLimitRepo{
		GetFn: func(_ context.Context, _ string, _ time.Time) (int, error) { return 1000, nil },
	})
	if !svc.isIPLocked(ctx, "1.2.3.4") {
		t.Fatal("rate-limit repo over threshold should lock")
	}

	svc.SetRateLimitRepo(&mocks.MockRateLimitRepo{
		GetFn: func(_ context.Context, _ string, _ time.Time) (int, error) { return 0, errors.New("db") },
	})
	if svc.isIPLocked(ctx, "1.2.3.4") {
		t.Fatal("rate-limit repo error should report not-locked")
	}
}

// findOrCreateDevice: existing device updates last-seen; missing device is created.
func TestFindOrCreateDevice(t *testing.T) {
	svc, o := newMockAuthService(t)
	ctx := context.Background()

	o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
		return &model.Device{ID: "dev-1"}, nil
	}
	if id := svc.findOrCreateDevice(ctx, "u", "fp", "ip", "ua"); id != "dev-1" {
		t.Fatalf("existing device should return its ID, got %q", id)
	}

	o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
		return nil, errors.New("lookup failed")
	}
	var created bool
	o.deviceRepo.CreateFn = func(_ context.Context, _ *model.Device) error {
		created = true
		return nil
	}
	if id := svc.findOrCreateDevice(ctx, "u", "fp", "ip", "ua"); id == "" {
		t.Fatal("missing device should be created with a fresh ID")
	}
	if !created {
		t.Fatal("expected device Create to be called")
	}
}
