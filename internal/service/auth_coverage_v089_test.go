package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// SetRoleCatalog (auth.go:174)
// The setter's only observable effect is that effectiveRoles starts filtering
// against the catalog. Prove the wiring by showing a role disappears after the
// catalog is installed.
// ---------------------------------------------------------------------------

func TestSetRoleCatalog_EnablesCatalogFiltering(t *testing.T) {
	svc, _ := newMockAuthService(t)

	// Before: no catalog → non-admin role survives effectiveRoles unchanged.
	if got := svc.effectiveRoles(context.Background(), []string{"moderator"}); len(got) != 1 || got[0] != "moderator" {
		t.Fatalf("pre-catalog: moderator should pass through, got %v", got)
	}

	// Install a catalog that knows only "user" — "moderator" is no longer valid.
	svc.SetRoleCatalog(NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) { return []string{"user"}, nil },
	}, time.Minute))

	if got := svc.effectiveRoles(context.Background(), []string{"moderator"}); len(got) != 1 || got[0] != "user" {
		t.Fatalf("post-catalog: moderator should be filtered to [user] fallback, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// RevokeAllTokensForUser (auth.go:766)
// ---------------------------------------------------------------------------

func TestRevokeAllTokensForUser_DelegatesToTokenRepo(t *testing.T) {
	var gotUser string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, userID string) error {
			gotUser = userID
			return nil
		}
	})

	if err := svc.RevokeAllTokensForUser(context.Background(), "user-77"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotUser != "user-77" {
		t.Errorf("RevokeAllForUser called with %q, want user-77", gotUser)
	}
}

func TestRevokeAllTokensForUser_PropagatesError(t *testing.T) {
	dbErr := errors.New("revoke failed")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, _ string) error { return dbErr }
	})

	if err := svc.RevokeAllTokensForUser(context.Background(), "user-77"); !errors.Is(err, dbErr) {
		t.Errorf("expected propagated error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// sendImportClaimLink (auth.go:338) — fire-and-forget goroutine.
// ---------------------------------------------------------------------------

func TestSendImportClaimLink_StoresResetTokenAndEmailsClaimURL(t *testing.T) {
	svc, _ := newMockAuthService(t)

	type setCall struct{ key, value string }
	setCh := make(chan setCall, 4)
	// Capture both cache.Set calls: reset:<hash> and pwreset_user:<userID>.
	svc.cache.(*mocks.MockCache).SetFn = func(_ context.Context, key, value string, _ time.Duration) error {
		setCh <- setCall{key, value}
		return nil
	}

	emailCh := make(chan string, 1)
	svc.emailSender.(*mocks.MockEmailSender).SendFn = func(_ context.Context, _, _, _, text string) error {
		emailCh <- text
		return nil
	}

	svc.sendImportClaimLink("user-42", "rider@legacy.test")

	var sawReset, sawReverse bool
	timeout := time.After(5 * time.Second)
	for !(sawReset && sawReverse) {
		select {
		case c := <-setCh:
			switch {
			case strings.HasPrefix(c.key, "reset:"):
				sawReset = true
				if c.value != "user-42" {
					t.Errorf("reset token should map to user-42, got %q", c.value)
				}
			case c.key == "pwreset_user:user-42":
				sawReverse = true
			default:
				t.Errorf("unexpected cache key %q", c.key)
			}
		case <-timeout:
			t.Fatalf("timed out waiting for cache writes (reset=%v reverse=%v)", sawReset, sawReverse)
		}
	}

	select {
	case text := <-emailCh:
		if !strings.Contains(text, "/reset-password?token=") {
			t.Errorf("claim email should contain reset-password link, got %q", text)
		}
		if !strings.Contains(text, "import=1") {
			t.Errorf("claim link should carry import=1 marker, got %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for claim email")
	}
}

func TestSendImportClaimLink_NilDepsNoEmail(t *testing.T) {
	svc, _ := newMockAuthService(t)
	svc.cache = nil // disables the whole path

	sent := make(chan struct{}, 1)
	svc.emailSender.(*mocks.MockEmailSender).SendFn = func(_ context.Context, _, _, _, _ string) error {
		sent <- struct{}{}
		return nil
	}

	svc.sendImportClaimLink("user-42", "rider@legacy.test")

	select {
	case <-sent:
		t.Error("no email should be sent when cache is nil")
	case <-time.After(200 * time.Millisecond):
		// expected: nothing happened
	}
}

// ---------------------------------------------------------------------------
// sendEmailOTP (auth.go:844) — fire-and-forget wrapper over doSendEmailOTP.
// Reuses the H1-gate setup: MFA required, no stronger factor enrolled.
// ---------------------------------------------------------------------------

func TestSendEmailOTPFireAndForget_CachesAndSends(t *testing.T) {
	svc, mockCache, mockEmail := newEmailOTPAuthService(t)

	var gotKey, gotVal string
	mockCache.SetFn = func(_ context.Context, key, value string, _ time.Duration) error {
		gotKey, gotVal = key, value
		return nil
	}
	sentTo := make(chan string, 1)
	mockEmail.SendFn = func(_ context.Context, to, _, _, _ string) error {
		sentTo <- to
		return nil
	}

	// sendEmailOTP runs doSendEmailOTP synchronously in this caller (the
	// goroutine is at the Login call-site, not inside the method).
	svc.sendEmailOTP("user-otp", "otp@example.com")

	if gotKey != "email_otp:user-otp" {
		t.Errorf("cache key = %q, want email_otp:user-otp", gotKey)
	}
	if gotVal == "" {
		t.Error("cached OTP signature should be non-empty")
	}
	select {
	case to := <-sentTo:
		if to != "otp@example.com" {
			t.Errorf("OTP email sent to %q, want otp@example.com", to)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OTP email")
	}
}

func TestSendEmailOTPFireAndForget_NotAllowedNoSend(t *testing.T) {
	// nil MFA service → emailOTPAllowed is false → doSendEmailOTP returns
	// ErrEmailOTPNotAllowed before any cache/email work. The fire-and-forget
	// wrapper swallows the error (logs only).
	svc, _ := newMockAuthService(t) // no mfaSvc

	var emailed bool
	svc.emailSender.(*mocks.MockEmailSender).SendFn = func(_ context.Context, _, _, _, _ string) error {
		emailed = true
		return nil
	}

	svc.sendEmailOTP("user-x", "x@example.com")

	if emailed {
		t.Error("email-OTP must not be sent when not an allowed factor")
	}
}

// ---------------------------------------------------------------------------
// recordFailedIP (auth.go:1056)
// ---------------------------------------------------------------------------

func TestRecordFailedIP_IncrementsCacheCounter(t *testing.T) {
	var gotKey string
	var gotTTL time.Duration
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.cache.IncrementFn = func(_ context.Context, key string, ttl time.Duration) (int64, error) {
			gotKey, gotTTL = key, ttl
			return 1, nil
		}
	})

	svc.recordFailedIP(context.Background(), "9.9.9.9")

	if gotKey != "lockout_ip:9.9.9.9" {
		t.Errorf("increment key = %q, want lockout_ip:9.9.9.9", gotKey)
	}
	if gotTTL != lockoutDuration {
		t.Errorf("increment TTL = %v, want %v", gotTTL, lockoutDuration)
	}
}

func TestRecordFailedIP_EmptyIPNoop(t *testing.T) {
	var called bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.cache.IncrementFn = func(_ context.Context, _ string, _ time.Duration) (int64, error) {
			called = true
			return 1, nil
		}
	})

	svc.recordFailedIP(context.Background(), "")

	if called {
		t.Error("recordFailedIP must not touch the cache for an empty IP")
	}
}

func TestRecordFailedIP_DBFallbackWhenCacheNil(t *testing.T) {
	var gotKey string
	rl := &mocks.MockRateLimitRepo{
		IncrementFn: func(_ context.Context, key string, _ time.Time) (int, error) {
			gotKey = key
			return 1, nil
		},
	}
	svc, _ := newMockAuthService(t)
	svc.cache = nil // force the DB-fallback branch
	svc.SetRateLimitRepo(rl)

	svc.recordFailedIP(context.Background(), "9.9.9.9")

	if gotKey != "lockout_ip:9.9.9.9" {
		t.Errorf("rate-limit fallback key = %q, want lockout_ip:9.9.9.9", gotKey)
	}
}

// ---------------------------------------------------------------------------
// NewRoleCatalog (role_catalog.go:27) — the uncovered branch is the ttl<=0
// default. A non-positive ttl must still yield a working catalog.
// ---------------------------------------------------------------------------

func TestNewRoleCatalog_NonPositiveTTLDefaults(t *testing.T) {
	c := NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) { return []string{"user", "moderator"}, nil },
	}, 0) // <= 0 → defaults to 60s internally

	if !c.Valid(context.Background(), "moderator") {
		t.Error("catalog built with ttl=0 should still validate known roles")
	}
	if c.Valid(context.Background(), "bogus") {
		t.Error("unknown role should not be valid")
	}
}
