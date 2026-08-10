package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// uniqueViolationErr returns an error that isUniqueViolation recognizes (SQLSTATE 23505).
func uniqueViolationErr() error {
	return &pgconn.PgError{Code: "23505"}
}

// A configured trap user short-circuits Login with believable fake tokens.
func TestLoginHoneypotTrapUser(t *testing.T) {
	svc, _ := newMockAuthService(t)
	svc.SetHoneypotAlerter(honeypot.NewAlerter("", []string{"trap@example.com"}, svc.auditLog))

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "trap@example.com", Password: "anything-at-all",
	}, "9.9.9.9", "TrapAgent")
	if err != nil {
		t.Fatalf("trap login should return fake tokens, got %v", err)
	}
	if res == nil || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("trap login should yield non-empty fake access and refresh tokens")
	}
	if res.Requires2FA {
		t.Error("trap login must not request 2FA")
	}
}

// An IP-wide lockout returns ErrAccountLocked before any user lookup.
func TestLoginIPLocked(t *testing.T) {
	var lookupCalled bool
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		lookupCalled = true
		return nil, nil
	}
	o.cache.GetFn = func(_ context.Context, key string) (string, error) {
		return "999", nil // both lockout:<id> and ip lockout counters read over threshold
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "victim@example.com", Password: "pw",
	}, "5.5.5.5", "UA")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("IP-locked login should return ErrAccountLocked, got %v", err)
	}
	if lookupCalled {
		t.Error("IP lockout must short-circuit before the user lookup")
	}
}

// Auto-lockout via the cache counter returns ErrAccountLocked even with a valid user.
func TestLoginAutoLockout(t *testing.T) {
	hash := validPasswordHash(t)
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{ID: "user-1", Email: "auto@example.com", PasswordHash: hash, EmailVerified: true}, nil
	}
	o.cache.GetFn = func(_ context.Context, key string) (string, error) {
		// IP counter not locked; per-user lockout counter is over threshold.
		if len(key) > 8 && key[:8] == "lockout:" {
			return "10", nil
		}
		return "0", nil
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "auto@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("auto-lockout should return ErrAccountLocked, got %v", err)
	}
}

// MFA required but no methods configured falls back to an email-OTP challenge.
func TestLoginMFAEmailOTPFallback(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		true, // MFA required
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: "otp@example.com", PasswordHash: hash, EmailVerified: true}, nil
		}
	})

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "otp@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA")
	if err != nil {
		t.Fatalf("email-OTP fallback should not error, got %v", err)
	}
	if !res.Requires2FA || res.ChallengeToken == "" {
		t.Fatal("expected a 2FA challenge for the email-OTP fallback")
	}
	if len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != "email_otp" {
		t.Errorf("available_methods should be [email_otp], got %v", res.AvailableMethods)
	}
}

// Login fails when the per-user session cap is exceeded just before token issue.
func TestLoginSessionLimitExceeded(t *testing.T) {
	hash := validPasswordHash(t)
	svc, o := newMockAuthService(t)
	svc.SetMaxSessionsPerUser(1)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{ID: "user-1", Email: "cap@example.com", PasswordHash: hash, EmailVerified: true}, nil
	}
	o.tokenRepo.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 9, nil
	}

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "cap@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA"); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("over-cap login should return ErrTooManySessions, got %v", err)
	}
}

// findOrCreateDevice: a TOCTOU unique-violation on Create resolves via re-lookup.
func TestFindOrCreateDeviceTOCTOURetry(t *testing.T) {
	svc, o := newMockAuthService(t)
	ctx := context.Background()

	calls := 0
	o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
		calls++
		if calls == 1 {
			return nil, nil // first lookup: absent
		}
		return &model.Device{ID: "dev-winner"}, nil // re-lookup after race
	}
	o.deviceRepo.CreateFn = func(_ context.Context, _ *model.Device) error {
		return uniqueViolationErr()
	}

	if id := svc.findOrCreateDevice(ctx, "u", "fp", "ip", "ua"); id != "dev-winner" {
		t.Fatalf("TOCTOU retry should return the winning device ID, got %q", id)
	}
}

// findOrCreateDevice: a non-unique Create error falls through to the generated ID.
func TestFindOrCreateDeviceCreateErrorNonUnique(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
		return nil, nil
	}
	o.deviceRepo.CreateFn = func(_ context.Context, _ *model.Device) error {
		return errors.New("disk full")
	}

	if id := svc.findOrCreateDevice(context.Background(), "u", "fp", "ip", "ua"); id == "" {
		t.Fatal("non-unique create error should still return the generated device ID")
	}
}

// findOrCreateDevice: a failing UpdateLastSeen is logged but still returns the device ID.
func TestFindOrCreateDeviceUpdateLastSeenError(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
		return &model.Device{ID: "dev-7"}, nil
	}
	o.deviceRepo.UpdateLastSeenFn = func(_ context.Context, _, _ string) error {
		return errors.New("update failed")
	}

	if id := svc.findOrCreateDevice(context.Background(), "u", "fp", "ip", "ua"); id != "dev-7" {
		t.Fatalf("update-last-seen error should not change the returned ID, got %q", id)
	}
}

// Register maps a concurrent UNIQUE violation on Create to ErrEmailTaken.
func TestRegisterCreateUniqueViolation(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return nil, nil // appears free at check time
	}
	o.userRepo.CreateFn = func(_ context.Context, _ *model.User) error {
		return uniqueViolationErr() // lost the race
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Email: "race@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("unique violation on Create should map to ErrEmailTaken, got %v", err)
	}
}
