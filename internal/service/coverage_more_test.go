package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// recordFailedIP must degrade gracefully when neither a cache nor a rate-limit
// repository is available: it logs a warning and returns without panicking,
// rather than attempting brute-force accounting it cannot perform.
func TestRecordFailedIP_NoCacheNoRateLimit(t *testing.T) {
	s := &AuthService{} // cache nil, rateLimits nil
	s.recordFailedIP(context.Background(), "203.0.113.7")
}

// When the cache is unavailable and the rate-limit fallback itself errors,
// recordFailedIP swallows the error (best-effort accounting must never block
// the auth path) after invoking the repository.
func TestRecordFailedIP_DBFallbackError(t *testing.T) {
	var called bool
	rl := &mocks.MockRateLimitRepo{
		IncrementFn: func(_ context.Context, _ string, _ time.Time) (int, error) {
			called = true
			return 0, errors.New("rate-limit store unavailable")
		},
	}
	s := &AuthService{rateLimits: rl} // cache nil → DB fallback branch
	s.recordFailedIP(context.Background(), "203.0.113.8")

	if !called {
		t.Fatal("rate-limit fallback should be invoked when cache is nil")
	}
}

// clearLockout is a no-op when no cache is configured (the lockout counter lives
// only in the cache). It must not panic on a nil cache.
func TestClearLockout_NilCache(t *testing.T) {
	s := &AuthService{} // cache nil
	s.clearLockout(context.Background(), "user-1")
}

// A failed second-factor attempt is recorded to the audit log with a
// machine-readable reason, so security monitoring can distinguish MFA failures
// from password failures.
func TestRecordMFAFailure_WritesAudit(t *testing.T) {
	var gotReason interface{}
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			if e.Metadata != nil {
				gotReason = e.Metadata["reason"]
			}
			return nil
		},
	}
	s := &AuthService{
		cache:    cache.NewMemoryCache(),
		auditLog: audit.NewLogger(repo, 0), // immediate mode → synchronous insert
	}

	s.RecordMFAFailure(context.Background(), "user-1", "203.0.113.9", "agent")

	if gotReason != "mfa_failed" {
		t.Fatalf("audit reason = %v, want mfa_failed", gotReason)
	}
}

// RequiresMFA must fail closed (propagate the error) when MFA status cannot be
// determined — both primary factor lookups failing makes the policy decision
// unsafe to guess.
func TestRequiresMFA_StatusErrorPropagates(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return nil, errors.New("totp store down")
		}},
		&mocks.MockWebAuthnRepo{ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return nil, errors.New("webauthn store down")
		}},
		&mocks.MockBackupCodeRepo{},
		true,
	)

	if _, err := svc.RequiresMFA(context.Background(), "user-1", false); err == nil {
		t.Fatal("expected error when MFA status cannot be determined")
	}
}

// Valid fails open when the catalog has never loaded and a refresh errors: an
// unknown name is treated as valid so a transient catalog outage cannot lock out
// otherwise-legitimate roles (the admin-reserved filter upstream still guards
// escalation).
func TestRoleCatalog_ValidFailsOpenWhenNeverLoaded(t *testing.T) {
	c := NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) { return nil, errors.New("catalog unavailable") },
	}, time.Minute)

	if !c.Valid(context.Background(), "anything") {
		t.Fatal("Valid must fail open (return true) when the catalog never loaded")
	}
}

// Filter short-circuits on an empty input, returning it unchanged without
// consulting the catalog.
func TestRoleCatalog_FilterEmptyInput(t *testing.T) {
	var consulted bool
	c := NewRoleCatalog(&mocks.MockAppRoleRepo{
		ListNamesFn: func(_ context.Context) ([]string, error) {
			consulted = true
			return []string{"user"}, nil
		},
	}, time.Minute)

	if got := c.Filter(context.Background(), nil); len(got) != 0 {
		t.Fatalf("Filter(nil) = %v, want empty", got)
	}
	if consulted {
		t.Fatal("Filter must not consult the catalog for an empty input")
	}
}

// Upsert rejects an invalid profile before it is ever encrypted or persisted:
// the validation error is returned and the repository is not touched.
func TestIdentityService_Upsert_InvalidProfile(t *testing.T) {
	var persisted bool
	repo := &mockIdentityRepo{
		upsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			persisted = true
			return nil
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	// Single-char username violates the usernameMinLen bound.
	err := svc.Upsert(context.Background(), "user-1", &IdentityData{Username: "x"})
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("Upsert error = %v, want ErrInvalidProfile", err)
	}
	if persisted {
		t.Fatal("invalid profile must not reach the repository")
	}
}

// doSendEmailOTP surfaces a cache failure when it cannot persist the OTP
// signature, so callers do not believe a code was issued.
func TestDoSendEmailOTP_CacheSetError(t *testing.T) {
	s := &AuthService{
		mfaSvc:      mfaNoMethods(true), // no stronger factor + required → fallback allowed
		cache:       &mocks.MockCache{SetFn: func(_ context.Context, _, _ string, _ time.Duration) error { return errors.New("cache write failed") }},
		emailSender: &mocks.MockEmailSender{},
		hmacSecret:  []byte("test-hmac-secret-32-bytes-long!!"),
		appName:     "TestVault",
	}

	if err := s.doSendEmailOTP(context.Background(), "user-1", "user@example.com"); err == nil {
		t.Fatal("expected error when caching the OTP signature fails")
	}
}

// doSendEmailOTP surfaces a delivery failure when the email sender errors, even
// though the OTP signature was already cached.
func TestDoSendEmailOTP_SendError(t *testing.T) {
	var sent bool
	s := &AuthService{
		mfaSvc:      mfaNoMethods(true),
		cache:       &mocks.MockCache{},
		emailSender: &mocks.MockEmailSender{SendFn: func(_ context.Context, _, _, _, _ string) error { sent = true; return errors.New("smtp unavailable") }},
		hmacSecret:  []byte("test-hmac-secret-32-bytes-long!!"),
		appName:     "TestVault",
	}

	if err := s.doSendEmailOTP(context.Background(), "user-1", "user@example.com"); err == nil {
		t.Fatal("expected error when OTP email delivery fails")
	}
	if !sent {
		t.Fatal("sender should have been invoked")
	}
}
