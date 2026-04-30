package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/tests/mocks"
)

func newEmailOTPAuthService(t *testing.T) (*AuthService, *mocks.MockCache, *mocks.MockEmailSender) {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mockCache := &mocks.MockCache{}
	mockEmail := &mocks.MockEmailSender{}
	hmacSecret := []byte("test-hmac-secret-for-email-otp!!")

	svc := NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLogger, NewHIBPClient(),
		mockCache, mockEmail, "https://vault.test", "TestVault",
		"", 15, false, hmacSecret,
	)
	return svc, mockCache, mockEmail
}

func TestSendEmailOTP(t *testing.T) {
	svc, mockCache, mockEmail := newEmailOTPAuthService(t)

	var cachedKey, cachedValue string
	var cachedTTL time.Duration
	mockCache.SetFn = func(_ context.Context, key, value string, ttl time.Duration) error {
		cachedKey = key
		cachedValue = value
		cachedTTL = ttl
		return nil
	}

	var sentTo, sentSubject string
	mockEmail.SendFn = func(_ context.Context, to, subject, _, _ string) error {
		sentTo = to
		sentSubject = subject
		return nil
	}

	err := svc.SendEmailOTP(context.Background(), "user-123", "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cachedKey != "email_otp:user-123" {
		t.Errorf("cache key = %q, want email_otp:user-123", cachedKey)
	}
	if cachedValue == "" {
		t.Error("cache value should be non-empty HMAC signature")
	}
	if cachedTTL != 5*time.Minute {
		t.Errorf("cache TTL = %v, want 5m", cachedTTL)
	}
	if sentTo != "user@example.com" {
		t.Errorf("email sent to %q, want user@example.com", sentTo)
	}
	if sentSubject == "" {
		t.Error("email subject should be non-empty")
	}
}

func TestVerifyEmailOTP_Valid(t *testing.T) {
	svc, mockCache, _ := newEmailOTPAuthService(t)

	// Simulate: code "123456" was sent, its HMAC stored in cache
	code := "123456"
	sig := vaultcrypto.HMACSign([]byte(code), svc.hmacSecret)

	mockCache.GetAndDeleteFn = func(_ context.Context, key string) (string, error) {
		if key == "email_otp:user-123" {
			return sig, nil
		}
		return "", nil
	}

	err := svc.VerifyEmailOTP(context.Background(), "user-123", code)
	if err != nil {
		t.Fatalf("expected valid OTP, got error: %v", err)
	}
}

func TestVerifyEmailOTP_WrongCode(t *testing.T) {
	svc, mockCache, _ := newEmailOTPAuthService(t)

	sig := vaultcrypto.HMACSign([]byte("123456"), svc.hmacSecret)
	mockCache.GetAndDeleteFn = func(_ context.Context, key string) (string, error) {
		return sig, nil
	}

	err := svc.VerifyEmailOTP(context.Background(), "user-123", "999999")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestVerifyEmailOTP_Expired(t *testing.T) {
	svc, mockCache, _ := newEmailOTPAuthService(t)

	mockCache.GetAndDeleteFn = func(_ context.Context, key string) (string, error) {
		return "", nil // empty = expired/not found
	}

	err := svc.VerifyEmailOTP(context.Background(), "user-123", "123456")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for expired OTP, got %v", err)
	}
}

func TestVerifyEmailOTP_SingleUse(t *testing.T) {
	svc, mockCache, _ := newEmailOTPAuthService(t)

	code := "654321"
	sig := vaultcrypto.HMACSign([]byte(code), svc.hmacSecret)
	called := 0

	mockCache.GetAndDeleteFn = func(_ context.Context, key string) (string, error) {
		called++
		if called == 1 {
			return sig, nil // first call returns the signature
		}
		return "", nil // second call: already deleted
	}

	// First verify succeeds
	if err := svc.VerifyEmailOTP(context.Background(), "user-123", code); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}

	// Second verify fails (replay)
	if err := svc.VerifyEmailOTP(context.Background(), "user-123", code); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("second verify should fail with ErrInvalidCredentials, got %v", err)
	}
}

func TestSendEmailOTP_NilCache(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLogger, NewHIBPClient(),
		nil, nil, "https://vault.test", "TestVault",
		"", 15, false, []byte("test-secret"),
	)

	err := svc.SendEmailOTP(context.Background(), "user-1", "test@test.com")
	if err == nil {
		t.Error("expected error when cache is nil")
	}
}
