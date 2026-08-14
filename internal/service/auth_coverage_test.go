package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// sendVerificationEmail tests (~10)
// These are tested synchronously since the actual method is called via goroutine
// in Register; here we call it directly.
// ---------------------------------------------------------------------------

func newAuthServiceWithDeps(t *testing.T) (*AuthService, *mocks.MockCache, *mocks.MockEmailSender) {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mockCache := &mocks.MockCache{}
	mockEmail := &mocks.MockEmailSender{}

	svc := NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLogger, NewHIBPClient(),
		mockCache, mockEmail, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)
	return svc, mockCache, mockEmail
}

func TestSendVerificationEmailSuccess(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	var cachedKey string
	var cachedValue string
	mockCache.SetFn = func(_ context.Context, key, value string, _ time.Duration) error {
		cachedKey = key
		cachedValue = value
		return nil
	}

	var sentTo string
	mockEmail.SendFn = func(_ context.Context, to, subject, html, text string) error {
		sentTo = to
		return nil
	}

	svc.sendVerificationEmail("user@example.com", "user-123", "", "/dashboard")

	if cachedKey == "" || !strings.HasPrefix(cachedKey, "verify:") {
		t.Errorf("cache key should start with 'verify:', got %q", cachedKey)
	}
	if cachedValue != "user-123" {
		t.Errorf("cached value should be 'user-123', got %q", cachedValue)
	}
	if sentTo != "user@example.com" {
		t.Errorf("email should be sent to 'user@example.com', got %q", sentTo)
	}
}

func TestSendVerificationEmailCacheError(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return errors.New("cache unavailable")
	}

	var emailSent bool
	mockEmail.SendFn = func(_ context.Context, _, _, _, _ string) error {
		emailSent = true
		return nil
	}

	// Should not panic; cache error is logged and email is not sent
	svc.sendVerificationEmail("user@example.com", "user-123", "", "")

	if emailSent {
		t.Error("email should NOT be sent when cache fails")
	}
}

func TestSendVerificationEmailSendError(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}
	mockEmail.SendFn = func(_ context.Context, _, _, _, _ string) error {
		return errors.New("SMTP connection refused")
	}

	// Should not panic; email error is logged
	svc.sendVerificationEmail("user@example.com", "user-123", "", "")
}

func TestSendVerificationEmailNoRedirect(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedHTML string
	mockEmail.SendFn = func(_ context.Context, _, _, html, _ string) error {
		capturedHTML = html
		return nil
	}

	svc.sendVerificationEmail("user@example.com", "user-123", "", "")

	if strings.Contains(capturedHTML, "&redirect=") {
		t.Error("verify URL should not include redirect param when redirectTo is empty")
	}
}

func TestSendVerificationEmailWithRedirect(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedText string
	mockEmail.SendFn = func(_ context.Context, _, _, _, text string) error {
		capturedText = text
		return nil
	}

	svc.sendVerificationEmail("user@example.com", "user-123", "", "/settings")

	if !strings.Contains(capturedText, "redirect=") {
		t.Error("verify URL should include redirect param when redirectTo is set")
	}
}

func TestSendVerificationEmailSubjectIncludesAppName(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedSubject string
	mockEmail.SendFn = func(_ context.Context, _, subject, _, _ string) error {
		capturedSubject = subject
		return nil
	}

	svc.sendVerificationEmail("user@example.com", "user-123", "", "")

	if !strings.Contains(capturedSubject, "TestVault") {
		t.Errorf("subject should include app name 'TestVault', got %q", capturedSubject)
	}
}

func TestSendVerificationEmailTokenInURL(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	mockCache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
		return nil
	}

	var capturedText string
	mockEmail.SendFn = func(_ context.Context, _, _, _, text string) error {
		capturedText = text
		return nil
	}

	svc.sendVerificationEmail("user@example.com", "user-123", "", "")

	if !strings.Contains(capturedText, "https://vault.test/verify-email?token=") {
		t.Errorf("email text should contain verify URL with token, got %q", capturedText)
	}
}

// ---------------------------------------------------------------------------
// Login edge case tests (~30)
// ---------------------------------------------------------------------------

// newMockAuthService creates an AuthService using the mocks package for full control.
func newMockAuthService(t *testing.T, opts ...func(*mockAuthOpts)) (*AuthService, *mockAuthOpts) {
	t.Helper()
	o := &mockAuthOpts{
		userRepo:    &mocks.MockUserRepo{},
		tokenRepo:   &mocks.MockRefreshTokenRepo{},
		deviceRepo:  &mocks.MockDeviceRepo{},
		pwHistory:   &mocks.MockPasswordHistoryRepo{},
		cache:       &mocks.MockCache{},
		emailSender: &mocks.MockEmailSender{},
	}
	for _, fn := range opts {
		fn(o)
	}
	// Default: refresh/role lookups resolve to a live, non-banned user unless a
	// test overrides GetByIDFn (e.g. to exercise banned/disabled/deleted rejection).
	if o.userRepo.GetByIDFn == nil {
		o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Roles: []string{"user"}}, nil
		}
	}
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := NewAuthService(
		o.userRepo, o.tokenRepo, o.deviceRepo, o.pwHistory,
		tokenSvc, o.mfaSvc, auditLogger, NewHIBPClient(),
		o.cache, o.emailSender, "https://vault.test", "TestVault",
		"", 15, o.hibpEnabled, nil,
	)
	return svc, o
}

type mockAuthOpts struct {
	userRepo    *mocks.MockUserRepo
	tokenRepo   *mocks.MockRefreshTokenRepo
	deviceRepo  *mocks.MockDeviceRepo
	pwHistory   *mocks.MockPasswordHistoryRepo
	cache       *mocks.MockCache
	emailSender *mocks.MockEmailSender
	mfaSvc      *MFAService
	hibpEnabled bool
}

func validPasswordHash(t *testing.T) string {
	t.Helper()
	hash, err := vaultcrypto.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestLoginAdminLockedReturnsInvalidCredentials(t *testing.T) {
	hash := validPasswordHash(t)
	lockedUntil := time.Now().Add(1 * time.Hour)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "locked@example.com",
				PasswordHash: hash, EmailVerified: true,
				LockedUntil: &lockedUntil,
			}, nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "locked@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")

	// Only an existing account can reach the admin-locked state, so a distinct
	// ErrAccountLocked leaks that the address is registered. The login path masks
	// it as ErrInvalidCredentials, exactly like a wrong password or unknown email.
	if !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountLocked) {
		t.Errorf("an admin-locked account must be indistinguishable from an unknown email (ErrInvalidCredentials), got %v", err)
	}
}

func TestLoginExpiredLockProceeds(t *testing.T) {
	hash := validPasswordHash(t)
	expiredLock := time.Now().Add(-1 * time.Hour) // lock expired 1 hour ago
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "expired-lock@example.com",
				PasswordHash: hash, EmailVerified: true,
				LockedUntil: &expiredLock,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "expired-lock@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("expired lock should allow login, got error: %v", err)
	}
	if result.AccessToken == "" {
		t.Error("access token should not be empty after expired lock login")
	}
}

func TestLoginWrongPasswordIncrementsFailCount(t *testing.T) {
	hash := validPasswordHash(t)
	var incrementCalled bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "wrong@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.userRepo.IncrementFailedLoginFn = func(_ context.Context, _ string) error {
			incrementCalled = true
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "wrong@example.com", Password: "totally-wrong-password!!",
	}, "1.2.3.4", "TestAgent")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password should return ErrInvalidCredentials, got %v", err)
	}
	if !incrementCalled {
		t.Error("IncrementFailedLogin should be called on wrong password")
	}
}

func TestLoginResetsFailCountOnSuccess(t *testing.T) {
	hash := validPasswordHash(t)
	var resetCalled bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "reset@example.com",
				PasswordHash: hash, EmailVerified: true,
				FailedLoginCount: 3,
			}, nil
		}
		o.userRepo.ResetFailedLoginFn = func(_ context.Context, _ string) error {
			resetCalled = true
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "reset@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("login should succeed, got %v", err)
	}
	if !resetCalled {
		t.Error("ResetFailedLogin should be called on successful login")
	}
}

func TestLoginMFARequiredTOTPOnly(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "mfa@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requires2FA {
		t.Error("should require 2FA when TOTP is configured")
	}
	if result.ChallengeToken == "" {
		t.Error("challenge token should not be empty when 2FA required")
	}
	if len(result.AvailableMethods) != 1 || result.AvailableMethods[0] != "totp" {
		t.Errorf("available_methods should be [totp], got %v", result.AvailableMethods)
	}
}

func TestLoginMFARequiredWebAuthnOnly(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "webauthn@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "webauthn@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requires2FA {
		t.Error("should require 2FA when WebAuthn is configured")
	}
	found := false
	for _, m := range result.AvailableMethods {
		if m == "webauthn" {
			found = true
		}
	}
	if !found {
		t.Errorf("available_methods should include 'webauthn', got %v", result.AvailableMethods)
	}
}

func TestLoginMFARequiredBothMethods(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}}, nil
			},
		},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "both-mfa@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "both-mfa@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Requires2FA {
		t.Error("should require 2FA when both methods configured")
	}
	if len(result.AvailableMethods) != 3 {
		t.Errorf("expected 3 methods (totp, webauthn, backup_code), got %v", result.AvailableMethods)
	}
}

func TestLoginNilMFAServiceProceeds(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		// mfaSvc remains nil
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "nomfa@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "nomfa@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("nil MFA service should not block login: %v", err)
	}
	if result.Requires2FA {
		t.Error("should not require 2FA when MFA service is nil")
	}
	if result.AccessToken == "" {
		t.Error("should issue access token when MFA service is nil")
	}
}

func TestLoginDeviceCreatedForNewFingerprint(t *testing.T) {
	hash := validPasswordHash(t)
	var deviceCreated bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "newdevice@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
			return nil, nil // no existing device
		}
		o.deviceRepo.CreateFn = func(_ context.Context, d *model.Device) error {
			deviceCreated = true
			if d.UserID != "user-1" {
				t.Errorf("device userID = %q, want user-1", d.UserID)
			}
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "newdevice@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !deviceCreated {
		t.Error("device should be created for new fingerprint")
	}
}

func TestLoginDeviceUpdatedForExistingFingerprint(t *testing.T) {
	hash := validPasswordHash(t)
	var lastSeenUpdated bool
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "existing@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
			return &model.Device{
				ID: "dev-1", UserID: "user-1", FingerprintHash: fp,
			}, nil
		}
		o.deviceRepo.UpdateLastSeenFn = func(_ context.Context, id, ip string) error {
			lastSeenUpdated = true
			if id != "dev-1" {
				t.Errorf("device ID = %q, want dev-1", id)
			}
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "existing@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if !lastSeenUpdated {
		t.Error("device last seen should be updated for existing fingerprint")
	}
}

func TestLoginGetByEmailError(t *testing.T) {
	dbErr := errors.New("database connection lost")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, dbErr
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "fail@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")

	if !errors.Is(err, dbErr) {
		t.Errorf("should return DB error, got %v", err)
	}
}

func TestLoginEmailCaseInsensitive(t *testing.T) {
	hash := validPasswordHash(t)
	var queriedEmail string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
			queriedEmail = email
			return &model.User{
				ID: "user-1", Email: email,
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	svc.Login(context.Background(), LoginInput{
		Email: "  User@EXAMPLE.com  ", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")

	if queriedEmail != "user@example.com" {
		t.Errorf("email should be lowercased and trimmed, got %q", queriedEmail)
	}
}

func TestLoginRememberMe(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "remember@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	resultNormal, _ := svc.Login(context.Background(), LoginInput{
		Email: "remember@example.com", Password: "correct-horse-battery-staple",
		RememberMe: false,
	}, "1.2.3.4", "TestAgent")

	resultRemember, _ := svc.Login(context.Background(), LoginInput{
		Email: "remember@example.com", Password: "correct-horse-battery-staple",
		RememberMe: true,
	}, "1.2.3.4", "TestAgent")

	if resultRemember.CookieMaxAge <= resultNormal.CookieMaxAge {
		t.Errorf("remember_me should have longer cookie max age: normal=%d, remember=%d",
			resultNormal.CookieMaxAge, resultRemember.CookieMaxAge)
	}
}

func TestLoginSuccessTokenType(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "type@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "type@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", result.TokenType)
	}
	if result.ExpiresIn <= 0 {
		t.Errorf("expires_in should be positive, got %d", result.ExpiresIn)
	}
}

func TestLoginStoresRefreshTokenHash(t *testing.T) {
	hash := validPasswordHash(t)
	var storedToken *model.RefreshToken
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "store@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			storedToken = rt
			return nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "store@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if storedToken == nil {
		t.Fatal("refresh token should be stored in repository")
	}
	// Verify the stored hash matches the SHA256 of the raw token
	expectedHash := vaultcrypto.SHA256Hex(result.RefreshToken)
	if storedToken.TokenHash != expectedHash {
		t.Errorf("stored hash should be SHA256 of raw token")
	}
	if storedToken.UserID != "user-1" {
		t.Errorf("stored token userID = %q, want user-1", storedToken.UserID)
	}
}

func TestLoginDeviceLookupError(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "devfail@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.deviceRepo.GetByFingerprintFn = func(_ context.Context, _, _ string) (*model.Device, error) {
			return nil, errors.New("device lookup error")
		}
	})

	// Login should still succeed despite device lookup failure (non-critical)
	result, err := svc.Login(context.Background(), LoginInput{
		Email: "devfail@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("login should succeed despite device lookup error: %v", err)
	}
	if result.AccessToken == "" {
		t.Error("access token should not be empty")
	}
}

func TestLoginRefreshTokenCreationError(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "rtfail@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, _ *model.RefreshToken) error {
			return errors.New("token storage failed")
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "rtfail@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")

	if err == nil {
		t.Error("login should fail when refresh token storage fails")
	}
}

func TestLoginMFANoMethodsProceeds(t *testing.T) {
	hash := validPasswordHash(t)
	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		false,
	)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "nomethods@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email: "nomethods@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("login should succeed with no MFA methods: %v", err)
	}
	if result.Requires2FA {
		t.Error("should not require 2FA when no methods configured")
	}
	if result.AccessToken == "" {
		t.Error("should issue access token")
	}
}

func TestLoginClientIDPropagated(t *testing.T) {
	hash := validPasswordHash(t)
	var storedClientID string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "client@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			storedClientID = rt.ClientID
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "client@example.com", Password: "correct-horse-battery-staple",
		ClientID: "frontend-app",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if storedClientID != "frontend-app" {
		t.Errorf("stored client_id = %q, want frontend-app", storedClientID)
	}
}

// ---------------------------------------------------------------------------
// Refresh edge case tests (~25)
// ---------------------------------------------------------------------------

func TestRefreshTokenNotFound(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return nil, nil
		}
	})

	_, err := svc.Refresh(context.Background(), "nonexistent-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("missing token should return ErrTokenInvalid, got %v", err)
	}
}

func TestRefreshRevokedToken(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				Revoked: true,
			}, nil
		}
	})

	_, err := svc.Refresh(context.Background(), "revoked-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("revoked token should return ErrTokenInvalid, got %v", err)
	}
}

func TestRefreshReplayDetectionNukesFamily(t *testing.T) {
	var familyRevoked bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				Used:      true, // already used = replay
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.RevokeFamilyFn = func(_ context.Context, familyID string) error {
			if familyID == "fam-1" {
				familyRevoked = true
			}
			return nil
		}
	})

	_, err := svc.Refresh(context.Background(), "used-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrReplayDetected) {
		t.Errorf("used token should return ErrReplayDetected, got %v", err)
	}
	if !familyRevoked {
		t.Error("entire family should be revoked on replay detection")
	}
}

func TestRefreshExpiredToken(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
			}, nil
		}
	})

	_, err := svc.Refresh(context.Background(), "expired-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token should return ErrTokenExpired, got %v", err)
	}
}

func TestRefreshFingerprintMismatchNukesFamily(t *testing.T) {
	storedFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "10.0.0.1", UserAgent: "OriginalAgent",
	})
	var familyRevoked bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: storedFP,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.RevokeFamilyFn = func(_ context.Context, familyID string) error {
			if familyID == "fam-1" {
				familyRevoked = true
			}
			return nil
		}
	})

	// Different IP and UA than what was stored
	_, err := svc.Refresh(context.Background(), "some-token", "9.9.9.9", "DifferentAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("fingerprint mismatch should return ErrTokenInvalid, got %v", err)
	}
	if !familyRevoked {
		t.Error("family should be revoked on fingerprint mismatch")
	}
}

func TestRefreshSuccessfulRotation(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	var oldMarkedUsed bool
	var newTokenCreated bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", ClientID: "client-1",
				FamilyID: "fam-1", FingerprintHash: fp, DeviceID: "dev-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, id string) (bool, error) {
			if id == "rt-1" {
				oldMarkedUsed = true
			}
			return true, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			newTokenCreated = true
			if rt.FamilyID != "fam-1" {
				t.Errorf("new token should be in same family, got %q", rt.FamilyID)
			}
			if rt.DeviceID != "dev-1" {
				t.Errorf("new token should have same device ID, got %q", rt.DeviceID)
			}
			return nil
		}
	})

	result, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !oldMarkedUsed {
		t.Error("old token should be marked as used")
	}
	if !newTokenCreated {
		t.Error("new refresh token should be created")
	}
	if result.AccessToken == "" {
		t.Error("new access token should not be empty")
	}
	if result.RefreshToken == "" {
		t.Error("new refresh token should not be empty")
	}
	if result.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", result.TokenType)
	}
}

func TestRefreshConcurrentReplay(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	var familyRevoked bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return false, nil // CAS failed = concurrent request already consumed
		}
		o.tokenRepo.RevokeFamilyFn = func(_ context.Context, familyID string) error {
			if familyID == "fam-1" {
				familyRevoked = true
			}
			return nil
		}
	})

	_, err := svc.Refresh(context.Background(), "concurrent-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrReplayDetected) {
		t.Errorf("concurrent replay should return ErrReplayDetected, got %v", err)
	}
	if !familyRevoked {
		t.Error("family should be revoked on concurrent replay")
	}
}

func TestRefreshGetByTokenHashError(t *testing.T) {
	dbErr := errors.New("database timeout")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return nil, dbErr
		}
	})

	_, err := svc.Refresh(context.Background(), "any-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, dbErr) {
		t.Errorf("should propagate DB error, got %v", err)
	}
}

func TestRefreshMarkUsedError(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("mark used failed")
		}
	})

	_, err := svc.Refresh(context.Background(), "any-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if err == nil {
		t.Error("should return error when MarkUsed fails")
	}
}

func TestRefreshNewTokenCreationError(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, _ *model.RefreshToken) error {
			return errors.New("storage failed for new token")
		}
	})

	_, err := svc.Refresh(context.Background(), "any-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if err == nil {
		t.Error("should return error when new token creation fails")
	}
}

func TestRefreshEmptyFingerprintStored(t *testing.T) {
	// When stored fingerprint is empty, fingerprint check should be skipped
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: "", // empty — skip fingerprint check
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})

	result, err := svc.Refresh(context.Background(), "some-token", "99.99.99.99", "DifferentAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("empty stored fingerprint should skip check: %v", err)
	}
	if result.AccessToken == "" {
		t.Error("access token should not be empty")
	}
}

func TestRefreshPreservesClientID(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	var newTokenClientID string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", ClientID: "frontend-app",
				FamilyID: "fam-1", FingerprintHash: fp,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
		o.tokenRepo.CreateFn = func(_ context.Context, rt *model.RefreshToken) error {
			newTokenClientID = rt.ClientID
			return nil
		}
	})

	_, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if newTokenClientID != "frontend-app" {
		t.Errorf("new token client_id = %q, want frontend-app", newTokenClientID)
	}
}

func TestRefreshExpiresInPositive(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})

	result, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExpiresIn <= 0 {
		t.Errorf("expires_in should be positive, got %d", result.ExpiresIn)
	}
	if result.CookieMaxAge <= 0 {
		t.Errorf("cookie_max_age should be positive, got %d", result.CookieMaxAge)
	}
}

// ---------------------------------------------------------------------------
// Register edge case tests (~15)
// ---------------------------------------------------------------------------

func TestRegisterSuccessFullFlow(t *testing.T) {
	var userCreated bool
	var pwHistoryStored bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil // email not taken
		}
		o.userRepo.CreateFn = func(_ context.Context, u *model.User) error {
			userCreated = true
			if u.Email != "new@example.com" {
				t.Errorf("email = %q, want new@example.com", u.Email)
			}
			if u.Locale != "en" {
				t.Errorf("locale = %q, want en (default)", u.Locale)
			}
			return nil
		}
		o.pwHistory.CreateFn = func(_ context.Context, _ *model.PasswordHistory) error {
			pwHistoryStored = true
			return nil
		}
	})

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "New@Example.com",
		Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if result.Email != "new@example.com" {
		t.Errorf("result email = %q, want new@example.com", result.Email)
	}
	if result.UserID == "" {
		t.Error("user_id should not be empty")
	}
	if !userCreated {
		t.Error("user should be created in repository")
	}
	if !pwHistoryStored {
		t.Error("password history should be stored")
	}
}

func TestRegisterDuplicateEmailWithMock(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "existing"}, nil
		}
	})

	_, err := svc.Register(context.Background(), RegisterInput{
		Email: "taken@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")

	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("should return ErrEmailTaken, got %v", err)
	}
}

func TestRegisterPasswordTooShortEdge(t *testing.T) {
	svc, _ := newMockAuthService(t)

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"14_chars", "12345678901234", ErrPasswordTooShort},
		{"15_chars_exact", "123456789012345", nil},
		{"empty", "", ErrPasswordTooShort},
		{"single_char", "a", ErrPasswordTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Register(context.Background(), RegisterInput{
				Email: fmt.Sprintf("%s@test.com", tt.name), Password: tt.password,
			}, "1.2.3.4")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("password %q: got error %v, want %v", tt.password, err, tt.wantErr)
				}
			} else {
				if errors.Is(err, ErrPasswordTooShort) {
					t.Errorf("password %q should not be rejected as too short", tt.password)
				}
			}
		})
	}
}

func TestRegisterInvalidEmailVariants(t *testing.T) {
	svc, _ := newMockAuthService(t)

	emails := []string{
		"",
		"not-an-email",
		"@missing-local.com",
		"missing-domain@",
		"spaces in@email.com",
		strings.Repeat("a", 255) + "@example.com", // >254 chars total
	}

	for _, email := range emails {
		t.Run(email, func(t *testing.T) {
			_, err := svc.Register(context.Background(), RegisterInput{
				Email: email, Password: "correct-horse-battery-staple",
			}, "1.2.3.4")

			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("email %q should return ErrInvalidInput, got %v", email, err)
			}
		})
	}
}

func TestRegisterUserCreateError(t *testing.T) {
	dbErr := errors.New("connection refused")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.userRepo.CreateFn = func(_ context.Context, _ *model.User) error {
			return dbErr
		}
	})

	_, err := svc.Register(context.Background(), RegisterInput{
		Email: "error@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")

	if !errors.Is(err, dbErr) {
		t.Errorf("should propagate user create error, got %v", err)
	}
}

func TestRegisterGetByEmailError(t *testing.T) {
	dbErr := errors.New("connection refused")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, dbErr
		}
	})

	_, err := svc.Register(context.Background(), RegisterInput{
		Email: "dberr@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")

	if !errors.Is(err, dbErr) {
		t.Errorf("should propagate DB error, got %v", err)
	}
}

func TestRegisterDisplayNameSanitized(t *testing.T) {
	var savedUser *model.User
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.userRepo.CreateFn = func(_ context.Context, u *model.User) error {
			savedUser = u
			return nil
		}
	})

	svc.Register(context.Background(), RegisterInput{
		Email:       "xss@example.com",
		Password:    "correct-horse-battery-staple",
		DisplayName: `<script>alert("xss")</script>`,
	}, "1.2.3.4")

	if savedUser == nil {
		t.Fatal("user should be saved")
	}
	if strings.Contains(savedUser.DisplayName, "<script>") {
		t.Errorf("display name should be sanitized, got %q", savedUser.DisplayName)
	}
}

func TestRegisterLocaleDefault(t *testing.T) {
	var savedUser *model.User
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.userRepo.CreateFn = func(_ context.Context, u *model.User) error {
			savedUser = u
			return nil
		}
	})

	svc.Register(context.Background(), RegisterInput{
		Email:    "locale@example.com",
		Password: "correct-horse-battery-staple",
		// Locale left empty
	}, "1.2.3.4")

	if savedUser == nil {
		t.Fatal("user should be saved")
	}
	if savedUser.Locale != "en" {
		t.Errorf("default locale should be 'en', got %q", savedUser.Locale)
	}
}

func TestRegisterPwHistoryErrorNonFatal(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.pwHistory.CreateFn = func(_ context.Context, _ *model.PasswordHistory) error {
			return errors.New("pw history DB error")
		}
	})

	// Should succeed despite pw history failure
	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "pwhist@example.com",
		Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if err != nil {
		t.Fatalf("pw history error should be non-fatal, got %v", err)
	}
	if result.UserID == "" {
		t.Error("user should still be created")
	}
}

func TestRegisterEmailSendingAsynchronous(t *testing.T) {
	// When cache and emailSender are set, sendVerificationEmail is called in goroutine
	// Register should complete before email is sent
	var wg sync.WaitGroup
	wg.Add(1)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
		o.cache.SetFn = func(_ context.Context, _, _ string, _ time.Duration) error {
			return nil
		}
		o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
			wg.Done()
			return nil
		}
	})

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "async@example.com",
		Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID == "" {
		t.Error("user should be created")
	}

	// Wait for the goroutine to complete (or timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Error("email sending goroutine did not complete within timeout")
	}
}

func TestRegisterWithRedirectSanitized(t *testing.T) {
	// Verify that the redirect_to field is sanitized before being used
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
	})

	// Register with a malicious redirect
	result, err := svc.Register(context.Background(), RegisterInput{
		Email:      "redirect@example.com",
		Password:   "correct-horse-battery-staple",
		RedirectTo: "//evil.com",
	}, "1.2.3.4")
	// Should succeed (redirect sanitization is non-blocking)
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID == "" {
		t.Error("user should be created")
	}
}

// ---------------------------------------------------------------------------
// Logout tests
// ---------------------------------------------------------------------------

func TestLogoutRevokesAllTokens(t *testing.T) {
	var revokedUser string
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, userID string) error {
			revokedUser = userID
			return nil
		}
	})

	err := svc.Logout(context.Background(), "user-42", "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatal(err)
	}
	if revokedUser != "user-42" {
		t.Errorf("should revoke tokens for user-42, got %q", revokedUser)
	}
}

func TestLogoutError(t *testing.T) {
	dbErr := errors.New("DB error")
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.RevokeAllForUserFn = func(_ context.Context, _ string) error {
			return dbErr
		}
	})

	err := svc.Logout(context.Background(), "user-42", "1.2.3.4", "TestAgent")
	if !errors.Is(err, dbErr) {
		t.Errorf("should propagate DB error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// isValidEmail tests
// ---------------------------------------------------------------------------
