package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Email OTP is the weakest factor the service will accept, and it is only
// legitimate for an account that has no stronger one enrolled. The gate that
// decides this reads the MFA status, and the two ways that read can be
// unavailable (the status query fails, or the single-use cache is missing) both
// have to deny. Answering "allowed" on an unknown status is the MFA downgrade
// the gate exists to stop.

// serviceAuthBrokenMFA returns an MFAService whose status lookup fails: both
// primary factor queries are down, which is what makes GetStatus report an
// error rather than an empty method list.
func serviceAuthBrokenMFA() *MFAService {
	fail := errors.New("mfa store unreachable")
	return NewMFAService(
		&mocks.MockTOTPRepo{GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) {
			return nil, fail
		}},
		&mocks.MockWebAuthnRepo{ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return nil, fail
		}},
		&mocks.MockBackupCodeRepo{},
		true,
	)
}

func TestEmailOTPDeniedWhenMFAStatusUnavailable(t *testing.T) {
	var cached, sent, consumed atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = serviceAuthBrokenMFA()
		o.cache.SetFn = func(context.Context, string, string, time.Duration) error {
			cached.Store(true)
			return nil
		}
		o.cache.GetAndDeleteFn = func(context.Context, string) (string, error) {
			consumed.Store(true)
			return "", nil
		}
		o.emailSender.SendFn = func(context.Context, string, string, string, string) error {
			sent.Store(true)
			return nil
		}
	})

	if svc.emailOTPAllowed(context.Background(), "user-1") {
		t.Fatal("email OTP was allowed while the MFA status was unknown")
	}

	if err := svc.SendEmailOTP(context.Background(), "user-1", "otp@example.com"); !errors.Is(err, ErrEmailOTPNotAllowed) {
		t.Errorf("SendEmailOTP err = %v, want ErrEmailOTPNotAllowed", err)
	}
	if cached.Load() || sent.Load() {
		t.Error("an OTP was minted for an account whose enrolled factors could not be read")
	}

	if err := svc.VerifyEmailOTP(context.Background(), "user-1", "000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("VerifyEmailOTP err = %v, want ErrInvalidCredentials", err)
	}
	if consumed.Load() {
		t.Error("the gated verify path consumed the cached OTP, so a retry would find it gone")
	}
}

// Without a cache there is no atomic GetAndDelete, so an accepted code could be
// replayed for the rest of its window. The verify must deny instead.
func TestVerifyEmailOTPDeniedWithoutCache(t *testing.T) {
	svc := &AuthService{mfaSvc: mfaNoMethods(true)}

	if !svc.emailOTPAllowed(context.Background(), "user-1") {
		t.Fatal("test setup: email OTP should be the permitted factor here")
	}
	if err := svc.VerifyEmailOTP(context.Background(), "user-1", "000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("VerifyEmailOTP err = %v, want ErrInvalidCredentials when single-use storage is unavailable", err)
	}
}
