package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// mfaWithTOTP builds an MFAService reporting a verified TOTP factor (a "strong"
// enrolled method). mfaNoMethods builds one with no enrolled factors.
func mfaWithTOTP(required bool) *MFAService {
	return NewMFAService(
		&mocks.MockTOTPRepo{GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "t1", Verified: true}, nil
		}},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{},
		required,
	)
}

func mfaNoMethods(required bool) *MFAService {
	return NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, required)
}

func TestEmailOTPAllowed(t *testing.T) {
	tests := []struct {
		name string
		mfa  *MFAService
		want bool
	}{
		{"no methods + required → allowed", mfaNoMethods(true), true},
		{"no methods + not required → denied", mfaNoMethods(false), false},
		{"TOTP enrolled + required → denied (no downgrade)", mfaWithTOTP(true), false},
		{"TOTP enrolled + not required → denied", mfaWithTOTP(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &AuthService{mfaSvc: tt.mfa}
			if got := s.emailOTPAllowed(context.Background(), "u1"); got != tt.want {
				t.Fatalf("emailOTPAllowed = %v, want %v", got, tt.want)
			}
		})
	}
}

// Audit H1: a user with TOTP enrolled must not be able to send/verify an email
// OTP (factor downgrade), even with a valid challenge.
func TestEmailOTP_DowngradeBlocked(t *testing.T) {
	s := &AuthService{mfaSvc: mfaWithTOTP(true)}

	if err := s.SendEmailOTP(context.Background(), "u1", "v@x.test"); !errors.Is(err, ErrEmailOTPNotAllowed) {
		t.Fatalf("SendEmailOTP for TOTP user = %v, want ErrEmailOTPNotAllowed", err)
	}
	// Verify is gated before any cache lookup, so a nil cache must not panic and
	// must reject as invalid credentials.
	if err := s.VerifyEmailOTP(context.Background(), "u1", "123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("VerifyEmailOTP for TOTP user = %v, want ErrInvalidCredentials", err)
	}
}

// A no-factor account with MFA required passes the gate (so the email-OTP
// fallback still works); the send then fails only for the expected missing-deps
// reason, not the gate.
func TestEmailOTP_FallbackPassesGate(t *testing.T) {
	s := &AuthService{mfaSvc: mfaNoMethods(true)}
	err := s.SendEmailOTP(context.Background(), "u1", "v@x.test")
	if errors.Is(err, ErrEmailOTPNotAllowed) {
		t.Fatalf("fallback account should pass the gate, got ErrEmailOTPNotAllowed")
	}
	// cache/sender are nil in this unit, so we expect the deps error instead.
	if err == nil {
		t.Fatalf("expected missing-deps error with nil cache/sender")
	}
}
