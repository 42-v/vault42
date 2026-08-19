package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// TestGetStatusFailsClosedOnASingleLookupError pins the MFA fail-open fix.
//
// GetStatus reads TOTP and WebAuthn. For a passkey-only account the TOTP read
// succeeds and returns nothing, so a webauthn read error left the old "both
// failed" guard unsatisfied: GetStatus returned an empty method set with no
// error, and the login path reads an empty method set as "no second factor".
// Either lookup failing means a factor may exist that this call cannot see, so
// the status is undetermined and must be an error.
func TestGetStatusFailsClosedOnASingleLookupError(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{}, // GetByUserID returns (nil, nil): no totp, no error
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("webauthn_credentials read failed")
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)

	if _, err := svc.GetStatus(context.Background(), "user-1"); err == nil {
		t.Fatal("GetStatus must fail closed when the webauthn lookup errors even though the " +
			"totp lookup succeeded; an empty method set with no error lets the login path skip " +
			"the second factor a passkey-only account holds")
	}
}

// TestLoginFailsClosedWhenMFAStatusIsUndetermined pins the login-side half.
//
// mfaRequired is false, so before the fix an undetermined MFA status fell
// through the no-methods branch straight to a single-step login that issued
// real tokens: a full second-factor bypass for a passkey-only account whose
// webauthn read merely hiccuped. Login must refuse instead.
func TestLoginFailsClosedWhenMFAStatusIsUndetermined(t *testing.T) {
	ctx := context.Background()
	hash := validPasswordHash(t)

	mfaSvc := NewMFAService(
		&mocks.MockTOTPRepo{}, // no totp, no error
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("webauthn_credentials read failed")
			},
		},
		&mocks.MockBackupCodeRepo{},
		false, // MFA not globally required: the undetermined path would otherwise issue full tokens
	)

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaSvc
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "passkey@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
	})

	res, err := svc.Login(ctx, LoginInput{
		Email: "passkey@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err == nil {
		t.Fatalf("login must fail closed when MFA status cannot be determined, but it returned a "+
			"result (%+v); a passkey-only account whose webauthn read errors would otherwise be "+
			"logged in with no second factor at all", res)
	}
}
