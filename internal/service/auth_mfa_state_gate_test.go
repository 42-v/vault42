package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The challenge token issued after the password step lives for minutes, and the
// account state is re-read when the second factor completes because those
// minutes are exactly the window an operator uses to react to a compromise.
// Banned, disabled and locked are pinned in tests/attack; deletion is the
// fourth state and the one with the different answer.
//
// A deleted subject gets ErrTokenInvalid rather than an account-state error on
// purpose. Login already answers ErrInvalidCredentials for a deleted account so
// that it is indistinguishable from one that never existed, and a distinct
// "this account was deleted" here would hand back through the second factor the
// exact oracle the password step refuses to give. What the caller is told is
// that the challenge is no good, which is also true.
func TestCompleteMFALoginRefusesDeletedAccount(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user", "admin"}, Deleted: true}, nil
	}
	var stored bool
	o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
		stored = true
		return nil
	}

	res, err := svc.CompleteMFALogin(context.Background(), "erased-during-mfa", "fp", "9.9.9.9", "UA", "", MFACompletion{Method: MethodTOTP})
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid; an account erased during the challenge window completed 2FA into a full session", err)
	}
	if res != nil {
		t.Error("a token pair was returned for a deleted account")
	}
	if stored {
		t.Error("a refresh family was opened for a deleted account, so the session would outlive the challenge")
	}
}

// TestCompleteMFALoginRefusesAnAccountThatMayNotUseItsPassword covers the two
// states Login refuses before a challenge exists: an operator's forced reset
// (adminapi require-password-reset) and an unclaimed import. Either can be set
// while a challenge minted from the password is still live, and the challenge
// must not redeem into the session the flag exists to prevent.
func TestCompleteMFALoginRefusesAnAccountThatMayNotUseItsPassword(t *testing.T) {
	for name, user := range map[string]model.User{
		"forced reset":     {MustResetPassword: true},
		"unclaimed import": {ImportPending: true},
	} {
		t.Run(name, func(t *testing.T) {
			svc, o := newMockAuthService(t)
			o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
				u := user
				u.ID, u.Roles = id, []string{"user"}
				return &u, nil
			}
			var stored bool
			o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
				stored = true
				return nil
			}

			res, err := svc.CompleteMFALogin(context.Background(), "flagged-during-mfa", "fp", "9.9.9.9", "UA", "", MFACompletion{Method: MethodTOTP})
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("err = %v, want ErrTokenInvalid", err)
			}
			if res != nil || stored {
				t.Error("a session was issued for an account whose password may not be used")
			}
		})
	}
}
