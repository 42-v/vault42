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

	res, err := svc.CompleteMFALogin(context.Background(), "erased-during-mfa", "fp", "9.9.9.9", "UA", "")
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
