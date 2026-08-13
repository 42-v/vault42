package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// unverifiedLoginProbe drives one login against an unverified account and
// reports whether the attempt was counted as a failure.
//
// The returned error is deliberately ignored by the callers below. The whole
// point of the defect being guarded is that the error is identical on both
// paths, so asserting on it proves nothing; what differs is the bookkeeping.
func unverifiedLoginProbe(t *testing.T, password string) (counted bool) {
	t.Helper()

	hash := validPasswordHash(t)
	var increments int

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "unverified@example.com",
				PasswordHash: hash, EmailVerified: false,
			}, nil
		}
		o.userRepo.IncrementFailedLoginFn = func(_ context.Context, _ string) error {
			increments++
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "unverified@example.com", Password: password,
	}, "127.0.0.1", "TestAgent")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on an unverified account, got %v", err)
	}
	return increments > 0
}

// TestUnverifiedLoginIsNotAPasswordOracle closes a clean binary confirmation of
// a real password.
//
// Login returns ErrInvalidCredentials for an unverified account precisely so an
// attacker cannot tell "unverified" from "wrong password" from "no such user".
// The error was identical. The side effects were not.
//
// Every other post-lookup non-success outcome runs recordLoginFailure, which
// increments the failed-login count, the lockout counter, the per-IP counter,
// the vault_login_failed_total metric, and writes an audit row. The
// !user.EmailVerified branch returned ErrInvalidCredentials with none of it, so:
//
//   - a WRONG password against an unverified account incremented the lockout
//     counter, and after lockoutThreshold attempts the endpoint started
//     answering 403 account_locked;
//   - the CORRECT password against the same account never touched the counter,
//     so it answered 401 forever.
//
// Six attempts therefore told an attacker whether their candidate was the real
// password, which is exactly the distinction the comment above that branch
// claims cannot be made. It also meant an attacker holding the correct password
// of an unverified account could hammer the endpoint indefinitely without ever
// locking out, producing no audit rows and leaving the failure metric flat.
//
// The comment on recordLoginFailure states the invariant directly: every
// post-lookup outcome that is not a successful authentication goes through that
// one function, so the paths cannot drift apart into distinguishable side
// effects. This test is that sentence made executable.
func TestUnverifiedLoginIsNotAPasswordOracle(t *testing.T) {
	withCorrectPassword := unverifiedLoginProbe(t, "correct-horse-battery-staple")
	withWrongPassword := unverifiedLoginProbe(t, "not-the-password-at-all")

	if withCorrectPassword != withWrongPassword {
		t.Errorf("an unverified login counts as a failure for a wrong password (%v) but not for "+
			"the correct one (%v). The lockout counter therefore advances only on wrong "+
			"guesses, so an attacker who sees 403 account_locked learns their candidate was "+
			"wrong and one who keeps seeing 401 learns it was right.",
			withWrongPassword, withCorrectPassword)
	}
	if !withCorrectPassword {
		t.Error("neither unverified login was recorded as a failure, so lockout never advances " +
			"on this path and an attacker can guess against an unverified account forever")
	}
}

// TestUnverifiedLoginStillLooksIdenticalToTheCaller is the other half.
//
// Routing the unverified branch through the failure bookkeeping must not change
// what the caller sees, or the fix would trade a side-effect oracle for a
// response oracle. Both passwords must still come back as the same error.
func TestUnverifiedLoginStillLooksIdenticalToTheCaller(t *testing.T) {
	hash := validPasswordHash(t)

	for _, tc := range []struct {
		name     string
		password string
	}{
		{"correct password", "correct-horse-battery-staple"},
		{"wrong password", "not-the-password-at-all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
					return &model.User{
						ID: "user-1", Email: "unverified@example.com",
						PasswordHash: hash, EmailVerified: false,
					}, nil
				}
			})

			res, err := svc.Login(context.Background(), LoginInput{
				Email: "unverified@example.com", Password: tc.password,
			}, "127.0.0.1", "TestAgent")

			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("got %v, want ErrInvalidCredentials", err)
			}
			if res != nil {
				t.Errorf("an unverified login returned a result alongside the error: %+v", res)
			}
		})
	}
}
