package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// TestLoginDoesNotResetTheMFALockoutOnTheFirstFactor guards audit H2 against a
// first-factor reset.
//
// The per-account MFA lockout counter is shared with the password path:
// RecordMFAFailure increments "lockout:<uid>" and MFAVerifyLocked reads it, so
// a run of wrong second-factor guesses trips the same threshold the password
// path uses. Its whole purpose is that the second factor is not brute-forceable
// within the challenge window even by an attacker who already holds the password
// (per-IP limits are defeated by IP rotation).
//
// Login clears that counter on a SUCCESSFUL first factor. On the single-step
// path that is correct: a full login just happened. On the path that still owes
// a second factor it hands an attacker who holds the password a free reset: log
// in, burn four MFA guesses, log in again to zero the counter, burn four more,
// forever, and the lockout never trips. The reset must wait for the full login
// to complete, which is why CompleteMFALogin (and only it, on the MFA path)
// calls clearLockout.
func TestLoginDoesNotResetTheMFALockoutOnTheFirstFactor(t *testing.T) {
	ctx := context.Background()
	hash := validPasswordHash(t)

	mem := cache.NewMemoryCache()
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
		// Back the cache spy with a real in-memory store so the counter behaves
		// like production: Increment accumulates, Delete zeroes it.
		o.cache.GetFn = mem.Get
		o.cache.SetFn = mem.Set
		o.cache.DeleteFn = mem.Delete
		o.cache.GetAndDeleteFn = mem.GetAndDelete
		o.cache.SetIfNotExistsFn = mem.SetIfNotExists
		o.cache.IncrementFn = mem.Increment
		o.cache.ExistsFn = mem.Exists
	})

	// Attacker burns all but one of the allowed second-factor guesses.
	for i := 0; i < lockoutThreshold-1; i++ {
		svc.RecordMFAFailure(ctx, "user-1", "1.2.3.4", "TestAgent")
	}
	if svc.MFAVerifyLocked(ctx, "user-1") {
		t.Fatalf("account locked before the threshold (%d-1 failures)", lockoutThreshold)
	}

	// Correct password, second factor still owed. This must NOT reset the counter.
	res, err := svc.Login(ctx, LoginInput{
		Email: "mfa@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("first-factor login should succeed with a challenge, got %v", err)
	}
	if res == nil || !res.Requires2FA {
		t.Fatalf("expected an MFA challenge, got %+v", res)
	}

	// One more failed second-factor attempt must now trip the lockout. If the
	// first-factor login zeroed the counter, this is only the first failure and
	// the account stays open, so the attacker guesses on unthrottled.
	svc.RecordMFAFailure(ctx, "user-1", "1.2.3.4", "TestAgent")
	if !svc.MFAVerifyLocked(ctx, "user-1") {
		t.Fatalf("H2 bypass: a first-factor login reset the shared MFA lockout counter, so %d "+
			"second-factor failures did not lock the account; an attacker holding the password "+
			"can re-login to zero the counter and brute-force the second factor indefinitely",
			lockoutThreshold)
	}
}
