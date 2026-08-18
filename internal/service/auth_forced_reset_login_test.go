package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// A forced password reset (model.User.MustResetPassword, migration 039) refuses
// the password path and mails a reset link instead. It is the general form of
// what 006 built for an unclaimed import, and it inherits that branch's whole
// security argument: the outcome an unauthenticated caller sees must be the
// outcome a wrong password sees, or the endpoint has become an oracle that says
// "this address is registered, and here is what state it is in".
//
// What is new is that the state is legitimately useful to a first-party client,
// which is why there is a second outcome at all. That outcome is reachable only
// after client-credential authentication carrying the login:status scope, which
// the transport establishes; the service is handed the answer as
// LoginInput.DiscloseStatus and must not otherwise behave differently. These
// tests pin both halves: the public answer stays identical, and every side
// effect stays identical whichever answer is returned.

func forcedResetService(t *testing.T, hash string) (*AuthService, *mockAuthOpts) {
	t.Helper()
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{
			ID: "u-forced", Email: "rider@legacy.test", EmailVerified: true,
			PasswordHash: hash, MustResetPassword: true,
		}, nil
	}
	return svc, o
}

func TestLogin_MustResetPasswordIsIndistinguishableFromWrongPassword(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := forcedResetService(t, hash)

	// The correct password. A caller who guessed right must learn nothing a
	// caller who guessed wrong does not.
	res, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a public caller must get ErrInvalidCredentials on a flagged account, got %v", err)
	}
	if errors.Is(err, ErrPasswordResetRequired) {
		t.Fatal("the distinct status reached an unauthenticated caller: the address is now known " +
			"to be registered, and known to be mid-migration")
	}
	if res != nil {
		t.Fatalf("no result may be returned: a forced reset is a failed login, got %+v", res)
	}
}

func TestLogin_MustResetPasswordTellsAScopedClientWhy(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := forcedResetService(t, hash)

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
		DiscloseStatus: true,
	}, "1.2.3.4", "UA")

	if !errors.Is(err, ErrPasswordResetRequired) {
		t.Fatalf("a client authorized for the status must be told why the login was refused, got %v", err)
	}
	if res != nil {
		t.Fatalf("the distinct status is still a refusal: no session may come with it, got %+v", res)
	}
}

// The password is not verified on this branch at all -- the stored hash may be a
// legacy scheme nothing here can parse -- so the distinct status must not vary
// with the password either. If it did, a client holding the scope would have a
// password oracle for every flagged account rather than a migration signal.
func TestLogin_MustResetPasswordDoesNotDependOnThePassword(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := forcedResetService(t, hash)

	_, wrong := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "not-the-password-at-all",
		DiscloseStatus: true,
	}, "1.2.3.4", "UA")
	_, right := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
		DiscloseStatus: true,
	}, "1.2.3.4", "UA")

	if !errors.Is(wrong, ErrPasswordResetRequired) || !errors.Is(right, ErrPasswordResetRequired) {
		t.Fatalf("the scoped client's answer varies with the password: wrong=%v right=%v", wrong, right)
	}
}

// The bookkeeping is the anti-enumeration property, not hygiene: a branch that
// skipped it would leave the flagged account answering forever while every other
// account locks out, which is the same oracle one step removed. It must also be
// identical for the disclosed and undisclosed outcomes, or the scope becomes a
// way to guess without paying for the guesses.
func TestLogin_MustResetPasswordFeedsTheSameLockoutCounters(t *testing.T) {
	for _, disclose := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "scoped client"}[disclose], func(t *testing.T) {
			hash := validPasswordHash(t)
			svc, o := forcedResetService(t, hash)

			var failedLoginUser string
			o.userRepo.IncrementFailedLoginFn = func(_ context.Context, id string) error {
				failedLoginUser = id
				return nil
			}

			var mu sync.Mutex
			counters := map[string]int{}
			o.cache.IncrementFn = func(_ context.Context, key string, _ time.Duration) (int64, error) {
				mu.Lock()
				defer mu.Unlock()
				counters[key]++
				return int64(counters[key]), nil
			}

			_, err := svc.Login(context.Background(), LoginInput{
				Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
				DiscloseStatus: disclose,
			}, "1.2.3.4", "UA")
			if err == nil {
				t.Fatal("a flagged account must not log in")
			}

			if failedLoginUser != "u-forced" {
				t.Error("the durable failed-login counter must advance exactly as it does for a wrong password")
			}
			mu.Lock()
			defer mu.Unlock()
			if counters["lockout:u-forced"] != 1 {
				t.Errorf("per-account lockout counter = %d, want 1: the flag would evade lockout",
					counters["lockout:u-forced"])
			}
			if counters["lockout_ip:1.2.3.4"] != 1 {
				t.Errorf("per-IP lockout counter = %d, want 1", counters["lockout_ip:1.2.3.4"])
			}
			var throttled int
			for key, n := range counters {
				if strings.HasPrefix(key, "auththrottle:") {
					throttled += n
				}
			}
			if throttled != 1 {
				t.Errorf("identity throttle counter = %d, want 1: the progressive delay every other "+
					"failure pays must be paid here too", throttled)
			}
		})
	}
}

// The reset link is the only way out of the state, so it must be sent -- out of
// band, where it is not an answer to the caller. It must NOT carry the import=1
// marker: that marker tells the frontend to word the page as claiming a migrated
// account, and this account may be an ordinary one an operator flagged.
func TestLogin_MustResetPasswordMailsAPlainResetLink(t *testing.T) {
	hash := validPasswordHash(t)
	svc, o := forcedResetService(t, hash)

	sent := make(chan string, 4)
	o.emailSender.SendFn = func(_ context.Context, to, _, _, text string) error {
		sent <- to + "|" + text
		return nil
	}

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	select {
	case got := <-sent:
		if !strings.Contains(got, "rider@legacy.test") || !strings.Contains(got, "/reset-password?token=") {
			t.Errorf("no reset link was mailed, so the account can never leave the state: %q", got)
		}
		if strings.Contains(got, "import=1") {
			t.Errorf("the forced-reset link carries the import claim marker: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reset link was mailed; a flagged account could never sign in again")
	}
}

// Without the throttle, an unauthenticated login is a mail cannon aimed at any
// address the caller knows, and every send invalidates the link the victim is
// part-way through using. The reservation is per account, so repeated attempts
// inside the window send once.
func TestLogin_MustResetPasswordMailsAtMostOncePerWindow(t *testing.T) {
	hash := validPasswordHash(t)
	svc, o := forcedResetService(t, hash)

	var mu sync.Mutex
	reserved := map[string]bool{}
	o.cache.SetIfNotExistsFn = func(_ context.Context, key, _ string, _ time.Duration) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if reserved[key] {
			return false, nil
		}
		reserved[key] = true
		return true, nil
	}
	sends := make(chan struct{}, 8)
	o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
		sends <- struct{}{}
		return nil
	}

	for i := 0; i < 5; i++ {
		if _, err := svc.Login(context.Background(), LoginInput{
			Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
		}, "1.2.3.4", "UA"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}
	select {
	case <-sends:
	case <-time.After(2 * time.Second):
		t.Fatal("the first reset link was never sent")
	}
	time.Sleep(200 * time.Millisecond)

	if extra := len(sends); extra != 0 {
		t.Errorf("%d extra reset mails sent; the login endpoint is an unauthenticated mail trigger", extra)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reserved["forced_reset_sent:u-forced"] {
		t.Errorf("the forced reset did not take a throttle reservation of its own: %v", reserved)
	}
}

// The two states have separate throttle keys on purpose. An account that was
// imported and then claimed still carries the forced-reset flag, and its reset
// mail must not be suppressed by the claim mail's reservation, which is still
// live for the rest of the hour.
func TestLogin_ForcedResetMailIsNotSuppressedByAnImportClaimReservation(t *testing.T) {
	hash := validPasswordHash(t)
	svc, o := forcedResetService(t, hash)

	var mu sync.Mutex
	reserved := map[string]bool{"import_claim_sent:u-forced": true} // an hour ago, while unclaimed
	o.cache.SetIfNotExistsFn = func(_ context.Context, key, _ string, _ time.Duration) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if reserved[key] {
			return false, nil
		}
		reserved[key] = true
		return true, nil
	}
	sends := make(chan struct{}, 4)
	o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
		sends <- struct{}{}
		return nil
	}

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	select {
	case <-sends:
	case <-time.After(2 * time.Second):
		t.Fatal("the claim reservation suppressed the forced-reset mail, so the account is stuck")
	}
}

// An unclaimed import is decided first. It is the more specific state -- there is
// no credential at all, and its link has to carry import=1 -- and deciding it
// first is what keeps this change from altering any outcome an imported account
// already had.
func TestLogin_UnclaimedImportOutranksAForcedReset(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{
			ID: "u-both", Email: "rider@legacy.test", EmailVerified: true,
			ImportPending: true, ImportedFrom: "legacy", MustResetPassword: true,
		}, nil
	}
	sent := make(chan string, 4)
	o.emailSender.SendFn = func(_ context.Context, to, _, _, text string) error {
		sent <- to + "|" + text
		return nil
	}

	// Even the scoped client is told nothing here: the account is an unclaimed
	// import, and that state has always been indistinguishable from a wrong
	// password.
	_, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "anything", DiscloseStatus: true,
	}, "1.2.3.4", "UA")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an unclaimed import must still answer ErrInvalidCredentials, got %v", err)
	}

	select {
	case got := <-sent:
		if !strings.Contains(got, "import=1") {
			t.Errorf("the mail lost the import claim marker, so the claim page is worded wrong: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no claim link was mailed")
	}
}
