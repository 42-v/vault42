package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
)

// Successful login with a metrics collector wired in covers the
// RecordLoginAttempt + RecordLoginSuccess/RecordTokenIssued counter branches.
func TestLogin_MetricsRecordedOnSuccess(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: "m@x.test", PasswordHash: hash, EmailVerified: true}, nil
		}
	})
	svc.SetMetrics(&metrics.Collector{})

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "m@x.test", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("login should succeed, got %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected an access token on success")
	}
}

// Wrong-password login with metrics wired in covers RecordLoginAttempt +
// the RecordLoginFailed branch on the wrong-password path.
func TestLogin_MetricsRecordedOnWrongPassword(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: "wp@x.test", PasswordHash: hash, EmailVerified: true}, nil
		}
	})
	svc.SetMetrics(&metrics.Collector{})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "wp@x.test", Password: "definitely-the-wrong-pw!!",
	}, "1.2.3.4", "TestAgent")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password should return ErrInvalidCredentials, got %v", err)
	}
}

// Unknown-user login with metrics wired in covers the RecordLoginFailed branch
// on the anti-enumeration (user==nil) path.
func TestLogin_MetricsRecordedOnUnknownUser(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		}
	})
	svc.SetMetrics(&metrics.Collector{})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "ghost@x.test", Password: "whatever-password-here",
	}, "1.2.3.4", "TestAgent")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user should return ErrInvalidCredentials, got %v", err)
	}
}

// A ResetFailedLogin failure on an otherwise-successful login is logged but
// does not block the login — covers the reset-error branch.
func TestLogin_ResetFailedLoginErrorIsNonFatal(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: "rfe@x.test", PasswordHash: hash, EmailVerified: true}, nil
		}
		o.userRepo.ResetFailedLoginFn = func(_ context.Context, _ string) error {
			return errors.New("db down")
		}
	})

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "rfe@x.test", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("reset-failed-login error must not block login, got %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected access token despite reset error")
	}
}

// A wrong password that pushes the account over the lockout threshold triggers
// the one-shot lock-notification email branch. The cache reports "not locked"
// on the pre-password-check and "locked" on the post-failure check.
func TestLogin_LockNotificationEmailSent(t *testing.T) {
	hash := validPasswordHash(t)
	var mu sync.Mutex
	lockoutReads := 0
	var emailSent bool
	emailWG := make(chan struct{}, 1)

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{ID: "user-lock", Email: "lock@x.test", PasswordHash: hash, EmailVerified: true}, nil
		}
		o.cache.GetFn = func(_ context.Context, key string) (string, error) {
			if !strings.HasPrefix(key, "lockout:") {
				return "", cache.ErrNotFound
			}
			mu.Lock()
			defer mu.Unlock()
			// The account-wide counter is a separate key now, and it is nowhere
			// near the distributed threshold in this scenario.
			if !strings.Contains(key, "|") {
				return "0", nil
			}
			lockoutReads++
			// First per-source read (pre-verify) → not locked; post-failure → locked.
			if lockoutReads == 1 {
				return "0", nil
			}
			return "99", nil
		}
		o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
			mu.Lock()
			emailSent = true
			mu.Unlock()
			select {
			case emailWG <- struct{}{}:
			default:
			}
			return nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "lock@x.test", Password: "wrong-password-value!!",
	}, "1.2.3.4", "TestAgent")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password should return ErrInvalidCredentials, got %v", err)
	}
	// The notification email fires in a goroutine; wait briefly for it.
	<-emailWG
	mu.Lock()
	defer mu.Unlock()
	if !emailSent {
		t.Fatal("lock-notification email should have been sent on lockout")
	}
}
