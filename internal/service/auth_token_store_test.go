package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// A login mints a refresh token and then stores it. If the store fails and the login
// still returned the pair, the user would walk away holding a refresh token the server
// has no record of — every refresh would be rejected as unknown, and the session would
// die at the first rotation with no explanation. Worse, the token family that
// reuse-detection relies on would not exist, so the safety net would be absent for a
// token that is nonetheless valid until it expires.
func TestLogin_RefreshTokenStoreFailureFailsTheLogin(t *testing.T) {
	hash := validPasswordHash(t)

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: email, PasswordHash: hash, EmailVerified: true}, nil
		}
		o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
			return errors.New("db down")
		}
	})

	res, err := svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct-horse-battery-staple",
	}, "203.0.113.1", "TestAgent")

	if err == nil {
		t.Fatal("login succeeded while the refresh token was never stored")
	}
	if res != nil {
		t.Error("a failed login returned a result")
	}
}

// The last_login stamp is cosmetic. It is explicitly best-effort, and a failure to write
// it must not cost the user their login — the opposite bug (failing the login because a
// bookkeeping column would not update) would lock everyone out over nothing.
func TestLogin_LastLoginStampFailureDoesNotFailTheLogin(t *testing.T) {
	hash := validPasswordHash(t)

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-1", Email: email, PasswordHash: hash, EmailVerified: true}, nil
		}
		o.userRepo.SetLastLoginFn = func(context.Context, string) error {
			return errors.New("db down")
		}
	})

	res, err := svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct-horse-battery-staple",
	}, "203.0.113.1", "TestAgent")
	if err != nil {
		t.Fatalf("a failed last_login stamp cost the user their login: %v", err)
	}
	if res == nil || res.AccessToken == "" {
		t.Error("no tokens were issued")
	}
}
