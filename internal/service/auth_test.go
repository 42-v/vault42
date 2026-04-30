package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// TestLoginNonExistentUser verifies that a nonexistent user returns
// ErrInvalidCredentials (not "user not found") to prevent enumeration.
func TestLoginNonExistentUser(t *testing.T) {
	svc, _ := newMockAuthService(t)

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "nobody@example.com", Password: "correct-horse-battery-staple",
	}, "127.0.0.1", "TestAgent")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("nonexistent user should return ErrInvalidCredentials, got %v", err)
	}
}

// TestLoginEmailNotVerified verifies that an unverified email returns
// ErrInvalidCredentials (anti-enumeration: same as wrong password).
func TestLoginEmailNotVerified(t *testing.T) {
	hash := validPasswordHash(t)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "unverified@example.com",
				PasswordHash: hash, EmailVerified: false,
			}, nil
		}
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email: "unverified@example.com", Password: "correct-horse-battery-staple",
	}, "127.0.0.1", "TestAgent")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unverified email should return ErrInvalidCredentials (anti-enumeration), got %v", err)
	}
}
