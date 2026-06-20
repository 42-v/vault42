package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// WS1: the login flow must reject banned / disabled / deleted accounts before
// password verification. Deleted accounts must be indistinguishable from
// non-existent ones (ErrInvalidCredentials), banned/disabled get distinct errors.
func TestLogin_AccountStateGate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*model.User)
		wantErr error
	}{
		{"banned", func(u *model.User) { u.Banned = true }, ErrAccountBanned},
		{"disabled", func(u *model.User) { u.Disabled = true }, ErrAccountDisabled},
		{"deleted looks like no-such-user", func(u *model.User) { u.Deleted = true }, ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, o := newMockAuthService(t)
			var pwVerified bool
			o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
				u := &model.User{
					ID: "u1", Email: "x@y.test", EmailVerified: true,
					// A real Argon2 hash would be needed to pass verify; set a
					// sentinel and assert we never reach verification.
					PasswordHash: "should-not-be-checked",
				}
				tt.mutate(u)
				return u, nil
			}
			o.userRepo.IncrementFailedLoginFn = func(_ context.Context, _ string) error {
				pwVerified = true // only reached on a wrong-password path
				return nil
			}

			_, err := svc.Login(context.Background(), LoginInput{Email: "x@y.test", Password: "whatever"}, "1.2.3.4", "UA")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got err %v, want %v", err, tt.wantErr)
			}
			if pwVerified {
				t.Error("account-state gate must short-circuit before password verification")
			}
		})
	}
}
