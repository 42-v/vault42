package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The login account-state gate. A deleted account is masked as a non-existent one
// (ErrInvalidCredentials) before the password is verified, so it never leaks. A
// banned or disabled account is an administrative denial revealed only after a
// successful password verification, so with the correct password each returns its
// distinct error; a wrong password or an unknown address stays masked (see
// TestLoginBannedDisabledDoesNotLeakExistence).
func TestLogin_AccountStateGate(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	hash := validPasswordHash(t)

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
			o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
				u := &model.User{
					ID: "u1", Email: "x@y.test", EmailVerified: true,
					PasswordHash: hash,
				}
				tt.mutate(u)
				return u, nil
			}

			_, err := svc.Login(context.Background(), LoginInput{Email: "x@y.test", Password: pw}, "1.2.3.4", "UA")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got err %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// A banned or disabled account must be indistinguishable from an unknown address
// to a caller who does NOT hold the password: the administrative denial is
// revealed only after a successful password verification, so a wrong password
// against a banned or disabled address answers ErrInvalidCredentials, exactly like
// a wrong password against an unknown one. Only a proven-password caller reaches
// the distinct 403, and a caller with the password already knows the account
// exists. Red-first across the existence boundary.
func TestLoginBannedDisabledDoesNotLeakExistence(t *testing.T) {
	hash := validPasswordHash(t)
	const wrongPW = "not-the-password"

	assertMasked := func(t *testing.T, mutate func(*model.User)) {
		t.Helper()
		svc, o := newMockAuthService(t)
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			u := &model.User{ID: "u1", Email: "x@y.test", EmailVerified: true, PasswordHash: hash}
			mutate(u)
			return u, nil
		}
		_, err := svc.Login(context.Background(), LoginInput{Email: "x@y.test", Password: wrongPW}, "1.2.3.4", "UA")
		if !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountBanned) || errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("got %v, want ErrInvalidCredentials (a banned/disabled account must not be distinguishable without the password)", err)
		}
	}

	t.Run("banned + wrong password is masked", func(t *testing.T) {
		assertMasked(t, func(u *model.User) { u.Banned = true })
	})
	t.Run("disabled + wrong password is masked", func(t *testing.T) {
		assertMasked(t, func(u *model.User) { u.Disabled = true })
	})
	t.Run("unknown email is the baseline", func(t *testing.T) {
		svc, o := newMockAuthService(t)
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) { return nil, nil }
		_, err := svc.Login(context.Background(), LoginInput{Email: "nobody@y.test", Password: wrongPW}, "1.2.3.5", "UA")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("unknown email got %v, want ErrInvalidCredentials", err)
		}
	})
}
