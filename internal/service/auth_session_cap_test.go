package service

import (
	"context"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The session cap is a resource control, not an auth boundary, and it is
// enforced with a >= against the configured maximum. Existing tests pin the
// rejection at and above the cap; nothing pinned the other side of the
// comparison. An off-by-one there would lock every user out of their last
// allowed session, which reads as an authentication outage rather than a
// misconfigured limit.
func TestLoginSessionCapAllowsTheLastFreeSlot(t *testing.T) {
	hash := validPasswordHash(t)

	tests := []struct {
		name    string
		active  int
		wantErr error
	}{
		{name: "one family below the cap", active: 2, wantErr: nil},
		{name: "at the cap", active: 3, wantErr: ErrTooManySessions},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
					return &model.User{
						ID: "user-1", Email: "cap@example.com",
						PasswordHash: hash, EmailVerified: true,
					}, nil
				}
				o.tokenRepo.CountActiveFamiliesFn = func(context.Context, string) (int, error) {
					return tc.active, nil
				}
			})
			svc.SetMaxSessionsPerUser(3)

			res, err := svc.Login(context.Background(), LoginInput{
				Email: "cap@example.com", Password: "correct-horse-battery-staple",
			}, "1.2.3.4", "TestAgent")

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && (res == nil || res.AccessToken == "" || res.RefreshToken == "") {
				t.Fatal("a login below the session cap was not issued a full token pair")
			}
			if tc.wantErr != nil && res != nil {
				t.Error("tokens were issued for a login rejected by the session cap")
			}
		})
	}
}
