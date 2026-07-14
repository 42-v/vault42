package service

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// A refresh token outlives the login that minted it, so account state can change
// underneath it: an account is disabled, or the row is gone entirely. Refresh is the
// only place that gets to notice — an access token is not revocable, so a session that
// keeps refreshing is a session that never ends.
//
// Banned was already covered. Disabled and "the user is no longer there" were not, and
// they are the two an operator actually reaches for: disabling an account is the
// routine response to a compromised or departing user, and a vanished row is what an
// erasure leaves behind. Either one must kill the whole token family, not just refuse
// this one rotation — otherwise a sibling token mints a fresh pair a second later.
func TestRefresh_RejectsAccountsThatChangedSinceLogin(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{IP: "1.2.3.4", UserAgent: "TestAgent"})

	cases := []struct {
		name string
		user *model.User
		want error
	}{
		{
			name: "disabled since login",
			user: &model.User{ID: "user-1", Disabled: true},
			want: ErrAccountDisabled,
		},
		{
			name: "the user row is gone",
			user: nil,
			want: ErrTokenInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			revokedFamily := ""
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.tokenRepo.GetByTokenHashFn = func(context.Context, string) (*model.RefreshToken, error) {
					return &model.RefreshToken{
						ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
						FingerprintHash: fp, ExpiresAt: time.Now().Add(time.Hour),
					}, nil
				}
				o.tokenRepo.MarkUsedFn = func(context.Context, string) (bool, error) { return true, nil }
				o.tokenRepo.RevokeFamilyFn = func(_ context.Context, fam string) error {
					revokedFamily = fam
					return nil
				}
				o.userRepo.GetByIDFn = func(context.Context, string) (*model.User, error) {
					return tc.user, nil
				}
			})

			_, err := svc.Refresh(context.Background(), "tok", "1.2.3.4", "TestAgent",
				vaultcrypto.FingerprintInput{})

			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v — the session was allowed to continue", err, tc.want)
			}
			if revokedFamily != "fam-1" {
				t.Error("the token family was not revoked — a sibling refresh token could mint a new pair immediately")
			}
		})
	}
}
