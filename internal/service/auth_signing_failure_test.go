package service

import (
	"context"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// ---------------------------------------------------------------------------
// Token issuance with an unusable signing key.
// Key rotation can leave a pod with a nil private key (UpdateSigningKey is the
// rotation entry point), and every flow that mints a JWT has an error return
// for exactly that. Each must fail closed: no tokens, no challenge, an error.
// ---------------------------------------------------------------------------

func TestAuthFlows_UnusableSigningKeyFailsClosed(t *testing.T) {
	hash := validPasswordHash(t)
	login := func(svc *AuthService) error {
		_, err := svc.Login(context.Background(), LoginInput{
			Email: "sign@example.com", Password: "correct-horse-battery-staple",
		}, "1.2.3.4", "TestAgent")
		return err
	}

	tests := []struct {
		name string
		wire func(o *mockAuthOpts)
		call func(svc *AuthService) error
		want string
	}{
		{
			name: "login TOTP challenge",
			wire: func(o *mockAuthOpts) { o.mfaSvc = mfaWithTOTP(false) },
			call: login,
			want: "issue 2FA challenge",
		},
		{
			name: "login email-OTP fallback challenge",
			wire: func(o *mockAuthOpts) { o.mfaSvc = mfaNoMethods(true) },
			call: login,
			want: "issue 2FA challenge",
		},
		{
			name: "login token pair",
			wire: func(_ *mockAuthOpts) {},
			call: login,
			want: "nil private key",
		},
		{
			name: "refresh rotation token pair",
			wire: func(o *mockAuthOpts) {
				o.tokenRepo.GetByTokenHashFn = func(context.Context, string) (*model.RefreshToken, error) {
					return &model.RefreshToken{
						ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
						ExpiresAt: time.Now().Add(time.Hour),
					}, nil
				}
			},
			call: func(svc *AuthService) error {
				_, err := svc.Refresh(context.Background(), "tok", "1.2.3.4", "TestAgent",
					vaultcrypto.FingerprintInput{})
				return err
			},
			want: "nil private key",
		},
		{
			name: "MFA completion token pair",
			wire: func(_ *mockAuthOpts) {},
			call: func(svc *AuthService) error {
				_, err := svc.CompleteMFALogin(context.Background(), "user-1", "fp", "1.2.3.4", "TestAgent", "", MFACompletion{Method: MethodTOTP})
				return err
			},
			want: "nil private key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
					return &model.User{
						ID: "user-1", Email: "sign@example.com",
						PasswordHash: hash, EmailVerified: true,
					}, nil
				}
			}, tc.wire)
			svc.tokenSvc.UpdateSigningKey(nil, "rotated-away")

			err := tc.call(svc)
			if err == nil {
				t.Fatal("token issuance succeeded without a signing key")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TokenService surfaces the SignToken failure itself, independent of the auth
// flow wrapping above.
func TestTokenService_IssueTokenPairNilSigningKey(t *testing.T) {
	svc, _ := newTestTokenService(t)
	svc.UpdateSigningKey(nil, testKID2)

	_, err := svc.IssueTokenPair(context.Background(), "user-1", []string{"user"}, []string{"read"}, "", "", "", false)
	if err == nil {
		t.Fatal("expected a signing error with a nil private key")
	}
	if !strings.Contains(err.Error(), "nil private key") {
		t.Errorf("err = %v, want a nil private key signing failure", err)
	}
}
