package honeypot_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

const entropyTrapEmail = "planted-admin@trap.example"

// trapLoginService builds the login path in the shape the honeypot profile runs
// it: trap users configured and an empty user table, which is what a honeypot
// database looks like.
func trapLoginService(t *testing.T) *service.AuthService {
	t.Helper()

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tokenSvc := service.NewTokenService(
		key, vaultcrypto.KIDFromPublicKey(&key.PublicKey), "https://vault.test", "https://vault.test",
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour,
	)
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)

	svc := service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog, service.NewHIBPClient(),
		&mocks.MockCache{}, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)
	svc.SetHoneypotAlerter(honeypot.NewAlerter("", []string{entropyTrapEmail}, auditLog))
	return svc
}

// A trap login that ran out of entropy must answer with an error and no session
// at all.
//
// The alternative is worse than a failed login: a body with an empty
// access_token, or a token whose subject was derived from a zero salt and is
// therefore the same value on every honeypot anyone ever deploys from this
// source. vault42 is public source, so a constant that falls out of a failed
// CSPRNG read is a signature an attacker can recognize without ever having seen
// this deployment before.
func TestATrapLoginStarvedOfEntropyIssuesNothing(t *testing.T) {
	tests := []struct {
		name string
		// saltDrawn decides whether the mint's first read is the identity salt
		// or the token id, which is what selects the branch under test.
		saltDrawn bool
		reads     int
		want      string
	}{
		{"the user id the trap answers with", false, 0, "honeypot: trap subject"},
		{"the access token", true, 0, "honeypot: fake JWT"},
		{"the refresh token", true, 1, "honeypot: fake refresh"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := honeypot.PrimeTrapIdentity(); err != nil {
				t.Fatalf("priming the trap identity with real entropy: %v", err)
			}
			if !tc.saltDrawn {
				honeypot.ResetTrapIdentitySalt()
			}
			restore := honeypot.StarveEntropyAfter(tc.reads)
			t.Cleanup(restore)

			res, err := trapLoginService(t).Login(context.Background(), service.LoginInput{
				Email: entropyTrapEmail, Password: "whatever",
			}, "203.0.113.9", "curl/8.6.0")
			if err == nil {
				t.Fatalf("the trap handed back a session built from entropy that was never produced: %+v", res)
			}
			if res != nil {
				t.Errorf("a login result was returned alongside the error: %+v", res)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %s", err, tc.want)
			}
		})
	}
}
