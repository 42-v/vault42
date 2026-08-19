package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// runChallengeGate redeems a 2FA challenge for a user in the given account
// state. The challenge carries no fingerprint, so the device binding passes and
// the request reaches the state gate inside CompleteMFALogin rather than being
// refused a step earlier.
func runChallengeGate(t *testing.T, user *model.User) *httptest.ResponseRecorder {
	t.Helper()

	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return user, nil },
	}
	svc := challengeAuthService(t, users, &mocks.MockRefreshTokenRepo{})

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: user.ID, ID: "chal-state"},
		TokenType:        "2fa_challenge",
		Fingerprint:      "",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()

	if !completeMFAIfChallenge(rec, req, claims, svc, false, service.MFACompletion{Method: service.MethodTOTP}) {
		t.Fatal("the challenge was not handled at all")
	}
	return rec
}

// The challenge TTL is a window of minutes between the password step and the
// second factor, and it is exactly the window in which an operator reacting to a
// compromise bans, disables or locks the account. CompleteMFALogin re-reads the
// account for that reason, but this transport only mapped two of its refusals:
// every state gate answered 500, so finishing the second factor on a banned
// account looked to the client like a server fault it should retry, and to an
// operator like vault42 was broken at the moment they banned someone.
//
// The codes here are the same ones login, refresh and the OAuth callback answer
// with, which is the property that keeps a client's handling of "banned" from
// depending on which door the user came through.
func TestCompleteMFAIfChallenge_AccountStateMapsToTheRightStatus(t *testing.T) {
	lockedUntil := time.Now().Add(1 * time.Hour)

	cases := []struct {
		name     string
		user     *model.User
		wantCode int
		wantBody string
	}{
		{
			name:     "banned",
			user:     &model.User{ID: "u-banned", Email: "banned@example.com", EmailVerified: true, Banned: true},
			wantCode: http.StatusForbidden,
			wantBody: "account_banned",
		},
		{
			name:     "disabled",
			user:     &model.User{ID: "u-disabled", Email: "disabled@example.com", EmailVerified: true, Disabled: true},
			wantCode: http.StatusForbidden,
			wantBody: "account_disabled",
		},
		{
			name:     "locked",
			user:     &model.User{ID: "u-locked", Email: "locked@example.com", EmailVerified: true, LockedUntil: &lockedUntil},
			wantCode: http.StatusForbidden,
			wantBody: "account_locked",
		},
		{
			// A deleted account is answered as an invalid token rather than as
			// a named policy refusal, because naming it would confirm to an
			// unauthenticated holder of the challenge that the address once
			// existed here.
			name:     "deleted",
			user:     &model.User{ID: "u-deleted", Email: "deleted@example.com", EmailVerified: true, Deleted: true},
			wantCode: http.StatusUnauthorized,
			wantBody: "invalid_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runChallengeGate(t, tc.user)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			var body map[string]string
			decodeResponse(t, rec, &body)
			if body["error"] != tc.wantBody {
				t.Errorf("error = %q, want %q", body["error"], tc.wantBody)
			}
		})
	}
}

// The refusal has to withhold the session, not merely label it. A second factor
// that answers 403 and still hands back a token pair, or sets the refresh
// cookie, would leave the banned account logged in for the life of that family.
func TestCompleteMFAIfChallenge_RefusedAccountGetsNoSession(t *testing.T) {
	rec := runChallengeGate(t, &model.User{
		ID: "u-banned", Email: "banned@example.com", EmailVerified: true, Banned: true,
	})

	if body := rec.Body.String(); strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Fatalf("a refused MFA completion still returned tokens: %s", body)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh_token") {
			t.Fatalf("a refused MFA completion set a refresh cookie %q", c.Name)
		}
	}
}
