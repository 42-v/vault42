package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// refreshGateOutcome records everything the refresh transport did with one
// account state: the response, whether the browser was told to drop the cookie,
// and whether the rotation family was terminated rather than merely this one
// rotation being refused.
type refreshGateOutcome struct {
	rec           *httptest.ResponseRecorder
	familyRevoked bool
	cookieCleared bool
}

// runRefreshGate presents a valid, unused, unexpired refresh token whose user
// resolves to the given account state, so the request reaches the state gate in
// AuthService.Refresh and nothing earlier refuses it first.
func runRefreshGate(t *testing.T, user *model.User) refreshGateOutcome {
	t.Helper()

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}

	out := refreshGateOutcome{}
	tokens := &mocks.MockRefreshTokenRepo{
		GetByTokenHashFn: func(context.Context, string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID:        "rt-state",
				UserID:    user.ID,
				FamilyID:  "family-state",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
		MarkUsedFn:     func(context.Context, string) (bool, error) { return true, nil },
		RevokeFamilyFn: func(context.Context, string) error { out.familyRevoked = true; return nil },
	}
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return user, nil },
	}

	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)
	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "state-token"})
	req.RemoteAddr = "203.0.113.7:5000"
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	out.rec = rec
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-refresh_token" && c.MaxAge == -1 {
			out.cookieCleared = true
		}
	}
	return out
}

// Refresh re-reads account state, and the three refusals it can produce for a
// live session are what make an operator's ban, disable or lock take effect on a
// browser that already holds a valid refresh token.
//
// Until this release those three fell through to the switch default, so the gate
// worked and then reported itself as a 500. Two things broke with it: a bulk ban
// showed up on the dashboard as a server-error spike rather than as policy, and
// a client had no way to tell "you are banned" from "vault42 is down", so it
// retried. Login already answered 403 with the same codes
// (TestLogin_AccountStateMapsToTheRightStatus), and the OAuth callback does too
// (TestOAuth_Callback_AccountStateGate); this pins the third transport to that
// contract so the four cannot drift apart again.
func TestRefresh_AccountStateMapsToTheRightStatus(t *testing.T) {
	lockedUntil := time.Now().Add(1 * time.Hour)

	cases := []struct {
		name     string
		user     *model.User
		wantCode int
		wantBody string
	}{
		{
			name:     "banned",
			user:     &model.User{ID: "u-banned", Roles: []string{"user"}, Banned: true},
			wantCode: http.StatusForbidden,
			wantBody: "account_banned",
		},
		{
			name:     "disabled",
			user:     &model.User{ID: "u-disabled", Roles: []string{"user"}, Disabled: true},
			wantCode: http.StatusForbidden,
			wantBody: "account_disabled",
		},
		{
			name:     "locked",
			user:     &model.User{ID: "u-locked", Roles: []string{"user"}, LockedUntil: &lockedUntil},
			wantCode: http.StatusForbidden,
			wantBody: "account_locked",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runRefreshGate(t, tc.user)

			if out.rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", out.rec.Code, tc.wantCode, out.rec.Body.String())
			}
			var body map[string]string
			decodeResponse(t, out.rec, &body)
			if body["error"] != tc.wantBody {
				t.Errorf("error = %q, want %q: the caller cannot tell a refusal by policy from a broken server", body["error"], tc.wantBody)
			}
			// The refusal is worth nothing if the session survives it.
			if !out.familyRevoked {
				t.Error("the rotation family was not revoked, so the refused session can keep rotating")
			}
			if !out.cookieCleared {
				t.Error("the refresh cookie was left in place; the browser keeps presenting a token belonging to a refused account")
			}
		})
	}
}

// The gate must be a refusal, not a slower success. A body carrying tokens next
// to a 403 would still be usable by a client that reads the payload before the
// status, which is exactly the mistake a status-only test would let through.
func TestRefresh_RefusedAccountGetsNoTokens(t *testing.T) {
	out := runRefreshGate(t, &model.User{ID: "u-banned", Roles: []string{"user"}, Banned: true})

	if body := out.rec.Body.String(); strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Fatalf("a refused refresh still returned tokens: %s", body)
	}
	for _, c := range out.rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh_token") && c.MaxAge > 0 {
			t.Fatalf("a refused refresh set a live refresh cookie (MaxAge=%d)", c.MaxAge)
		}
	}
}
