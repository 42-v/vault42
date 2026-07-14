package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The login handler maps each refusal to a distinct status and code. That mapping is the
// entire contract a client has for telling these cases apart, and every one of them means
// something different to the person on the other end: banned is permanent, disabled is an
// operator action, locked is temporary, too-many-sessions means close a tab.
//
// If any of them collapsed into a generic 500 or, worse, into each other, a banned user
// would be told to try again later — and an operator watching the logs would see a server
// error where there was none. These cases were never exercised, so nothing stopped that
// mapping from drifting.
func TestLogin_AccountStateMapsToTheRightStatus(t *testing.T) {
	hash, err := vaultcrypto.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	cases := []struct {
		name     string
		mutate   func(*model.User)
		wantCode int
		wantBody string
	}{
		{
			name:     "banned",
			mutate:   func(u *model.User) { u.Banned = true },
			wantCode: http.StatusForbidden,
			wantBody: "account_banned",
		},
		{
			name:     "disabled",
			mutate:   func(u *model.User) { u.Disabled = true },
			wantCode: http.StatusForbidden,
			wantBody: "account_disabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &mocks.MockUserRepo{
				GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
					u := &model.User{ID: "user-1", Email: email, PasswordHash: hash, EmailVerified: true}
					tc.mutate(u)
					return u, nil
				},
			}

			tokenSvc, _ := newTestTokenService(t)
			auditLog := newTestAuditLogger()
			authSvc := service.NewAuthService(
				users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
				&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
				nil, &mocks.MockCache{}, nil, "https://vault.test", "TestVault", "", 15, false, nil,
			)
			h := NewAuthHandler(authSvc, users, &mocks.MockCache{}, auditLog, "", false)

			req := httptest.NewRequest(http.MethodPost, "/auth/login",
				jsonBody(t, map[string]string{
					"email":    "user@example.com",
					"password": "correct-horse-battery-staple",
				}))
			req.RemoteAddr = "203.0.113.1:5000"
			rec := httptest.NewRecorder()

			h.Login(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, tc.wantBody) {
				t.Errorf("body = %s, want %s", body, tc.wantBody)
			}
			if strings.Contains(rec.Body.String(), "access_token") {
				t.Error("a refused login still issued tokens")
			}
		})
	}
}

// An imported account's first login issues no session at all: a claim link is emailed and
// the response is a 202 carrying only the flag. If tokens leaked into this response, an
// account whose password we never imported — and whose owner has not proven anything —
// would be handed a live session.
func TestLogin_ImportPendingIssuesNoTokens(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{
				ID: "user-import", Email: email, EmailVerified: true,
				PasswordHash: "!imported", ImportPending: true,
			}, nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	mockCache := &mocks.MockCache{}
	authSvc := service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, mockCache, &mocks.MockEmailSender{}, "https://vault.test", "TestVault", "", 15, false, nil,
	)
	h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		jsonBody(t, map[string]string{"email": "imported@example.com", "password": "anything"}))
	req.RemoteAddr = "203.0.113.1:5000"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "import_claim_required") {
		t.Errorf("body = %s, want import_claim_required", body)
	}
	if strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Error("an imported account was handed a session before it was ever claimed")
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh_token") {
			t.Error("a refresh cookie was set for an unclaimed imported account")
		}
	}
}
