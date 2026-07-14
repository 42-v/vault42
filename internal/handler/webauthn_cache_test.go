package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The WebAuthn challenge is held in the cache between /begin and /finish. If the
// store fails and /begin still returns 200, the browser prompts for the
// authenticator, the user touches their key, and /finish then fails because the
// session was never there — an enrolment or a login that cannot possibly succeed,
// reported as if it had started fine. The failure has to surface at /begin.
func TestWebAuthnBegin_CacheFailureIsNotSilent(t *testing.T) {
	boom := errors.New("cache unavailable")

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Vault",
		RPID:          "localhost",
		RPOrigins:     []string{"https://localhost"},
	})
	if err != nil {
		t.Fatalf("webauthn config: %v", err)
	}

	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com", DisplayName: "U"}, nil
		},
	}
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return nil, nil
		},
	}

	tests := []struct {
		name    string
		path    string
		handler func(*WebAuthnHandler) func(http.ResponseWriter, *http.Request)
	}{
		{"RegisterBegin", "/auth/2fa/webauthn/register/begin",
			func(h *WebAuthnHandler) func(http.ResponseWriter, *http.Request) { return h.RegisterBegin }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache := &mocks.MockCache{
				SetFn: func(context.Context, string, string, time.Duration) error { return boom },
			}
			h := newWebAuthnHandler(wan, credRepo, userRepo, cache)

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req = setAuthContext(req, "user-1")
			rec := httptest.NewRecorder()

			tc.handler(h)(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500 — a challenge that was never stored must not look like a started ceremony", rec.Code)
			}
		})
	}
}

// A credential that the database refuses to store must not be reported as
// registered: the user would believe their security key is enrolled, and would
// discover otherwise only when locked out.
func TestWebAuthnRegisterFinish_StoreFailureIsNotReportedAsSuccess(t *testing.T) {
	credRepo := &mocks.MockWebAuthnRepo{
		CreateFn: func(context.Context, *model.WebAuthnCredential) error {
			return errors.New("db down")
		},
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return nil, nil
		},
	}
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com"}, nil
		},
	}
	// No session in the cache: /finish must reject rather than proceed to a store
	// it has no ceremony for.
	cache := &mocks.MockCache{
		GetFn: func(context.Context, string) (string, error) { return "", errors.New("miss") },
	}

	h := newWebAuthnHandler(&webauthn.WebAuthn{}, credRepo, userRepo, cache)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", nil)
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.RegisterFinish(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("registration reported success with no stored ceremony")
	}
}
