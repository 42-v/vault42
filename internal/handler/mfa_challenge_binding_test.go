package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func challengeAuthService(t *testing.T, users *mocks.MockUserRepo, tokens *mocks.MockRefreshTokenRepo) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, newTestAuditLogger(),
		nil, &mocks.MockCache{}, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// A 2FA challenge token is bound to the device and network it was minted for. That binding
// is what stops a challenge token, stolen mid-flow, from being redeemed somewhere else:
// without it, an attacker who lifts the challenge out of a victim's browser could finish
// the second factor from their own machine and walk away with a full session — having
// never touched the victim's authenticator.
//
// The check must refuse, and it must refuse with an ordinary 401 rather than completing
// the login.
func TestCompleteMFAIfChallenge_ChallengeFromAnotherDeviceIsRefused(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", EmailVerified: true}, nil
		},
	}
	svc := challengeAuthService(t, users, &mocks.MockRefreshTokenRepo{})

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "user-1", ID: "chal-1"},
		TokenType:        "2fa_challenge",
		// A fingerprint from a machine that is not the one making this request.
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	req.Header.Set("User-Agent", "SomeOtherBrowser/1.0")
	rec := httptest.NewRecorder()

	handled := completeMFAIfChallenge(rec, req, claims, svc, false, service.MFACompletion{Method: service.MethodTOTP})

	if !handled {
		t.Fatal("the challenge was not handled at all")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a challenge minted elsewhere was redeemed from this device", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a full session was issued for a challenge bound to a different device")
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh_token") {
			t.Error("a refresh cookie was set for a challenge bound to a different device")
		}
	}
}

// When the binding matches but completing the login fails, the caller must get a 500 —
// not a 200 with a half-built session, and not a silent fall-through to the enclosing
// handler's own success response.
func TestCompleteMFAIfChallenge_CompletionFailureIsA500(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com", EmailVerified: true}, nil
		},
	}
	// The refresh token cannot be stored: the session it would hand back is one the
	// server has no record of, so completion must fail rather than issue it.
	tokens := &mocks.MockRefreshTokenRepo{
		CreateFn: func(context.Context, *model.RefreshToken) error {
			return errors.New("db down")
		},
	}
	svc := challengeAuthService(t, users, tokens)

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "user-1", ID: "chal-1"},
		TokenType:        "2fa_challenge",
		// Empty fingerprint: the binding check passes, so we reach the completion.
		Fingerprint: "",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", nil)
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()

	handled := completeMFAIfChallenge(rec, req, claims, svc, false, service.MFACompletion{Method: service.MethodTOTP})

	if !handled {
		t.Fatal("the challenge was not handled")
	}
	if rec.Code == http.StatusOK {
		t.Fatal("MFA completion reported success while the refresh token was never stored")
	}
}
