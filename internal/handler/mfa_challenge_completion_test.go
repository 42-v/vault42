package handler

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// acctChallengeRequest attaches an unbound 2FA challenge token to req, the state a
// client is in between a correct password and a correct second factor.
func acctChallengeRequest(req *http.Request, subject, jti string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject, ID: jti},
		TokenType:        "2fa_challenge",
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

func acctMFAAuthService(t *testing.T, users *mocks.MockUserRepo, c *mocks.MockCache, mfaSvc *service.MFAService, hmacSecret []byte) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, mfaSvc, newTestAuditLogger(),
		nil, c, nil, "https://vault.test", "TestVault", "", 15, false, hmacSecret,
	)
}

// The second-factor verify endpoints serve two callers with the same token type on
// the same route: someone enrolling a factor on an already-authenticated session,
// and someone finishing a login that is still only half done. The challenge case
// has to end in a real session and stop there.
//
// If the handler kept going after completing the challenge it would append its own
// enrolment response to a body that already contains the token pair. On the wire
// that is two JSON documents concatenated: clients parse the first and ignore the
// rest, so the bug is invisible from the browser and visible only as a session that
// nobody can account for. Both endpoints are pinned the same way — the login result
// is the whole response.
func TestMFAVerify_ChallengeCompletionIsTheWholeResponse(t *testing.T) {
	t.Run("totp", func(t *testing.T) {
		masterKey := make([]byte, 32)
		secret, err := vaultcrypto.GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("generate TOTP secret: %v", err)
		}
		encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte("user-1"))
		if err != nil {
			t.Fatalf("encrypt TOTP secret: %v", err)
		}
		code, err := vaultcrypto.GenerateTOTPCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate TOTP code: %v", err)
		}

		totpRepo := &mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{
					ID: "totp-1", UserID: userID,
					SecretEnc: hex.EncodeToString(encrypted), Verified: true,
				}, nil
			},
		}
		users := &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "user@example.com", EmailVerified: true}, nil
			},
		}
		c := &mocks.MockCache{}
		svc := acctMFAAuthService(t, users, c, nil, nil)
		h := NewTOTPHandler(totpRepo, masterKey, "VaultTest", c, svc, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify",
			jsonBody(t, map[string]string{"code": code}))
		req.RemoteAddr = "203.0.113.7:5000"
		req = acctChallengeRequest(req, "user-1", "chal-totp")
		rec := httptest.NewRecorder()

		h.Verify(rec, req)

		acctAssertChallengeCompleted(t, rec)
	})

	t.Run("email_otp", func(t *testing.T) {
		const code = "418420"
		hmacSecret := []byte("test-email-otp-hmac-secret")
		signature := vaultcrypto.HMACSign([]byte(code), hmacSecret)

		mfaSvc := service.NewMFAService(
			&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, true,
		)
		users := &mocks.MockUserRepo{
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Email: "user@example.com", EmailVerified: true}, nil
			},
		}
		c := &mocks.MockCache{
			GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
				if key == "email_otp:user-1" {
					return signature, nil
				}
				return "", cache.ErrNotFound
			},
		}
		svc := acctMFAAuthService(t, users, c, mfaSvc, hmacSecret)
		h := NewEmailOTPHandler(svc, users, false)

		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/email-otp/verify",
			jsonBody(t, map[string]string{"code": code}))
		req.RemoteAddr = "203.0.113.7:5000"
		req = acctChallengeRequest(req, "user-1", "chal-email")
		rec := httptest.NewRecorder()

		h.Verify(rec, req)

		acctAssertChallengeCompleted(t, rec)
	})
}

func acctAssertChallengeCompleted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "access_token") {
		t.Fatalf("the challenge was not completed into a session: %s", body)
	}
	if strings.Contains(body, "\"verified\"") {
		t.Errorf("the enrolment response was appended to the login result: %s", body)
	}

	refreshed := false
	for _, ck := range rec.Result().Cookies() {
		if strings.Contains(ck.Name, "refresh_token") {
			refreshed = true
		}
	}
	if !refreshed {
		t.Error("no refresh cookie was set for a completed 2FA login")
	}
}
