package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// A social login writes a refresh-token family, and that family has to be bound
// to a device row exactly the way a password login binds one. Without the bind
// the session is invisible to GET /user/sessions (which lists devices) and
// unreachable by DELETE /user/sessions/{id}, whose RevokeByDeviceID matches on
// device_id and never matches a NULL. The user is then left with "sign out
// everywhere" as the only way to kill a session they believe is compromised.
//
// This test drives the callback to completion and asserts the two facts that
// make per-session revocation work: a device row exists for the user, and the
// OAuth refresh row carries that device's id (with the same fingerprint), so
// RevokeByDeviceID(device.ID) reaches the family.
func TestOAuth_Callback_BindsRefreshFamilyToADevice(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, EmailVerified: true}, nil
		},
	}
	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
			return &model.SocialAccount{UserID: oauthCapUserID}, nil
		},
	}

	var createdDevice *model.Device
	devices := &mocks.MockDeviceRepo{
		CreateFn: func(_ context.Context, d *model.Device) error {
			createdDevice = d
			return nil
		},
	}

	var writtenToken *model.RefreshToken
	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(context.Context, string) (int, error) { return 0, nil },
		CreateFn: func(_ context.Context, tok *model.RefreshToken) error {
			writtenToken = tok
			return nil
		},
	}
	cache := &mocks.MockCache{
		GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil },
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		users, tokens, devices, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, auditLog, nil, cache, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	authSvc.SetMaxSessionsPerUser(3)

	h := NewOAuthHandler(
		map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
		[]byte("test-hmac-secret-32-bytes-long!!"), cache, "https://vault.test",
		users, social, tokens, authSvc, tokenSvc, nil, auditLog, false,
	)

	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", "device-bind-nonce", expiry, []byte("test-hmac-secret-32-bytes-long!!"))
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("User-Agent", "Mozilla/5.0 (device-bind-test)")
	req.SetPathValue("provider", "google")
	req.AddCookie(testOAuthCookie())
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if writtenToken == nil {
		t.Fatal("no refresh-token family was written for an accepted social login")
	}
	if createdDevice == nil {
		t.Fatal("no device row was created for the social login; the session is invisible to GET /user/sessions")
	}
	if createdDevice.UserID != oauthCapUserID {
		t.Fatalf("device bound to %q, want %q", createdDevice.UserID, oauthCapUserID)
	}
	if writtenToken.DeviceID == "" {
		t.Fatal("OAuth refresh row has an empty DeviceID; RevokeByDeviceID can never revoke this session")
	}
	if writtenToken.DeviceID != createdDevice.ID {
		t.Fatalf("refresh row DeviceID %q does not match device row id %q; DELETE /user/sessions/{id} would miss it",
			writtenToken.DeviceID, createdDevice.ID)
	}
	if writtenToken.FingerprintHash != createdDevice.FingerprintHash {
		t.Fatalf("refresh fingerprint %q does not match device fingerprint %q; GetByFingerprint would not line up",
			writtenToken.FingerprintHash, createdDevice.FingerprintHash)
	}
}
