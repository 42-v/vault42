package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/tests/mocks"
)

// TestOAuth_Callback_SocialLookupError_FailsClosed pins that a repository error
// on the (provider, provider_user_id) identity lookup fails closed instead of
// being coerced to "no such identity".
//
// GetByProviderAndID returns (nil, nil) on a clean miss and (nil, err) on a real
// DB fault, so discarding the error makes the two indistinguishable: a linked
// identity that momentarily cannot be read is treated as a first-time login and
// the callback runs the create-or-link-by-email path. When the asserted address
// is free that path writes a fresh user row whose (provider, provider_user_id)
// is already claimed, so the later social.Create fails and the row is orphaned,
// squatting the address. The lookup must fail closed instead.
func TestOAuth_Callback_SocialLookupError_FailsClosed(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "social-lookup-err-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, _ string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(_ context.Context, _, _ string) (*model.SocialAccount, error) {
			return nil, errors.New("db read timeout")
		},
	}

	createCalled := false
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			return nil, nil
		},
		CreateFn: func(_ context.Context, _ *model.User) error {
			createCalled = true
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("social identity lookup returned a DB error; callback must fail closed with 500, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if createCalled {
		t.Fatal("callback created a user after the social identity lookup errored: a transient read error was coerced to \"identity absent\" and orphaned a row")
	}
}

// TestOAuth_Callback_EmailLookupError_FailsClosed pins that a repository error on
// the GetByEmail lookup fails closed instead of proceeding to create.
//
// With no existing (provider, provider_user_id) row, the callback resolves the
// account by address. GetByEmail returns (nil, nil) on a clean miss and
// (nil, err) on a DB fault; discarding the error sends a fault down the create
// branch, writing a user row for an address whose real owner the failed read
// never got to reveal. The lookup must fail closed instead.
func TestOAuth_Callback_EmailLookupError_FailsClosed(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	provider := &mockProvider{name: "google"}
	providers := map[string]oauth2.Provider{"google": provider}

	nonce := "email-lookup-err-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	mockCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, _ string) (string, error) {
			return "test-verifier", nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		GetByProviderAndIDFn: func(_ context.Context, _, _ string) (*model.SocialAccount, error) {
			return nil, nil
		},
	}

	createCalled := false
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			return nil, errors.New("db read timeout")
		},
		CreateFn: func(_ context.Context, _ *model.User) error {
			createCalled = true
			return nil
		},
	}

	h := newTestOAuthHandler(t, providers, withCache(mockCache), withSocial(social), withUsers(users))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=test-code", nil)
	req.AddCookie(testOAuthCookie())
	req.SetPathValue("provider", "google")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("email lookup returned a DB error; callback must fail closed with 500, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if createCalled {
		t.Fatal("callback created a user after the email lookup errored: a transient read error was coerced to \"address free\" and orphaned a row")
	}
}
