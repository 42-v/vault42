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
	"github.com/42-v/vault42/tests/mocks"
)

// 2nd-pass review: the OAuth callback must enforce the same account-state gates
// as password login + refresh — OAuth must not be a bypass for a banned/disabled/
// deleted account — and must claim (not silently ignore) an import_pending account.
func TestOAuth_Callback_AccountStateGate(t *testing.T) {
	hmacSecret := []byte("test-hmac-secret-32-bytes-long!!")
	nonce := "acct-nonce"
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	state := signedOAuthState("google", nonce, expiry, hmacSecret)

	run := func(t *testing.T, u *model.User) *httptest.ResponseRecorder {
		social := &mocks.MockSocialAccountRepo{
			GetByProviderAndIDFn: func(context.Context, string, string) (*model.SocialAccount, error) {
				return &model.SocialAccount{UserID: u.ID}, nil
			},
		}
		cleared := false
		users := &mocks.MockUserRepo{
			GetByIDFn:            func(_ context.Context, id string) (*model.User, error) { return u, nil },
			ClearImportPendingFn: func(context.Context, string) error { cleared = true; return nil },
		}
		cache := &mocks.MockCache{GetAndDeleteFn: func(context.Context, string) (string, error) { return "verifier", nil }}
		h := newTestOAuthHandler(t, map[string]oauth2.Provider{"google": &mockProvider{name: "google"}},
			withCache(cache), withSocial(social), withUsers(users))
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback/google?state="+state+"&code=c", nil)
		req.SetPathValue("provider", "google")
		req.AddCookie(testOAuthCookie())
		rec := httptest.NewRecorder()
		h.Callback(rec, req)
		if u.ImportPending && rec.Code != http.StatusForbidden && !cleared {
			t.Errorf("import_pending account should be claimed (ClearImportPending) on OAuth login")
		}
		return rec
	}

	t.Run("banned -> 403", func(t *testing.T) {
		if rec := run(t, &model.User{ID: "u1", EmailVerified: true, Banned: true}); rec.Code != http.StatusForbidden {
			t.Fatalf("banned must be 403, got %d", rec.Code)
		}
	})
	t.Run("disabled -> 403", func(t *testing.T) {
		if rec := run(t, &model.User{ID: "u2", EmailVerified: true, Disabled: true}); rec.Code != http.StatusForbidden {
			t.Fatalf("disabled must be 403, got %d", rec.Code)
		}
	})
	t.Run("deleted -> 403", func(t *testing.T) {
		if rec := run(t, &model.User{ID: "u3", EmailVerified: true, Deleted: true}); rec.Code != http.StatusForbidden {
			t.Fatalf("deleted must be 403, got %d", rec.Code)
		}
	})
	t.Run("import_pending claimed, not blocked", func(t *testing.T) {
		rec := run(t, &model.User{ID: "u4", EmailVerified: true, ImportPending: true})
		if rec.Code == http.StatusForbidden {
			t.Fatalf("import_pending should be claimed + proceed, got 403: %s", rec.Body.String())
		}
	})
}
