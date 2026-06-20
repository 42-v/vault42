package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// liveUserRepo returns a user repo whose GetByID resolves to a live, non-banned
// user — refresh now enforces account state, so refresh tests need a real user.
func liveUserRepo() *mocks.MockUserRepo {
	return &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Roles: []string{"user"}}, nil
		},
	}
}

// ---------------------------------------------------------------------------
// Refresh: missing cookie (already tested in handler_test.go, but subtested here)
// ---------------------------------------------------------------------------

func TestRefresh_Subtests_MissingCookie(t *testing.T) {
	t.Run("empty_cookie_value", func(t *testing.T) {
		h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: ""})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		// Empty token value will be hashed and looked up, returning nil -> ErrTokenInvalid
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "invalid_token" {
			t.Fatalf("expected error=invalid_token, got %q", result["error"])
		}
	})

	t.Run("wrong_cookie_name", func(t *testing.T) {
		h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "some-value"})
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "missing_refresh_token" {
			t.Fatalf("expected error=missing_refresh_token, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: fingerprint mismatch (token bound to different fingerprint)
// ---------------------------------------------------------------------------

func TestRefresh_FingerprintMismatch(t *testing.T) {
	t.Run("different_fingerprint_revokes_family", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		// Bind the token to a specific fingerprint
		originalFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "10.0.0.1",
			UserAgent: "OriginalBrowser/1.0",
		})

		familyRevoked := false
		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-fp-bound",
					UserID:          "user-123",
					FamilyID:        "family-fp",
					FingerprintHash: originalFP,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
			RevokeFamilyFn: func(ctx context.Context, familyID string) error {
				familyRevoked = true
				return nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "fp-bound-token"})
		// Different IP and user-agent than original
		req.RemoteAddr = "192.168.1.100:9999"
		req.Header.Set("User-Agent", "DifferentBrowser/2.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "invalid_token" {
			t.Fatalf("expected error=invalid_token, got %q", result["error"])
		}

		if !familyRevoked {
			t.Fatal("expected RevokeFamily to have been called on fingerprint mismatch")
		}

		// Verify cookie was cleared
		found := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected refresh_token cookie to be cleared on fingerprint mismatch")
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: MarkUsed fails (concurrent race)
// ---------------------------------------------------------------------------

func TestRefresh_MarkUsedFails(t *testing.T) {
	t.Run("mark_used_returns_false_concurrent_replay", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		familyRevoked := false
		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-concurrent",
					UserID:          "user-123",
					FamilyID:        "family-concurrent",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return false, nil // CAS failure: someone else consumed it
			},
			RevokeFamilyFn: func(ctx context.Context, familyID string) error {
				familyRevoked = true
				return nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "concurrent-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "replay_detected" {
			t.Fatalf("expected error=replay_detected, got %q", result["error"])
		}

		if !familyRevoked {
			t.Fatal("expected RevokeFamily to have been called on concurrent replay")
		}
	})

	t.Run("mark_used_returns_error", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-err",
					UserID:          "user-123",
					FamilyID:        "family-err",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return false, errors.New("db error during CAS")
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "cas-error-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "internal_error" {
			t.Fatalf("expected error=internal_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: GetByTokenHash returns error
// ---------------------------------------------------------------------------

func TestRefresh_GetByTokenHashError(t *testing.T) {
	t.Run("db_error_on_token_lookup", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return nil, errors.New("db connection lost")
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "db-error-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "internal_error" {
			t.Fatalf("expected error=internal_error, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: successful rotation verifies all response fields
// ---------------------------------------------------------------------------

func TestRefresh_SuccessfulRotation_FullResponseValidation(t *testing.T) {
	t.Run("verifies_access_token_expires_in_cookie", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-full",
					UserID:          "user-full",
					FamilyID:        "family-full",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "full-validation-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]interface{}
		decodeResponse(t, rec, &result)

		// Verify access_token is present and non-empty
		accessToken, ok := result["access_token"].(string)
		if !ok || accessToken == "" {
			t.Fatal("expected non-empty access_token in response")
		}

		// Verify token_type
		if result["token_type"] != "Bearer" {
			t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
		}

		// Verify expires_in is positive
		expiresIn, ok := result["expires_in"].(float64)
		if !ok || expiresIn <= 0 {
			t.Fatalf("expected positive expires_in, got %v", result["expires_in"])
		}

		// Verify refresh cookie is set with positive MaxAge
		found := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge > 0 {
				found = true
				if cookie.Path != "/" {
					t.Fatalf("expected cookie path=/, got %q", cookie.Path)
				}
				if !cookie.HttpOnly {
					t.Fatal("expected HttpOnly=true on refresh cookie")
				}
				if cookie.SameSite != http.SameSiteStrictMode {
					t.Fatalf("expected SameSite=Strict, got %d", cookie.SameSite)
				}
				break
			}
		}
		if !found {
			t.Fatal("expected new refresh_token cookie with positive MaxAge")
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: token with no fingerprint hash (empty) should still work
// ---------------------------------------------------------------------------

func TestRefresh_EmptyFingerprintHash(t *testing.T) {
	t.Run("token_without_fingerprint_binding", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-nofp",
					UserID:          "user-nofp",
					FamilyID:        "family-nofp",
					FingerprintHash: "", // no fingerprint binding
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "no-fp-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "AnyAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: replay detection clears cookie
// ---------------------------------------------------------------------------

func TestRefresh_ReplayDetectedClearsCookie(t *testing.T) {
	t.Run("replay_clears_refresh_cookie", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:       "rt-replay",
					UserID:   "user-123",
					FamilyID: "family-replay",
					Used:     true, // already used
				}, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "replay-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		// Verify cookie is cleared
		foundCleared := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
				foundCleared = true
				break
			}
		}
		if !foundCleared {
			t.Fatal("expected refresh_token cookie to be cleared on replay")
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: expired token clears cookie
// ---------------------------------------------------------------------------

func TestRefresh_ExpiredTokenClearsCookie(t *testing.T) {
	t.Run("expired_clears_refresh_cookie", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:        "rt-expired",
					UserID:    "user-123",
					FamilyID:  "family-exp",
					ExpiresAt: time.Now().Add(-10 * time.Minute), // expired
				}, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "expired-cookie-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "token_expired" {
			t.Fatalf("expected error=token_expired, got %q", result["error"])
		}

		foundCleared := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
				foundCleared = true
				break
			}
		}
		if !foundCleared {
			t.Fatal("expected refresh_token cookie to be cleared on expiration")
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: revoked token returns invalid_token and clears cookie
// ---------------------------------------------------------------------------

func TestRefresh_RevokedTokenClearsCookie(t *testing.T) {
	t.Run("revoked_clears_refresh_cookie", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:       "rt-revoked",
					UserID:   "user-123",
					FamilyID: "family-rev",
					Revoked:  true,
				}, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "revoked-cookie-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "invalid_token" {
			t.Fatalf("expected error=invalid_token, got %q", result["error"])
		}

		// Verify cookie is cleared
		foundCleared := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
				foundCleared = true
				break
			}
		}
		if !foundCleared {
			t.Fatal("expected refresh_token cookie to be cleared on revoked token")
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: successful rotation with secure cookies enabled
// ---------------------------------------------------------------------------

func TestRefresh_SuccessSecureCookies(t *testing.T) {
	t.Run("secure_cookies_flag_set_on_refresh", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-secure",
					UserID:          "user-secure",
					FamilyID:        "family-secure",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		// Enable secure cookies
		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", true)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "secure-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}

		// Verify the new refresh cookie has Secure=true
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge > 0 {
				if !cookie.Secure {
					t.Fatal("expected Secure=true on refresh cookie when secureCookies is enabled")
				}
				return
			}
		}
		t.Fatal("expected new refresh_token cookie to be set")
	})
}

// ---------------------------------------------------------------------------
// Refresh: with Accept-Language header in fingerprint
// ---------------------------------------------------------------------------

func TestRefresh_WithAcceptLanguageHeader(t *testing.T) {
	t.Run("accept_language_in_fingerprint_computation", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:             "127.0.0.1",
			UserAgent:      "TestAgent/1.0",
			AcceptLanguage: "en-US,en;q=0.9",
		})

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-lang",
					UserID:          "user-lang",
					FamilyID:        "family-lang",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "lang-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: new token store failure after successful rotation
// ---------------------------------------------------------------------------

func TestRefresh_NewTokenStoreFailure(t *testing.T) {
	t.Run("create_new_refresh_token_fails", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		createCallCount := 0
		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-store-fail",
					UserID:          "user-store",
					FamilyID:        "family-store",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
			CreateFn: func(ctx context.Context, token *model.RefreshToken) error {
				createCallCount++
				return errors.New("db write failed")
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "store-fail-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
		}

		if createCallCount == 0 {
			t.Fatal("expected Create to have been called")
		}
	})
}

// ---------------------------------------------------------------------------
// Auth handler: Login with missing fingerprint headers
// ---------------------------------------------------------------------------

func TestLogin_MissingFingerprintHeaders(t *testing.T) {
	t.Run("no_user_agent_or_accept_language", func(t *testing.T) {
		password := "validpassword123"
		hash, _ := vaultcrypto.HashPassword(password)

		users := &mocks.MockUserRepo{
			GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
				return &model.User{
					ID:            "user-nofp",
					Email:         email,
					PasswordHash:  hash,
					EmailVerified: true,
				}, nil
			},
		}

		h, _ := newTestAuthHandler(t, users)

		body := jsonBody(t, map[string]string{
			"email":    "user@example.com",
			"password": password,
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.RemoteAddr = "127.0.0.1:9999"
		// No User-Agent or Accept-Language headers
		rec := httptest.NewRecorder()

		h.Login(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Auth handler: VerifyEmail cache GetAndDelete error
// ---------------------------------------------------------------------------

func TestVerifyEmail_CacheGetAndDeleteError(t *testing.T) {
	t.Run("cache_returns_error", func(t *testing.T) {
		users := &mocks.MockUserRepo{}

		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{
			GetAndDeleteFn: func(ctx context.Context, key string) (string, error) {
				return "", errors.New("cache connection failed")
			},
		}

		mockTokens := &mocks.MockRefreshTokenRepo{}
		mockDevices := &mocks.MockDeviceRepo{}
		mockPwHistory := &mocks.MockPasswordHistoryRepo{}

		authSvc := service.NewAuthService(
			users, mockTokens, mockDevices, mockPwHistory,
			tokenSvc, nil, auditLog, nil, mockCache, nil,
			"https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token=some-token", nil)
		rec := httptest.NewRecorder()

		h.VerifyEmail(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "invalid_or_expired_token" {
			t.Fatalf("expected error=invalid_or_expired_token, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// Auth handler: Register invalid JSON (large body)
// ---------------------------------------------------------------------------

func TestRegister_LargeBody(t *testing.T) {
	t.Run("very_large_password_still_checked", func(t *testing.T) {
		h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{
			GetByEmailFn: func(ctx context.Context, email string) (*model.User, error) {
				return nil, nil
			},
			CreateFn: func(ctx context.Context, user *model.User) error {
				return nil
			},
		})

		largePassword := strings.Repeat("a", 1000)
		body := jsonBody(t, map[string]string{
			"email":    "bigpass@example.com",
			"password": largePassword,
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
		rec := httptest.NewRecorder()

		h.Register(rec, req)

		// Password is > 15 chars so should succeed
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Auth handler: Logout with refresh cookie present (still clears it)
// ---------------------------------------------------------------------------

func TestLogout_ClearsRefreshCookieEvenWithCookiePresent(t *testing.T) {
	t.Run("logout_clears_cookie_even_when_present", func(t *testing.T) {
		users := &mocks.MockUserRepo{}
		h, _ := newTestAuthHandler(t, users)

		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req = setAuthContext(req, "user-123")
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "should-be-cleared"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Logout(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}

		found := false
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "__Host-refresh_token" && cookie.MaxAge == -1 {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected refresh_token cookie to be cleared on logout")
		}
	})
}

// ---------------------------------------------------------------------------
// MFA handler: Status service error
// ---------------------------------------------------------------------------

func TestMFAStatus_ServiceError(t *testing.T) {
	t.Run("mfa_service_returns_error", func(t *testing.T) {
		mockTOTP := &mocks.MockTOTPRepo{
			GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
				return nil, errors.New("db error")
			},
		}
		mockWebAuthn := &mocks.MockWebAuthnRepo{
			ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
				return nil, errors.New("db error")
			},
		}
		mockBackup := &mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
				return nil, errors.New("db error")
			},
		}

		mfaSvc := service.NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
		h := NewMFAHandler(mfaSvc)

		req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		h.Status(rec, req)

		// MFA service accumulates errors; it might still return a partial result
		// or the handler returns 500 if the service errors
		// Based on service code: errors are logged but it returns what it can
		if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 200 or 500, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Readyz: cache down
// ---------------------------------------------------------------------------

func TestReadyzCacheDown(t *testing.T) {
	t.Run("cache_down_returns_200_degraded", func(t *testing.T) {
		deps := &ReadyzDeps{
			PingDB:    func() error { return nil },
			PingCache: func() error { return errors.New("cache connection refused") },
		}
		handler := Readyz(deps)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)

		// Cache being down is degraded, not a full failure -- still returns 200
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var body map[string]string
		decodeResponse(t, rec, &body)
		if body["cache"] != "degraded" {
			t.Fatalf("expected cache=degraded, got %q", body["cache"])
		}
		if body["database"] != "up" {
			t.Fatalf("expected database=up, got %q", body["database"])
		}
	})
}

// ---------------------------------------------------------------------------
// Readyz: both down
// ---------------------------------------------------------------------------

func TestReadyzBothDown(t *testing.T) {
	t.Run("db_and_cache_both_down", func(t *testing.T) {
		deps := &ReadyzDeps{
			PingDB:    func() error { return errors.New("db down") },
			PingCache: func() error { return errors.New("cache down") },
		}
		handler := Readyz(deps)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)

		// DB down returns 503 immediately (cache check is never reached)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}

		var body map[string]string
		decodeResponse(t, rec, &body)
		if body["database"] != "down" {
			t.Fatalf("expected database=down, got %q", body["database"])
		}
		if body["status"] != "not_ready" {
			t.Fatalf("expected status=not_ready, got %q", body["status"])
		}
	})
}

// ---------------------------------------------------------------------------
// Response helpers: writeJSON with nil data
// ---------------------------------------------------------------------------

func TestWriteJSON_NilData(t *testing.T) {
	t.Run("nil_data_produces_null_json", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusOK, nil)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		body := strings.TrimSpace(rec.Body.String())
		if body != "null" {
			t.Fatalf("expected null, got %q", body)
		}
	})
}

// ---------------------------------------------------------------------------
// Response helpers: writeError status codes
// ---------------------------------------------------------------------------

func TestWriteError_VariousStatusCodes(t *testing.T) {
	codes := []struct {
		name   string
		code   int
		errMsg string
	}{
		{"bad_request", http.StatusBadRequest, "bad_request"},
		{"unauthorized", http.StatusUnauthorized, "unauthorized"},
		{"forbidden", http.StatusForbidden, "forbidden"},
		{"not_found", http.StatusNotFound, "not_found"},
		{"conflict", http.StatusConflict, "conflict"},
		{"internal_error", http.StatusInternalServerError, "internal_error"},
		{"not_implemented", http.StatusNotImplemented, "not_implemented"},
		{"service_unavailable", http.StatusServiceUnavailable, "service_unavailable"},
	}

	for _, tc := range codes {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteError(rec, tc.code, tc.errMsg)

			if rec.Code != tc.code {
				t.Fatalf("expected %d, got %d", tc.code, rec.Code)
			}

			var result map[string]string
			decodeResponse(t, rec, &result)
			if result["error"] != tc.errMsg {
				t.Fatalf("expected error=%s, got %q", tc.errMsg, result["error"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// decodeJSON: empty body
// ---------------------------------------------------------------------------

func TestDecodeJSON_EmptyBody(t *testing.T) {
	t.Run("empty_body_returns_error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))

		var dst struct {
			Email string `json:"email"`
		}
		err := decodeJSON(req, &dst)
		if err == nil {
			t.Fatal("expected error from empty body, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// clientIP helper
// ---------------------------------------------------------------------------

func TestClientIP_FromRemoteAddr(t *testing.T) {
	t.Run("extracts_ip_from_remote_addr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		ip := middleware.ClientIP(req)
		if ip == "" {
			t.Fatal("expected non-empty IP")
		}
	})
}

// ---------------------------------------------------------------------------
// getClaims helper
// ---------------------------------------------------------------------------

func TestGetClaims_NilContext(t *testing.T) {
	t.Run("no_claims_in_context_returns_nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		claims := middleware.GetClaims(req.Context())
		if claims != nil {
			t.Fatal("expected nil claims for unauthenticated request")
		}
	})

	t.Run("claims_present_in_context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = setAuthContext(req, "user-123")
		claims := middleware.GetClaims(req.Context())
		if claims == nil {
			t.Fatal("expected non-nil claims")
		}
		if claims.Subject != "user-123" {
			t.Fatalf("expected subject=user-123, got %q", claims.Subject)
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: token with clientID preserved through rotation
// ---------------------------------------------------------------------------

func TestRefresh_PreservesClientIDAndFamilyID(t *testing.T) {
	t.Run("rotation_preserves_family_and_client", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
			IP:        "127.0.0.1",
			UserAgent: "TestAgent/1.0",
		})

		var createdToken *model.RefreshToken
		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:              "rt-client",
					UserID:          "user-client",
					ClientID:        "my-client-app",
					FamilyID:        "family-persist",
					DeviceID:        "device-42",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(24 * time.Hour),
				}, nil
			},
			MarkUsedFn: func(ctx context.Context, id string) (bool, error) {
				return true, nil
			},
			CreateFn: func(ctx context.Context, token *model.RefreshToken) error {
				createdToken = token
				return nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "client-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
		}

		if createdToken == nil {
			t.Fatal("expected new refresh token to be created")
		}
		if createdToken.FamilyID != "family-persist" {
			t.Fatalf("expected familyID=family-persist, got %q", createdToken.FamilyID)
		}
		if createdToken.ClientID != "my-client-app" {
			t.Fatalf("expected clientID=my-client-app, got %q", createdToken.ClientID)
		}
		if createdToken.DeviceID != "device-42" {
			t.Fatalf("expected deviceID=device-42, got %q", createdToken.DeviceID)
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: just-expired token (boundary case)
// ---------------------------------------------------------------------------

func TestRefresh_JustExpiredToken(t *testing.T) {
	t.Run("token_expired_one_second_ago", func(t *testing.T) {
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		mockCache := &mocks.MockCache{}

		mockTokens := &mocks.MockRefreshTokenRepo{
			GetByTokenHashFn: func(ctx context.Context, hash string) (*model.RefreshToken, error) {
				return &model.RefreshToken{
					ID:        "rt-boundary",
					UserID:    "user-123",
					FamilyID:  "family-boundary",
					ExpiresAt: time.Now().Add(-1 * time.Second), // just expired
				}, nil
			},
		}

		authSvc := service.NewAuthService(
			liveUserRepo(), mockTokens, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, nil, "https://vault.test", "TestVault", "", 15, false, nil,
		)

		h := NewAuthHandler(authSvc, &mocks.MockUserRepo{}, mockCache, auditLog, "", false)

		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: "boundary-token"})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}

		var result map[string]string
		decodeResponse(t, rec, &result)
		if result["error"] != "token_expired" {
			t.Fatalf("expected error=token_expired, got %q", result["error"])
		}
	})
}

// ---------------------------------------------------------------------------
// Refresh: long token value (doesn't crash)
// ---------------------------------------------------------------------------

func TestRefresh_LongTokenValue(t *testing.T) {
	t.Run("very_long_token_value", func(t *testing.T) {
		h, _ := newTestAuthHandler(t, &mocks.MockUserRepo{})

		longToken := strings.Repeat("a", 10000)
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: longToken})
		req.RemoteAddr = "127.0.0.1:9999"
		rec := httptest.NewRecorder()

		h.Refresh(rec, req)

		// Should be invalid_token since the hash won't match anything
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
		}
	})
}
