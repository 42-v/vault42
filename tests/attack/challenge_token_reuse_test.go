package attack

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

// makeChallengeToken creates a 2FA challenge JWT for testing.
func makeChallengeToken(t *testing.T, key *rsa.PrivateKey, kid, sub, issuer, audience, tokenType string, exp time.Time) string {
	t.Helper()
	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    issuer,
			Audience:  vjwt.ClaimStrings{audience},
			ExpiresAt: vjwt.NewNumericDate(exp),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		TokenType: tokenType,
	}, key)
	if err != nil {
		t.Fatalf("makeChallengeToken failed: %v", err)
	}
	return tokenStr
}

// TestChallengeToken_BearerEndpointRejectsChallengeType verifies that a
// 2fa_challenge token is rejected by endpoints that only accept Bearer tokens.
func TestChallengeToken_BearerEndpointRejectsChallengeType(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	// Create a 2fa_challenge token
	tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "vault", "2fa_challenge",
		time.Now().Add(5*time.Minute))

	// Wrap a simple handler with Auth middleware (Bearer-only)
	handler := middleware.Auth(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Bearer-only endpoint should reject 2fa_challenge token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestChallengeToken_ChallengeEndpointAcceptsChallengeType verifies that
// AuthChallenge middleware accepts 2fa_challenge tokens.
func TestChallengeToken_ChallengeEndpointAcceptsChallengeType(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "vault", "2fa_challenge",
		time.Now().Add(5*time.Minute))

	// Wrap with AuthChallenge middleware (accepts both Bearer and 2fa_challenge)
	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetClaims(r.Context())
		if claims == nil {
			t.Fatal("Expected claims in context")
		}
		if claims.TokenType != "2fa_challenge" {
			t.Fatalf("Expected token_type=2fa_challenge, got %q", claims.TokenType)
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("AuthChallenge endpoint should accept 2fa_challenge token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestChallengeToken_WrongAudience verifies that a challenge token with wrong
// audience is rejected.
func TestChallengeToken_WrongAudience(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	// Token with wrong audience
	tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "wrong-audience", "2fa_challenge",
		time.Now().Add(5*time.Minute))

	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Challenge token with wrong audience should be rejected, got %d", rec.Code)
	}
}

// TestChallengeToken_WrongIssuer verifies that a challenge token with wrong
// issuer is rejected.
func TestChallengeToken_WrongIssuer(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	tokenStr := makeChallengeToken(t, key, kid, "user-123", "wrong-issuer", "vault", "2fa_challenge",
		time.Now().Add(5*time.Minute))

	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Challenge token with wrong issuer should be rejected, got %d", rec.Code)
	}
}

// TestChallengeToken_Expired verifies that an expired challenge token is rejected.
func TestChallengeToken_Expired(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	// Token that expired 1 minute ago
	tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "vault", "2fa_challenge",
		time.Now().Add(-1*time.Minute))

	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expired challenge token should be rejected, got %d", rec.Code)
	}
}

// TestChallengeToken_UnknownTokenType verifies that tokens with arbitrary
// token_type values are rejected by both Auth and AuthChallenge middleware.
func TestChallengeToken_UnknownTokenType(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	unknownTypes := []string{"refresh", "api_key", "admin", "service", "2fa_complete"}

	for _, tt := range unknownTypes {
		t.Run("Bearer_"+tt, func(t *testing.T) {
			tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "vault", tt,
				time.Now().Add(5*time.Minute))

			handler := middleware.Auth(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			}))

			req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("Bearer-only endpoint should reject token_type=%q, got %d", tt, rec.Code)
			}
		})

		t.Run("Challenge_"+tt, func(t *testing.T) {
			tokenStr := makeChallengeToken(t, key, kid, "user-123", "vault", "vault", tt,
				time.Now().Add(5*time.Minute))

			handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			}))

			req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("AuthChallenge endpoint should reject token_type=%q, got %d", tt, rec.Code)
			}
		})
	}
}

// TestChallengeToken_BearerTokenOnChallengeEndpoint verifies that a normal
// Bearer token is also accepted by AuthChallenge endpoints (for already-
// authenticated users managing their MFA).
func TestChallengeToken_BearerTokenOnChallengeEndpoint(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	// Normal Bearer token (empty token_type = Bearer by default)
	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"vault"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetClaims(r.Context())
		if claims == nil {
			t.Fatal("Expected claims in context")
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("AuthChallenge endpoint should accept Bearer tokens, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestChallengeToken_WrongSigningKey verifies that a challenge token signed
// with an unknown key is rejected.
func TestChallengeToken_WrongSigningKey(t *testing.T) {
	realKey, _ := vaultcrypto.GenerateRSAKeyPair()
	attackerKey, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	// Only the real key is in the key map
	keys := map[string]*rsa.PublicKey{kid: &realKey.PublicKey}

	// Token signed with attacker's key but using the real kid
	tokenStr := makeChallengeToken(t, attackerKey, kid, "user-123", "vault", "vault", "2fa_challenge",
		time.Now().Add(5*time.Minute))

	handler := middleware.AuthChallenge(keys, "vault", "vault")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/totp/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Token signed with wrong key should be rejected, got %d", rec.Code)
	}
}
