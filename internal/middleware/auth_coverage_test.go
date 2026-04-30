package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

func TestAuth_BearerPrefixVariations(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0011-2233"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"lowercase bearer", "bearer some-token", http.StatusUnauthorized},
		{"BEARER uppercase", "BEARER some-token", http.StatusUnauthorized},
		{"no space after Bearer", "Bearersome-token", http.StatusUnauthorized},
		{"double space", "Bearer  some-token", http.StatusUnauthorized},
		{"only Bearer no token", "Bearer", http.StatusUnauthorized},
		{"empty string", "", http.StatusUnauthorized},
		{"whitespace only", " ", http.StatusUnauthorized},
		{"tab separated", "Bearer\ttoken", http.StatusUnauthorized},
		{"Basic scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
		{"Digest scheme", "Digest realm=test", http.StatusUnauthorized},
		{"Token scheme", "Token abc123", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestAuth_DPoPSchemeAccepted(t *testing.T) {
	key := newTestKey(t)
	kid := "aa00bb11-cc22"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, key, kid, "test-issuer", "test-audience", "user-dpop", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "DPoP "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("DPoP scheme is accepted", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestAuth_WrongIssuer(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0033-5566"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "expected-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, key, kid, "wrong-issuer", "test-audience", "user-123", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects wrong issuer", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuth_WrongAudience(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0044-7788"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "expected-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, key, kid, "test-issuer", "wrong-audience", "user-123", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects wrong audience", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuth_TokenSignedWithDifferentKey(t *testing.T) {
	signingKey := newTestKey(t)
	verifyKey := newTestKey(t) // Different key
	kid := "aabb0055-9900"
	keys := map[string]*rsa.PublicKey{kid: &verifyKey.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, signingKey, kid, "test-issuer", "test-audience", "user-123", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects token signed with different key", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuth_EmptyKeyMap(t *testing.T) {
	keys := map[string]*rsa.PublicKey{} // No keys at all

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	key := newTestKey(t)
	tokenStr := signTestToken(t, key, "aabb0066-1122", "test-issuer", "test-audience", "user-123", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects when no keys configured", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuth_NotYetValidToken(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0077-3344"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-future",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: vjwt.NewNumericDate(time.Now().Add(30 * time.Minute)), // Future
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "future-jti",
		},
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects not-yet-valid token", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuth_NonBearerTokenType(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0088-5566"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-2fa",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "2fa-jti",
		},
		TokenType: "2fa_challenge",
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects non-Bearer token type", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("error is invalid_token_type", func(t *testing.T) {
		body := rec.Body.String()
		if !strings.Contains(body, "invalid_token_type") {
			t.Errorf("body = %q, want invalid_token_type error", body)
		}
	})
}

func TestAuth_EmptyTokenTypeIsAllowed(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb0099-7788"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Token with empty TokenType should be allowed (backward compat)
	tokenStr := signTestToken(t, key, kid, "test-issuer", "test-audience", "user-normal", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("empty token type is accepted", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestAuth_BearerTokenTypeExplicit(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb00aa-bb11"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  vjwt.ClaimStrings{"test-audience"},
			Subject:   "user-explicit-bearer",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "bearer-jti",
		},
		TokenType: "Bearer",
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("explicit Bearer token type is accepted", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestAuth_ClaimsAvailableInContext(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb00cc-dd22"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	var extractedClaims *vaultcrypto.VaultClaims
	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedClaims = GetClaims(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr := signTestToken(t, key, kid, "test-issuer", "test-audience", "user-ctx-test", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; cannot test claims", rec.Code)
	}

	t.Run("claims are in context", func(t *testing.T) {
		if extractedClaims == nil {
			t.Fatal("claims should be set in context")
		}
	})

	t.Run("subject matches", func(t *testing.T) {
		if extractedClaims == nil {
			t.Skip("claims nil")
		}
		if extractedClaims.Subject != "user-ctx-test" {
			t.Errorf("subject = %q, want user-ctx-test", extractedClaims.Subject)
		}
	})

	t.Run("issuer matches", func(t *testing.T) {
		if extractedClaims == nil {
			t.Skip("claims nil")
		}
		if extractedClaims.Issuer != "test-issuer" {
			t.Errorf("issuer = %q, want test-issuer", extractedClaims.Issuer)
		}
	})

	t.Run("roles present", func(t *testing.T) {
		if extractedClaims == nil {
			t.Skip("claims nil")
		}
		if len(extractedClaims.Roles) == 0 {
			t.Error("roles should be present")
		}
	})
}

func TestGetClaims_WrongContextValueType(t *testing.T) {
	// Store a non-VaultClaims value under the ClaimsKey
	ctx := context.WithValue(context.Background(), ClaimsKey, "not-a-claims-object")
	claims := GetClaims(ctx)

	t.Run("returns nil for wrong type", func(t *testing.T) {
		if claims != nil {
			t.Errorf("expected nil claims for wrong type assertion, got %v", claims)
		}
	})
}

func TestRequireAuth_MultipleCalls(t *testing.T) {
	callCount := 0
	handler := RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "user-multi"},
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		ctx := context.WithValue(req.Context(), ClaimsKey, claims)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	t.Run("handler called correct number of times", func(t *testing.T) {
		if callCount != 3 {
			t.Errorf("call count = %d, want 3", callCount)
		}
	})
}

func TestAuth_MalformedJWT(t *testing.T) {
	key := newTestKey(t)
	kid := "aabb00dd-ee33"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	malformed := []struct {
		name  string
		token string
	}{
		{"empty token", "Bearer "},
		{"single dot", "Bearer a.b"},
		{"no dots", "Bearer abcdef"},
		{"four dots", "Bearer a.b.c.d.e"},
		{"base64 garbage header", "Bearer !!!.!!!.!!!"},
	}

	for _, tt := range malformed {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", tt.token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 for malformed token", rec.Code)
			}
		})
	}
}

func TestAuth_MultipleKeys(t *testing.T) {
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	kid1 := "aabb00ee-ff44"
	kid2 := "aabb00ff-0055"
	keys := map[string]*rsa.PublicKey{
		kid1: &key1.PublicKey,
		kid2: &key2.PublicKey,
	}

	handler := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("key1 valid", func(t *testing.T) {
		tokenStr := signTestToken(t, key1, kid1, "test-issuer", "test-audience", "user-1", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("key2 valid", func(t *testing.T) {
		tokenStr := signTestToken(t, key2, kid2, "test-issuer", "test-audience", "user-2", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("unknown kid rejected", func(t *testing.T) {
		key3, _ := rsa.GenerateKey(rand.Reader, 2048)
		tokenStr := signTestToken(t, key3, "aabb1122-3344", "test-issuer", "test-audience", "user-3", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}
