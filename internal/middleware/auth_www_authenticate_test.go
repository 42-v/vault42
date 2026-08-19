package middleware

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// RFC 6750 §3: a resource server that rejects a request because the bearer
// credential was absent, unusable, or insufficient MUST answer with a
// WWW-Authenticate header naming the "Bearer" scheme. §3.1 fixes which error
// code goes with which rejection, and those codes are the only machine-readable
// signal a client has for telling "refresh the token" apart from "ask for more
// scope". vault42 emitted none of it: the string WWW-Authenticate did not
// appear anywhere in the tree.

func TestBearerChallenge_AuthMiddleware(t *testing.T) {
	key := newTestKey(t)
	kid := "challenge-kid"
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	protected := Auth(keys, "test-issuer", "test-audience")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	expired := signTestToken(t, key, kid, "test-issuer", "test-audience", "sub", -time.Hour)
	challenge := signChallengeTypeToken(t, key, kid, "test-issuer", "test-audience")

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		// wantError is the RFC 6750 §3.1 code, or "" when the header must carry
		// no error code at all (§3: a request that presents no bearer credential
		// gets a bare challenge, because naming an error would describe a
		// credential the client never sent).
		wantError string
	}{
		{"no credential", "", http.StatusUnauthorized, ""},
		{"unsupported scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized, ""},
		{"malformed header", "Bearer", http.StatusUnauthorized, ""},
		{"unverifiable token", "Bearer not-a-jwt", http.StatusUnauthorized, "invalid_token"},
		{"expired token", "Bearer " + expired, http.StatusUnauthorized, "invalid_token"},
		{"wrong token type", "Bearer " + challenge, http.StatusUnauthorized, "invalid_token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			assertChallenge(t, rec, tt.wantError, "")
		})
	}
}

func TestBearerChallenge_InsufficientScope(t *testing.T) {
	handler := RequireScope("kms:unwrap")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("token without the scope", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kms/unwrap", nil)
		req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, &vaultcrypto.VaultClaims{Scopes: []string{"read"}}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		// §3: the scope attribute carries the scope required to access the
		// resource, so a client can request exactly it rather than guess.
		assertChallenge(t, rec, "insufficient_scope", "kms:unwrap")
	})

	t.Run("no claims at all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kms/unwrap", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		assertChallenge(t, rec, "", "")
	})
}

// assertChallenge checks the WWW-Authenticate header shape: the Bearer scheme,
// a realm, the expected §3.1 error code (or none), and the required scope when
// one applies.
func assertChallenge(t *testing.T, rec *httptest.ResponseRecorder, wantError, wantScope string) {
	t.Helper()
	got := rec.Header().Get("WWW-Authenticate")
	if got == "" {
		t.Fatalf("no WWW-Authenticate header on a %d from a bearer-protected resource (RFC 6750 §3)", rec.Code)
	}
	if !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want the Bearer scheme (RFC 6750 §3)", got)
	}
	if !strings.Contains(got, `realm="`+httputil.BearerRealm+`"`) {
		t.Errorf("WWW-Authenticate = %q, want realm=%q", got, httputil.BearerRealm)
	}
	if wantError == "" {
		if strings.Contains(got, "error=") {
			t.Errorf("WWW-Authenticate = %q carries an error code for a request that presented no credential (RFC 6750 §3)", got)
		}
		return
	}
	if !strings.Contains(got, `error="`+wantError+`"`) {
		t.Errorf("WWW-Authenticate = %q, want error=%q (RFC 6750 §3.1)", got, wantError)
	}
	if !strings.Contains(got, `error_description="`) {
		t.Errorf("WWW-Authenticate = %q carries no error_description", got)
	}
	if wantScope != "" && !strings.Contains(got, `scope="`+wantScope+`"`) {
		t.Errorf("WWW-Authenticate = %q, want scope=%q", got, wantScope)
	}
}

func signChallengeTypeToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  vjwt.ClaimStrings{audience},
			Subject:   "sub",
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: vjwt.NewNumericDate(time.Now()),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
			ID:        "challenge-jti",
		},
		TokenType: "2fa_challenge",
	}
	tokenStr, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("sign challenge token: %v", err)
	}
	return tokenStr
}
