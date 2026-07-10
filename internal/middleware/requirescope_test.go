package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

func TestRequireScope(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mw := RequireScope("kms:unwrap")(next)

	withScopes := func(scopes []string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/kms/unwrap", nil)
		claims := &vaultcrypto.VaultClaims{RegisteredClaims: vjwt.RegisteredClaims{Subject: "c"}, Scopes: scopes}
		return req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))
	}

	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"no_claims", httptest.NewRequest(http.MethodPost, "/kms/unwrap", nil), http.StatusUnauthorized},
		{"missing_scope", withScopes([]string{"user:read"}), http.StatusForbidden},
		{"has_scope", withScopes([]string{"user:read", "kms:unwrap"}), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, tc.req)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, rec.Code)
			}
		})
	}
}
