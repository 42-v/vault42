package attack

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

// setupAuthMiddleware creates an auth middleware with a valid key and a signed token for testing.
func setupAuthMiddleware(t *testing.T) (http.Handler, string) {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	handler := middleware.Auth(keys, "test", "test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	return handler, tokenStr
}

// TestJWT_AuthHeader covers the Authorization header parse in middleware.Auth:
// every mangling of the scheme or of the token around one valid credential.
//
// The "well formed" row is what makes the rest mean anything. Without it a
// middleware that refused everything, a broken key map for instance, would
// satisfy all eight refusals and the table would still be green.
func TestJWT_AuthHeader(t *testing.T) {
	handler, token := setupAuthMiddleware(t)

	cases := []struct {
		name   string
		header func(token string) string
		want   int
	}{
		{"well formed", func(tok string) string { return "Bearer " + tok }, http.StatusOK},
		{"lowercase scheme", func(tok string) string { return "bearer " + tok }, http.StatusUnauthorized},
		{"uppercase scheme", func(tok string) string { return "BEARER " + tok }, http.StatusUnauthorized},
		{"trailing space after token", func(tok string) string { return "Bearer " + tok + " " }, http.StatusUnauthorized},
		// SplitN(" Bearer token", " ", 2) yields [" Bearer", "token"], so the
		// scheme keeps the leading space and stops matching "Bearer".
		{"leading space before scheme", func(tok string) string { return " Bearer " + tok }, http.StatusUnauthorized},
		{"scheme with no token", func(string) string { return "Bearer" }, http.StatusUnauthorized},
		{"token with no scheme", func(tok string) string { return tok }, http.StatusUnauthorized},
		{"basic auth", func(string) string { return "Basic dXNlcjpwYXNz" }, http.StatusUnauthorized},
		{"empty header", func(string) string { return "" }, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.header(token)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", value)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("Authorization: %q got %d, want %d", value, rec.Code, tc.want)
			}
		})
	}
}
