package server

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
)

const dpopRouteKID = "aabbccdd-11223344"

// dpopRoutesMux builds the wired mux plus a signing key, so a test can present a
// token the routes will actually accept.
func dpopRoutesMux(t *testing.T, dpopEnabled bool) (http.Handler, *rsa.PrivateKey) {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       dpopEnabled,
	}
	s := New(&Deps{
		Config:    cfg,
		Cache:     memCache,
		Keys:      map[string]*rsa.PublicKey{dpopRouteKID: &key.PublicKey},
		ReadyDeps: &handler.ReadyzDeps{},
	})
	// Recovery, because these routes run on nil repositories: a token that passes
	// authentication reaches a handler that dereferences one, and the 500 that
	// produces is the signal that it got through. A rejected token never reaches a
	// handler at all.
	return middleware.Recovery(s.setupRoutes()), key
}

// signRouteToken mints an access token for the wired mux, optionally bound to a
// DPoP key thumbprint.
func signRouteToken(t *testing.T, key *rsa.PrivateKey, jkt string) string {
	t.Helper()
	now := time.Now()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "https://vault.localhost",
			Audience:  vjwt.ClaimStrings{"https://vault.localhost"},
			Subject:   "user-1",
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "jti-1",
		},
		TokenType: "Bearer",
	}
	if jkt != "" {
		claims.Confirmation = &vaultcrypto.Confirmation{JKT: jkt}
	}
	token, err := vaultcrypto.SignToken(claims, key, dpopRouteKID)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// The middleware could only ever enforce a binding on a route it was mounted on,
// and it was mounted on five: the two token endpoints, the 2FA verify wrapper,
// POST /kms/unwrap and POST /mint. Every other authenticated route — the whole of
// /user — took a bound token as an ordinary bearer token, so a stolen token was
// simply replayed there instead and the constraint bought nothing.
func TestABoundTokenIsRefusedOnAnOrdinaryAuthenticatedRouteWithoutAProof(t *testing.T) {
	mux, key := dpopRoutesMux(t, true)
	token := signRouteToken(t, key, "some-bound-thumbprint")

	for _, target := range []string{"/user/profile", "/user/sessions", "/user/devices"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("Authorization", "DPoP "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s with a bound token and no proof = %d, want 401; the route accepts a "+
					"sender-constrained token as a bearer token", target, rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "dpop_proof_required") {
				t.Errorf("body = %q, want dpop_proof_required", body)
			}
		})
	}
}

// The confirm-gated destructive routes are built by hand rather than through the
// authed wrapper, so they are the ones most likely to be missed.
func TestABoundTokenIsRefusedOnTheConfirmGatedRoutesWithoutAProof(t *testing.T) {
	mux, key := dpopRoutesMux(t, true)
	token := signRouteToken(t, key, "some-bound-thumbprint")

	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/auth/confirm"},
		{http.MethodPost, "/user/password"},
		{http.MethodDelete, "/user/social/abc"},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("{}"))
			req.Header.Set("Authorization", "DPoP "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s with a bound token and no proof = %d, want 401", tc.method, tc.target, rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "dpop_proof_required") {
				t.Errorf("body = %q, want dpop_proof_required", body)
			}
		})
	}
}

// WithDPoPScheme had zero production callers, so the scheme was rejected
// unconditionally and CHANGELOG's "rejected unless the flag is set" was false in
// both positions. With issuance now binding cnf.jkt, a rejected scheme would also
// make a bound token unusable.
func TestTheDPoPSchemeIsAcceptedOnlyWhileTheFlagIsSet(t *testing.T) {
	t.Run("rejected with the flag off", func(t *testing.T) {
		mux, key := dpopRoutesMux(t, false)
		req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		req.Header.Set("Authorization", "DPoP "+signRouteToken(t, key, ""))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for the DPoP scheme with the flag off", rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "invalid_authorization") {
			t.Errorf("body = %q, want invalid_authorization", body)
		}
	})

	t.Run("accepted with the flag on", func(t *testing.T) {
		mux, key := dpopRoutesMux(t, true)
		req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		req.Header.Set("Authorization", "DPoP "+signRouteToken(t, key, ""))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// The handler runs on nil repositories and panics into the recovery
		// middleware's 500, which is proof the token passed authentication —
		// a rejected scheme never reaches a handler at all.
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("the DPoP scheme was rejected with the flag on: %s", rec.Body.String())
		}
	})
}

// An unbound token keeps working under Bearer with the flag on, which is what
// makes enabling DPoP a non-breaking change for every existing client.
func TestAnUnboundTokenStillWorksUnderBearerWithDPoPEnabled(t *testing.T) {
	mux, key := dpopRoutesMux(t, true)
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+signRouteToken(t, key, ""))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("an ordinary bearer token was refused with DPoP enabled: %s", rec.Body.String())
	}
}
