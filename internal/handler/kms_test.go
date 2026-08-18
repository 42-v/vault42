package handler

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// newTestKMS builds a kms.Service over a deterministic 32-byte test root.
func newTestKMS(t *testing.T, seed byte) *kms.Service {
	t.Helper()
	root := make([]byte, 32)
	for i := range root {
		root[i] = seed + byte(i)
	}
	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	return svc
}

// withKMSClaims injects client-credential claims onto the request context,
// bypassing the Auth middleware (used for handler-direct tests).
func withKMSClaims(req *http.Request, scopes []string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "life42-gateway"},
		ClientID:         "life42-gateway",
		Scopes:           scopes,
		TokenType:        "Bearer",
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

func kmsPost(t *testing.T, kid, ciphertextB64 string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/kms/unwrap",
		jsonBody(t, KMSUnwrapRequest{Kid: kid, Ciphertext: ciphertextB64}))
	req.RemoteAddr = "127.0.0.1:9999"
	return req
}

func TestKMSUnwrap_RoundTrip(t *testing.T) {
	svc := newTestKMS(t, 0x11)
	h := NewKMSHandler(svc, newTestAuditLogger())

	root := []byte("this-is-a-32-byte-life42-datroot")
	env, err := svc.Wrap("life42-root-kek", root)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	req := withKMSClaims(kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString(env)), []string{"kms:unwrap"})
	rec := httptest.NewRecorder()
	h.Unwrap(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body %s", rec.Code, rec.Body.String())
	}
	var resp KMSUnwrapResponse
	decodeResponse(t, rec, &resp)
	got, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(got) != string(root) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, root)
	}
}

// TestKMSUnwrap_UniformFailure asserts malformed, tampered, and wrong-KEK
// requests all produce a byte-identical 400 response — the oracle-resistance
// invariant. Any divergence in status or body would leak which check failed.
func TestKMSUnwrap_UniformFailure(t *testing.T) {
	svc := newTestKMS(t, 0x22)
	wrongSvc := newTestKMS(t, 0x99) // different root => different KEK
	h := NewKMSHandler(svc, newTestAuditLogger())

	goodEnv, err := svc.Wrap("life42-root-kek", []byte("another-32-byte-root-for-testing"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	tampered := append([]byte(nil), goodEnv...)
	tampered[len(tampered)-1] ^= 0x01

	wrongKEKEnv, err := wrongSvc.Wrap("life42-root-kek", []byte("root-wrapped-under-the-wrong-kek!"))
	if err != nil {
		t.Fatalf("wrap wrong: %v", err)
	}

	cases := map[string]*http.Request{
		"not_base64": kmsPost(t, "life42-root-kek", "!!!not base64!!!"),
		"too_short":  kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString([]byte{0x00, 0x01})),
		"tampered":   kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString(tampered)),
		"wrong_kid":  kmsPost(t, "unknown-kid", base64.StdEncoding.EncodeToString(goodEnv)),
		"wrong_kek":  kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString(wrongKEKEnv)),
		"empty_kid":  kmsPost(t, "", base64.StdEncoding.EncodeToString(goodEnv)),
		"bad_json":   httptest.NewRequest(http.MethodPost, "/kms/unwrap", jsonBody(t, map[string]int{"kid": 1})),
	}

	var wantCode int
	var wantBody string
	first := true
	for name, req := range cases {
		rec := httptest.NewRecorder()
		h.Unwrap(rec, withKMSClaims(req, []string{"kms:unwrap"}))
		if first {
			wantCode, wantBody, first = rec.Code, rec.Body.String(), false
			if wantCode != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d", name, wantCode)
			}
		}
		if rec.Code != wantCode || rec.Body.String() != wantBody {
			t.Errorf("%s: non-uniform failure: code=%d body=%q (want code=%d body=%q)",
				name, rec.Code, rec.Body.String(), wantCode, wantBody)
		}
	}
}

// TestKMSUnwrap_DPoPRequiredWhenEnabled asserts the anti-replay wiring the router
// applies when VAULT_DPOP_ENABLED: the unwrap handler is wrapped in dpopWrap
// (inside authMw + RequireScope). For a DPoP-bound kms token (cnf.jkt present), a
// request without a fresh DPoP proof is rejected — so a captured Bearer token +
// body cannot be replayed within the access-token TTL to re-release the plaintext.
// With the flag off, dpopWrap is a no-op and the plain-Bearer path still serves.
func TestKMSUnwrap_DPoPRequiredWhenEnabled(t *testing.T) {
	svc := newTestKMS(t, 0x55)
	h := NewKMSHandler(svc, newTestAuditLogger())

	env, err := svc.Wrap("life42-root-kek", []byte("dpop-test-32-byte-datroot-abcdef"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	body := base64.StdEncoding.EncodeToString(env)

	// Claims a DPoP-bound life42-gateway token would carry: unwrap scope + cnf.jkt.
	boundClaims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "life42-gateway"},
		ClientID:         "life42-gateway",
		Scopes:           []string{"kms:unwrap"},
		TokenType:        "Bearer",
		Confirmation:     &vaultcrypto.Confirmation{JKT: "bound-thumbprint"},
	}
	withBound := func(req *http.Request) *http.Request {
		return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, boundClaims))
	}

	const origin = "https://vault.test"

	t.Run("enabled: bound token without DPoP proof rejected", func(t *testing.T) {
		// Mirrors the mounted chain when the flag is on: RequireScope -> DPoP -> handler.
		chain := middleware.RequireScope("kms:unwrap")(
			middleware.DPoP(nil, origin)(http.HandlerFunc(h.Unwrap)))
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, withBound(kmsPost(t, "life42-root-kek", body)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bound token without DPoP proof must be rejected, got %d body %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "dpop_proof_required") {
			t.Fatalf("expected dpop_proof_required, got body %s", rec.Body.String())
		}
	})

	t.Run("disabled: plain-Bearer path still succeeds", func(t *testing.T) {
		// dpopWrap is a no-op when the flag is off — no DPoP layer in the chain.
		chain := middleware.RequireScope("kms:unwrap")(http.HandlerFunc(h.Unwrap))
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, withBound(kmsPost(t, "life42-root-kek", body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("flag-off plain-Bearer path should succeed, got %d body %s", rec.Code, rec.Body.String())
		}
	})
}

func TestKMSUnwrap_Unauthenticated(t *testing.T) {
	h := NewKMSHandler(newTestKMS(t, 0x33), newTestAuditLogger())
	req := kmsPost(t, "life42-root-kek", base64.StdEncoding.EncodeToString([]byte("x")))
	rec := httptest.NewRecorder()
	h.Unwrap(rec, req) // no claims injected
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body %s", rec.Code, rec.Body.String())
	}
}

// TestKMSUnwrap_AuthzChain exercises the exact middleware chain the router
// mounts (Auth -> RequireScope -> handler) with real signed tokens: no bearer
// is rejected, a token lacking the scope is rejected, and a scoped token
// succeeds end-to-end.
func TestKMSUnwrap_AuthzChain(t *testing.T) {
	key := newTestRSAKey(t)
	kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)
	const iss = "vault-test"
	ts := service.NewTokenService(key, kid, iss, iss, 5*time.Minute, time.Hour, time.Hour)
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}

	svc := newTestKMS(t, 0x44)
	h := NewKMSHandler(svc, newTestAuditLogger())
	chain := middleware.Auth(keys, iss, iss)(
		middleware.RequireScope("kms:unwrap")(http.HandlerFunc(h.Unwrap)))

	env, err := svc.Wrap("life42-root-kek", []byte("chain-test-32-byte-root-abcdefgh"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	body := base64.StdEncoding.EncodeToString(env)

	issue := func(scopes []string) string {
		pair, err := ts.IssueTokenPair(context.Background(), "life42-gateway", []string{"service"}, scopes, "life42-gateway", "", "", false)
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		return pair.AccessToken
	}

	tests := []struct {
		name   string
		bearer string
		want   int
	}{
		{"no_bearer", "", http.StatusUnauthorized},
		{"missing_scope", issue([]string{"user:read"}), http.StatusForbidden},
		{"with_scope", issue([]string{"kms:unwrap"}), http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := kmsPost(t, "life42-root-kek", body)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d; body %s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}
