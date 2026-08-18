package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/dpop"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// dpopProofOpts is everything a test needs to bend about a proof: the key that
// signs it, the method and URI it commits to, the access token it is bound to,
// and its replay id.
type dpopProofOpts struct {
	key    *rsa.PrivateKey
	method string
	uri    string
	token  string
	jti    string
	iat    time.Time
}

func signDPoPProof(t *testing.T, o dpopProofOpts) string {
	t.Helper()
	if o.jti == "" {
		o.jti = "jti-" + o.method + o.uri
	}
	if o.iat.IsZero() {
		o.iat = time.Now()
	}
	claims := &vaultcrypto.DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(o.iat),
			ID:       o.jti,
		},
		HTM: o.method,
		HTU: o.uri,
	}
	if o.token != "" {
		claims.ATH = vaultcrypto.SHA256Base64URL(o.token)
	}
	header := map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(o.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(o.key.PublicKey.E)).Bytes()),
		},
	}
	proof, err := vjwt.SignRS256WithHeader(header, claims, o.key)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	return proof
}

func dpopTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func dpopThumbprint(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	jkt, err := vaultcrypto.ComputeJWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return jkt
}

// The hop that did not exist. Without the thumbprint on the context there is
// nothing for issuance to write into cnf.jkt, and with cnf.jkt never written the
// comparison at the bottom of the middleware never runs — which is what made a
// presented proof a proof of nothing.
func TestAValidatedProofPutsItsThumbprintOnTheContext(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	var seen string
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = dpop.Thumbprint(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "https://vault.test/auth/login", nil)
	req.Header.Set("DPoP", signDPoPProof(t, dpopProofOpts{key: key, method: "POST", uri: "https://vault.test/auth/login"}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if want := dpopThumbprint(t, key); seen != want {
		t.Errorf("thumbprint on the context = %q, want %q", seen, want)
	}
}

// A request with no proof leaves the context clean, so issuance mints an ordinary
// bearer token. Every non-DPoP client depends on that being the default.
func TestARequestWithNoProofCarriesNoThumbprint(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	seen := "unset"
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = dpop.Thumbprint(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "https://vault.test/auth/login", nil))

	if seen != "" {
		t.Errorf("thumbprint = %q for a request with no proof, want empty", seen)
	}
}

// boundRequest builds a request presenting a DPoP-bound token, with whatever
// scheme, proof key and target the case needs.
func boundRequest(t *testing.T, scheme, token, boundJKT string, proof string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://vault.test/user/profile", nil)
	if scheme != "" {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	claims := &vaultcrypto.VaultClaims{Confirmation: &vaultcrypto.Confirmation{JKT: boundJKT}}
	return req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))
}

// The key confirmation itself: a bound token presented with a proof over a
// DIFFERENT key is refused. This is the check that was unreachable.
func TestABoundTokenIsRefusedWhenTheProofIsOverAnotherKey(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	bound, attacker := dpopTestKey(t), dpopTestKey(t)
	const token = "access-token"
	proof := signDPoPProof(t, dpopProofOpts{
		key: attacker, method: "GET", uri: "https://vault.test/user/profile", token: token,
	})

	reached := false
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, boundRequest(t, "DPoP", token, dpopThumbprint(t, bound), proof))

	if reached {
		t.Fatal("a token bound to one key was accepted with a proof over another")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// The matching key gets through, or the control is just a denial.
func TestABoundTokenIsAcceptedWithAProofOverItsOwnKey(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	const token = "access-token"
	proof := signDPoPProof(t, dpopProofOpts{
		key: key, method: "GET", uri: "https://vault.test/user/profile", token: token,
	})

	reached := false
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, boundRequest(t, "DPoP", token, dpopThumbprint(t, key), proof))

	if !reached {
		t.Fatalf("a correctly bound request was refused: %d %s", rec.Code, rec.Body.String())
	}
}

// RFC 9449 §7.1: a sender-constrained token travels under the DPoP scheme.
// Accepting it under Bearer lets any consumer that only reads the scheme treat a
// bound token as an ordinary one, which is the confusion the scheme exists to
// prevent.
func TestABoundTokenIsRefusedUnderTheBearerScheme(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	const token = "access-token"
	proof := signDPoPProof(t, dpopProofOpts{
		key: key, method: "GET", uri: "https://vault.test/user/profile", token: token,
	})

	reached := false
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, boundRequest(t, "Bearer", token, dpopThumbprint(t, key), proof))

	if reached {
		t.Fatal("a sender-constrained token was accepted under the Bearer scheme")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); body == "" || !contains(body, "dpop_scheme_required") {
		t.Errorf("body = %q, want dpop_scheme_required", body)
	}
}

// A bound token with no proof at all is refused, which is the case that makes
// stealing the token alone useless.
func TestABoundTokenIsRefusedWithNoProof(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	reached := false
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, boundRequest(t, "DPoP", "access-token", dpopThumbprint(t, key), ""))

	if reached {
		t.Fatal("a sender-constrained token was accepted with no proof")
	}
	if body := rec.Body.String(); !contains(body, "dpop_proof_required") {
		t.Errorf("body = %q, want dpop_proof_required", body)
	}
}

// One proof, one request. A captured proof replayed against a bound token must be
// refused on its jti even though every other check still passes.
func TestAReplayedProofIsRefusedOnItsJTI(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	jkt := dpopThumbprint(t, key)
	const token = "access-token"
	proof := signDPoPProof(t, dpopProofOpts{
		key: key, method: "GET", uri: "https://vault.test/user/profile", token: token, jti: "single-use",
	})

	accepted := 0
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accepted++ }))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, boundRequest(t, "DPoP", token, jkt, proof))
	second := httptest.NewRecorder()
	h.ServeHTTP(second, boundRequest(t, "DPoP", token, jkt, proof))

	if accepted != 1 {
		t.Fatalf("the handler ran %d times for one proof, want 1", accepted)
	}
	if second.Code != http.StatusUnauthorized {
		t.Errorf("replayed proof status = %d, want 401", second.Code)
	}
	if body := second.Body.String(); !contains(body, "dpop_proof_reused") {
		t.Errorf("body = %q, want dpop_proof_reused", body)
	}
}

// htm and htu bind a proof to one method and one URI, so a proof captured from a
// read cannot be replayed against a write, or against another endpoint.
func TestAProofIsBoundToItsMethodAndURI(t *testing.T) {
	key := dpopTestKey(t)
	jkt := dpopThumbprint(t, key)
	const token = "access-token"

	for _, tc := range []struct {
		name           string
		method, target string
	}{
		{"another method", "POST", "https://vault.test/user/profile"},
		{"another endpoint", "GET", "https://vault.test/user/sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memCache := cache.NewMemoryCache()
			t.Cleanup(func() { _ = memCache.Close() })

			proof := signDPoPProof(t, dpopProofOpts{
				key: key, method: tc.method, uri: tc.target, token: token, jti: tc.name,
			})

			reached := false
			h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
			rec := httptest.NewRecorder()
			// The request is always GET /user/profile; only the proof's claims move.
			h.ServeHTTP(rec, boundRequest(t, "DPoP", token, jkt, proof))

			if reached {
				t.Fatalf("a proof committed to %s %s was accepted on GET /user/profile", tc.method, tc.target)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

// ath ties the proof to the exact token presented, so a proof captured alongside
// one token cannot be reused with a stolen one.
func TestAProofIsBoundToTheTokenItWasMintedFor(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	proof := signDPoPProof(t, dpopProofOpts{
		key: key, method: "GET", uri: "https://vault.test/user/profile", token: "the-original-token",
	})

	reached := false
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, boundRequest(t, "DPoP", "a-different-token", dpopThumbprint(t, key), proof))

	if reached {
		t.Fatal("a proof minted for one token was accepted with another")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
