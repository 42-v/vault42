package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// unboundRequest builds an authenticated request whose token carries no cnf.jkt —
// an ordinary bearer session — while still presenting a DPoP proof. Nothing stops
// a client from doing this, and after the binding was completed this middleware
// sits on every authenticated route, so it is the shape most requests would have
// if a client sent proofs unconditionally.
func unboundRequest(t *testing.T, proof string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://vault.test/user/profile", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	req.Header.Set("DPoP", proof)
	claims := &vaultcrypto.VaultClaims{}
	return req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))
}

// A replay entry costs a cache slot for dpopReplayTTL, and the cache is shared
// with every fail-closed rate limiter in the deployment. Writing one for a proof
// whose thumbprint is never compared spends that slot on nothing: the request
// holds an unbound token, so replaying the proof buys an attacker exactly what
// presenting the stolen token alone already buys.
//
// The route this runs on has no rate limiter — most authenticated routes do not —
// so an unbound client sending proofs can write entries as fast as it can send
// requests. That is a denial of service against login, not a replay control.
func TestAnUnboundTokenWritesNoReplayEntry(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key := dpopTestKey(t)
	h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	const requests = 25
	for i := range requests {
		jti := fmt.Sprintf("unbound-%d", i)
		proof := signDPoPProof(t, dpopProofOpts{
			key: key, method: "GET", uri: "https://vault.test/user/profile",
			token: "access-token", jti: jti,
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, unboundRequest(t, proof))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
		if _, err := memCache.Get(t.Context(), dpopReplayKey(jti)); err == nil {
			t.Fatalf("request %d wrote a replay entry for an unbound token", i)
		}
	}
}

// The other side of the same rule: the two cases where the entry does protect
// something must still write it. A token endpoint has no claims on the context,
// and a bound token is the replay control's whole reason to exist.
func TestTheReplayEntryIsStillWrittenWhereItProtectsSomething(t *testing.T) {
	key := dpopTestKey(t)
	jkt := dpopThumbprint(t, key)

	t.Run("token endpoint", func(t *testing.T) {
		memCache := cache.NewMemoryCache()
		t.Cleanup(func() { _ = memCache.Close() })

		h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		req := httptest.NewRequest(http.MethodPost, "https://vault.test/auth/login", nil)
		req.Header.Set("DPoP", signDPoPProof(t, dpopProofOpts{
			key: key, method: "POST", uri: "https://vault.test/auth/login", jti: "mint-once",
		}))
		h.ServeHTTP(httptest.NewRecorder(), req)

		if _, err := memCache.Get(t.Context(), dpopReplayKey("mint-once")); err != nil {
			t.Errorf("no replay entry for a proof presented at a token endpoint: %v", err)
		}
	})

	t.Run("bound token", func(t *testing.T) {
		memCache := cache.NewMemoryCache()
		t.Cleanup(func() { _ = memCache.Close() })

		const token = "access-token"
		h := DPoP(memCache, "https://vault.test")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		proof := signDPoPProof(t, dpopProofOpts{
			key: key, method: "GET", uri: "https://vault.test/user/profile", token: token, jti: "bound-once",
		})
		h.ServeHTTP(httptest.NewRecorder(), boundRequest(t, "DPoP", token, jkt, proof))

		if _, err := memCache.Get(t.Context(), dpopReplayKey("bound-once")); err != nil {
			t.Errorf("no replay entry for a proof presented with a bound token: %v", err)
		}
	})
}
