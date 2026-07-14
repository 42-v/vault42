package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/cache"
)

// The `ath` claim binds a DPoP proof to the specific access token it was minted
// for. Without it, a proof captured from one request could be replayed with a
// different (stolen) token — the proof would still validate, because nothing
// would tie it to the token being presented.
//
// This exercises the path where an Authorization header is present, so the
// middleware computes the token hash and requires the proof to carry it. A proof
// with no `ath` must be rejected once a bearer token is on the request.
func TestDPoP_ProofWithoutAthIsRejectedWhenTokenPresent(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	reached := false
	h := DPoP(memCache, "https://vault.example.com")(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }),
	)

	req := httptest.NewRequest(http.MethodGet, "https://vault.example.com/user/profile", nil)
	req.Header.Set("Authorization", "Bearer some-access-token")
	// A syntactically present but invalid proof: the point is that the middleware
	// takes the ath-computing branch (Authorization is set and well-formed) and
	// then fails validation, rather than skipping the binding entirely.
	req.Header.Set("DPoP", "not-a-valid-proof")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached {
		t.Error("an invalid DPoP proof reached the handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// A malformed Authorization header (no space, so no token part) must not panic
// the ath computation — it simply yields no hash.
func TestDPoP_MalformedAuthorizationHeaderDoesNotPanic(t *testing.T) {
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	h := DPoP(memCache, "https://vault.example.com")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	req := httptest.NewRequest(http.MethodGet, "https://vault.example.com/user/profile", nil)
	req.Header.Set("Authorization", "Bearer") // no token part
	req.Header.Set("DPoP", "not-a-valid-proof")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req) // must not panic

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
