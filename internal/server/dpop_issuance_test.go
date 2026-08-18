package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// issuanceRoutes is every route on the vault mux that can put a freshly signed
// access token into a response.
//
// The DPoP middleware is the only writer of the thumbprint the issuance paths
// read (internal/dpop), so a route missing from the chain cannot mint a
// sender-constrained token however the deployment is configured: cnf.jkt stays
// empty, and the comparison in middleware.DPoP that a protected route performs
// against it therefore never fires. POST /client/token was exactly that route,
// and it is the one that feeds POST /kms/unwrap and POST /mint — the two
// credential-release oracles, which no user token can reach at all because
// every user issuance path hardcodes the read/write scopes. So the binding was
// absent from precisely the tokens it exists to constrain.
//
// authenticated marks the routes that sit behind authMw/challengeMw: the probe
// has to present a token before the request reaches the DPoP middleware.
var issuanceRoutes = []struct {
	method        string
	target        string
	authenticated bool
}{
	{http.MethodPost, "/auth/login", false},
	{http.MethodPost, "/auth/refresh", false},
	{http.MethodPost, "/client/token", false},
	{http.MethodPost, "/auth/2fa/totp/verify", true},
	{http.MethodPost, "/auth/2fa/backup-code/verify", true},
	{http.MethodPost, "/auth/2fa/email-otp/verify", true},
	{http.MethodPost, "/auth/2fa/webauthn/verify/finish", true},
}

// A malformed proof is the probe because it separates the two states cleanly: a
// route running the middleware rejects it with invalid_dpop_proof before any
// handler sees the request, and a route that skips the middleware ignores the
// header entirely and runs the handler on this fixture's nil repositories.
func TestEveryIssuanceRouteRunsTheDPoPMiddleware(t *testing.T) {
	mux, key := dpopRoutesMux(t, true)

	for _, tc := range issuanceRoutes {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("DPoP", "not-a-proof")
			if tc.authenticated {
				req.Header.Set("Authorization", "Bearer "+signRouteToken(t, key, ""))
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
				t.Fatalf("%s %s with a malformed DPoP header = %d %s, want 401 invalid_dpop_proof; "+
					"the route is not behind dpopWrap, so nothing it issues can carry cnf.jkt",
					tc.method, tc.target, rec.Code, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// The control for the test above: with the flag off the same probe must NOT be
// rejected, because dpopWrap is a no-op then and a deployment that has not
// enabled DPoP must not start failing requests that carry the header.
//
// Without this arm the gate would also pass against a build that rejected the
// header unconditionally, which is a different bug wearing the same 401.
func TestAMalformedProofIsIgnoredOnIssuanceRoutesWithTheFlagOff(t *testing.T) {
	mux, key := dpopRoutesMux(t, false)

	for _, tc := range issuanceRoutes {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("DPoP", "not-a-proof")
			if tc.authenticated {
				req.Header.Set("Authorization", "Bearer "+signRouteToken(t, key, ""))
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if body := rec.Body.String(); strings.Contains(body, "invalid_dpop_proof") {
				t.Fatalf("%s %s rejected a DPoP header with the feature disabled: %s",
					tc.method, tc.target, strings.TrimSpace(body))
			}
		})
	}
}
