package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	tests := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "0",
		"Referrer-Policy":           "no-referrer",
		"Cache-Control":             "no-store",
	}

	for header, want := range tests {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// ASVS V3.4.3 names object-src 'none' and base-uri 'none' as the CSP minimum.
// Neither is implied by default-src: base-uri is not a fetch directive at all,
// so a <base> injection re-points every relative URL on the page past a
// default-src 'self' policy untouched, and object-src falls back to default-src
// only in CSP Level 3 browsers.
func TestCSPDeclaresObjectSrcAndBaseURI(t *testing.T) {
	for _, tc := range []struct {
		name          string
		serveFrontend bool
		path          string
	}{
		{"api policy", false, "/auth/login"},
		{"frontend policy", true, "/index.html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := SecurityHeaders(tc.serveFrontend)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			csp := rec.Header().Get("Content-Security-Policy")
			for _, directive := range []string{"object-src 'none'", "base-uri 'none'"} {
				if !strings.Contains(csp, directive) {
					t.Errorf("CSP %q omits %q (ASVS V3.4.3)", csp, directive)
				}
			}
		})
	}
}

func TestCSPHeader(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("CSP header should be set")
	}
}
