package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Additional origins come from config as a comma-separated list, so blanks are
// routine. A blank must not become an allowed origin — an empty Origin header
// would then match and CORS would be open to anyone who sends one.
func TestCORS_AdditionalOriginsAreHonouredAndBlanksIgnored(t *testing.T) {
	h := CORS("https://vault.example.com", []string{"https://app.example.com", ""}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	tests := []struct {
		name   string
		origin string
		want   string // expected Access-Control-Allow-Origin
	}{
		{"the primary origin", "https://vault.example.com", "https://vault.example.com"},
		{"an additional origin", "https://app.example.com", "https://app.example.com"},
		{"an origin that is on neither list", "https://evil.example.com", ""},
		// No Origin header is a same-origin request: the middleware answers with the
		// primary origin. What matters is that the blank entry in the additional
		// list never became a *matchable* origin — origins[""] is never set, so a
		// request cannot opt into it.
		{"no Origin header falls back to the primary", "", "https://vault.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.want {
				t.Errorf("Allow-Origin = %q, want %q", got, tc.want)
			}
		})
	}
}

// isLocalhostOrigin gates the allow-all dev mode. A value that is not a URL at
// all must not slip through it.
func TestIsLocalhostOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:5173", true},
		{"https://127.0.0.1", true},
		{"https://evil.com", false},
		{"://not a url", false},
		{"http://[::1", false}, // unparseable
	}

	for _, tc := range tests {
		if got := isLocalhostOrigin(tc.origin); got != tc.want {
			t.Errorf("isLocalhostOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}
