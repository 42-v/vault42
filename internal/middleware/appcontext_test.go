package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/email"
)

// captureApp runs AppContext and returns the app slug the handler saw in context.
func captureApp(t *testing.T, r *http.Request) string {
	t.Helper()
	var seen string
	AppContext(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		seen = email.AppFromContext(req.Context())
	})).ServeHTTP(httptest.NewRecorder(), r)
	return seen
}

func TestAppContext(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		header  string
		query   string
		want    string
	}{
		{"trusted proxy header sets app", []string{"192.0.2.0/24"}, "acme", "", "acme"},
		{"untrusted peer header ignored", []string{"198.51.100.1"}, "beta", "", ""},
		{"no trusted proxies configured", nil, "beta", "", ""},
		{"query parameter never selects a tenant", []string{"192.0.2.0/24"}, "", "?app=beta", ""},
		{"query parameter cannot override header", []string{"192.0.2.0/24"}, "acme", "?app=beta", "acme"},
		{"invalid header ignored", []string{"192.0.2.0/24"}, "Bad App!", "", ""},
		{"absent leaves global branding", []string{"192.0.2.0/24"}, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(tt.proxies)
			defer SetTrustedProxies(nil)
			r := httptest.NewRequest(http.MethodGet, "/auth/login"+tt.query, nil)
			r.RemoteAddr = "192.0.2.10:44321"
			if tt.header != "" {
				r.Header.Set("X-Vault-App", tt.header)
			}
			if got := captureApp(t, r); got != tt.want {
				t.Errorf("resolved app = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppContext_CallsNext(t *testing.T) {
	called := false
	AppContext(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("AppContext must always call the next handler")
	}
}
