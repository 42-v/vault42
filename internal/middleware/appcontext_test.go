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
		name   string
		header string
		query  string
		want   string
	}{
		{"header sets app", "acme", "", "acme"},
		{"query fallback when no header", "", "?app=beta", "beta"},
		{"header wins over query", "acme", "?app=beta", "acme"},
		{"invalid header ignored", "Bad App!", "", ""},
		{"invalid query ignored", "", "?app=Bad!", ""},
		{"absent leaves global branding", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/login"+tt.query, nil)
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
