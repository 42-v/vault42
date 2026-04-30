package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_AllHeadersPresent(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	required := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Cache-Control",
		"Pragma",
	}

	for _, header := range required {
		t.Run(header+" is set", func(t *testing.T) {
			if rec.Header().Get(header) == "" {
				t.Errorf("%s header should be set", header)
			}
		})
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")

	t.Run("contains max-age", func(t *testing.T) {
		if !strings.Contains(hsts, "max-age=31536000") {
			t.Errorf("HSTS = %q, should contain max-age=31536000 (1 year)", hsts)
		}
	})

	t.Run("includes subdomains", func(t *testing.T) {
		if !strings.Contains(hsts, "includeSubDomains") {
			t.Errorf("HSTS = %q, should include includeSubDomains", hsts)
		}
	})

	t.Run("includes preload", func(t *testing.T) {
		if !strings.Contains(hsts, "preload") {
			t.Errorf("HSTS = %q, should include preload", hsts)
		}
	})
}

func TestSecurityHeaders_CSP(t *testing.T) {
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	t.Run("default-src is none", func(t *testing.T) {
		if !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("CSP = %q, should contain default-src 'none'", csp)
		}
	})

	t.Run("frame-ancestors is none", func(t *testing.T) {
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP = %q, should contain frame-ancestors 'none'", csp)
		}
	})
}

func TestSecurityHeaders_NextHandlerCalled(t *testing.T) {
	called := false
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("next handler is called", func(t *testing.T) {
		if !called {
			t.Error("next handler should be called")
		}
	})
}

func TestSecurityHeaders_HeadersSetBeforeHandler(t *testing.T) {
	// Verify headers are set before the next handler writes the response body
	var hstsInHandler string
	handler := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hstsInHandler = w.Header().Get("Strict-Transport-Security")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("HSTS is set before next handler", func(t *testing.T) {
		if hstsInHandler == "" {
			t.Error("HSTS header should be set before next handler executes")
		}
	})
}

func TestSecurityHeaders_CSPRouting(t *testing.T) {
	apiCSP := "default-src 'none'"
	frontendCSP := "default-src 'self'"

	// API paths must always get strict CSP, even with serveFrontend=true
	apiPaths := []string{
		"/auth/login",
		"/auth/register",
		"/auth/2fa/totp/setup",
		"/client/token",
		"/user/profile",
		"/user/sessions",
		"/user/blobs",
		"/user/identity",
		"/admin/config",
		"/.well-known/jwks.json",
		"/healthz",
		"/readyz",
	}

	// Frontend paths get relaxed CSP when serveFrontend=true
	frontendPaths := []string{
		"/",
		"/login",
		"/2fa",
		"/profile",
		"/assets/index.js",
	}

	handler := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range apiPaths {
		t.Run("API "+path+" gets strict CSP", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			csp := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, apiCSP) {
				t.Errorf("path %s CSP = %q, want strict API CSP containing %q", path, csp, apiCSP)
			}
		})
	}

	for _, path := range frontendPaths {
		t.Run("Frontend "+path+" gets relaxed CSP", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			csp := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, frontendCSP) {
				t.Errorf("path %s CSP = %q, want frontend CSP containing %q", path, csp, frontendCSP)
			}
		})
	}

	// With serveFrontend=false, all paths get strict CSP
	handlerNoFrontend := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range frontendPaths {
		t.Run("NoFrontend "+path+" gets strict CSP", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handlerNoFrontend.ServeHTTP(rec, req)

			csp := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, apiCSP) {
				t.Errorf("path %s CSP = %q, want strict API CSP containing %q", path, csp, apiCSP)
			}
		})
	}
}
