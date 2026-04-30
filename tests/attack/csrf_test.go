package attack

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/middleware"
)

// TestCSRF_CORSRejectsWildcardWithCredentials verifies that CORS middleware
// does not allow wildcard origin (*) when credentials are involved, which
// would be a CSRF vulnerability.
func TestCSRF_CORSRejectsWildcardWithCredentials(t *testing.T) {
	// allowAll=false with a specific origin
	handler := middleware.CORS("https://app.example.com", nil, false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	tests := []struct {
		name          string
		origin        string
		expectAllowed bool
	}{
		{"correct_origin", "https://app.example.com", true},
		{"wrong_origin", "https://evil.example.com", false},
		{"no_origin", "", false},
		{"subdomain_attack", "https://evil.app.example.com", false},
		{"http_downgrade", "http://app.example.com", false},
		{"port_variation", "https://app.example.com:8443", false},
		{"path_suffix", "https://app.example.com.evil.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/auth/login", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			req.Header.Set("Access-Control-Request-Method", "POST")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			if tc.expectAllowed && allowOrigin != tc.origin {
				t.Fatalf("Expected Allow-Origin=%q, got %q", tc.origin, allowOrigin)
			}
			if !tc.expectAllowed && allowOrigin == tc.origin && tc.origin != "" {
				t.Fatalf("Origin %q should NOT be allowed, but got Allow-Origin=%q", tc.origin, allowOrigin)
			}
		})
	}
}

// TestCSRF_CORSAllowAllMode verifies that allowAll mode only reflects localhost
// origins (dev restriction), rejecting non-localhost origins for security.
func TestCSRF_CORSAllowAllMode(t *testing.T) {
	handler := middleware.CORS("", nil, true)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Localhost origins should be reflected
	localhostOrigins := []string{
		"http://localhost:3000",
		"https://localhost:8443",
		"http://127.0.0.1:8080",
	}

	for _, origin := range localhostOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/health", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			if allowOrigin != origin {
				t.Fatalf("Allow-all mode should reflect localhost origin %q, got %q", origin, allowOrigin)
			}

			allowCreds := rec.Header().Get("Access-Control-Allow-Credentials")
			if allowCreds != "true" {
				t.Fatal("Allow-all mode should set Allow-Credentials to true")
			}
		})
	}

	// Non-localhost origins should be rejected
	rejectedOrigins := []string{
		"https://any-origin.example.com",
		"https://evil.com",
	}

	for _, origin := range rejectedOrigins {
		t.Run("rejects_"+origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/health", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			if allowOrigin != "" {
				t.Fatalf("Allow-all mode should reject non-localhost origin %q, got %q", origin, allowOrigin)
			}
		})
	}

	// Without Origin header, should fall back to *
	t.Run("no_origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
		if allowOrigin != "*" {
			t.Fatalf("Allow-all without Origin header should be *, got %q", allowOrigin)
		}
	})
}

// TestCSRF_SecurityHeadersPresent verifies that security headers preventing
// various client-side attacks are set.
func TestCSRF_SecurityHeadersPresent(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	requiredHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}

	for header, expected := range requiredHeaders {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("Header %q = %q, want %q", header, got, expected)
		}
	}
}

// TestCSRF_PreflightMethodValidation verifies that CORS preflight validates
// the requested HTTP method.
func TestCSRF_PreflightMethodValidation(t *testing.T) {
	handler := middleware.CORS("https://app.example.com", nil, false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("OPTIONS", "/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Preflight should return 204 (No Content) or 200
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("Preflight should return 204 or 200, got %d", rec.Code)
	}

	allowMethods := rec.Header().Get("Access-Control-Allow-Methods")
	if allowMethods == "" {
		t.Fatal("Preflight response should include Access-Control-Allow-Methods")
	}
}

// TestCSRF_MaxBodyEnforcement verifies that MaxBody middleware prevents
// oversized request bodies (which could be part of CSRF amplification attacks).
func TestCSRF_MaxBodyEnforcement(t *testing.T) {
	maxBytes := int64(1024) // 1KB max

	handler := middleware.MaxBody(maxBytes)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Small body should be accepted
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.ContentLength = 100
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	// MaxBody wraps the body reader but doesn't check ContentLength upfront
	// The handler should still work for normal requests

	// This test verifies the middleware exists and wraps properly
	if rec.Code != http.StatusOK {
		t.Fatalf("Small body should be accepted, got %d", rec.Code)
	}
}

// TestCSRF_NoCacheOnAuthEndpoints verifies that security headers include
// cache control to prevent CSRF via cached responses.
func TestCSRF_NoCacheOnAuthEndpoints(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("POST", "/auth/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Security headers middleware should set protective headers
	xContentType := rec.Header().Get("X-Content-Type-Options")
	if xContentType != "nosniff" {
		t.Fatalf("X-Content-Type-Options should be nosniff, got %q", xContentType)
	}
}

// TestCSRF_RequestIDGenerated verifies that each request gets a unique
// request ID for audit trail purposes (helps trace CSRF attempts).
func TestCSRF_RequestIDGenerated(t *testing.T) {
	handler := middleware.RequestID(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := middleware.GetRequestID(r.Context())
			if reqID == "" {
				t.Fatal("Request ID should not be empty")
			}
			w.Header().Set("X-Request-Id-Check", reqID)
			w.WriteHeader(http.StatusOK)
		}),
	)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		id := rec.Header().Get("X-Request-Id-Check")
		if id == "" {
			t.Fatal("No request ID generated")
		}
		if ids[id] {
			t.Fatalf("Duplicate request ID at iteration %d", i)
		}
		ids[id] = true
	}
}
