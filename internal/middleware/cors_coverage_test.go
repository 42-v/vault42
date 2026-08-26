package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORS_FixedOrigin_GetRequest(t *testing.T) {
	handler := CORS("https://vault.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("status is 200 for GET", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("origin header matches configured origin", func(t *testing.T) {
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://vault.example.com" {
			t.Errorf("origin = %q, want https://vault.example.com", got)
		}
	})

	t.Run("vary header is set", func(t *testing.T) {
		want := "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
		if got := rec.Header().Get("Vary"); got != want {
			t.Errorf("Vary = %q, want %q", got, want)
		}
	})
}

func TestCORS_FixedOrigin_IgnoresRequestOrigin(t *testing.T) {
	handler := CORS("https://vault.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("request with different Origin header gets no ACAO", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin = %q, want empty (non-matching origin should be rejected)", got)
		}
	})

	t.Run("request with empty Origin still uses configured origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://vault.example.com" {
			t.Errorf("origin = %q, want https://vault.example.com", got)
		}
	})
}

func TestCORS_Preflight_StatusNoContent(t *testing.T) {
	nextCalled := false
	handler := CORS("https://example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("returns 204", func(t *testing.T) {
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", rec.Code)
		}
	})

	t.Run("next handler not called", func(t *testing.T) {
		if nextCalled {
			t.Error("next handler should NOT be called on preflight OPTIONS")
		}
	})
}

func TestCORS_Preflight_AllHeaders(t *testing.T) {
	handler := CORS("https://example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/auth", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("allow-methods", func(t *testing.T) {
		got := rec.Header().Get("Access-Control-Allow-Methods")
		methods := make(map[string]bool)
		for _, m := range strings.Split(got, ",") {
			methods[strings.TrimSpace(m)] = true
		}
		for _, want := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			if !methods[want] {
				t.Errorf("allow-methods %q missing %s", got, want)
			}
		}
	})

	t.Run("allow-headers includes Authorization", func(t *testing.T) {
		// Containment, not equality. Both subtests are named "includes X" and
		// both compared the whole string, so every legitimate addition to the
		// list broke them while proving nothing the name claimed. The list has
		// since had to grow for the SDK's own headers.
		got := rec.Header().Get("Access-Control-Allow-Headers")
		if !strings.Contains(got, "Authorization") {
			t.Errorf("allow-headers = %q, should include Authorization", got)
		}
	})

	t.Run("allow-credentials is true", func(t *testing.T) {
		got := rec.Header().Get("Access-Control-Allow-Credentials")
		if got != "true" {
			t.Errorf("allow-credentials = %q, want true", got)
		}
	})

	t.Run("max-age is set", func(t *testing.T) {
		got := rec.Header().Get("Access-Control-Max-Age")
		if got != "86400" {
			t.Errorf("max-age = %q, want 86400", got)
		}
	})
}

func TestCORS_AllowAll_ReflectsLocalhostOrigin(t *testing.T) {
	handler := CORS("", nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := []string{
		"http://localhost:3000",
		"https://localhost:8443",
		"http://127.0.0.1:8080",
	}

	for _, origin := range allowed {
		t.Run("reflects "+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("origin = %q, want %q", got, origin)
			}
		})
	}

	rejected := []string{
		"https://frontend.example.com",
		"http://192.168.1.100:8080",
		"https://sub.domain.example.org",
	}

	for _, origin := range rejected {
		t.Run("rejects "+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("origin = %q, want empty for non-localhost", got)
			}
		})
	}
}

func TestCORS_AllowAll_NoOriginFallsToWildcard(t *testing.T) {
	handler := CORS("", nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	// No Origin header set
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("falls back to wildcard", func(t *testing.T) {
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("origin = %q, want *", got)
		}
	})
}

func TestCORS_AllowAll_PreflightReflectsLocalhostOrigin(t *testing.T) {
	handler := CORS("", nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/auth", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("status 204", func(t *testing.T) {
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", rec.Code)
		}
	})

	t.Run("reflects localhost origin on preflight", func(t *testing.T) {
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
			t.Errorf("origin = %q, want http://localhost:3000", got)
		}
	})
}

func TestCORS_CredentialsAlwaysTrue(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		allowAll bool
	}{
		{"fixed origin", "https://example.com", false},
		{"allow all", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := CORS(tt.origin, nil, tt.allowAll)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.allowAll {
				req.Header.Set("Origin", "http://localhost:3000")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Errorf("credentials = %q, want true", got)
			}
		})
	}
}

func TestCORS_NonOptionsMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
	}

	handler := CORS("https://example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range methods {
		t.Run(method+" passes through", func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/resource", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for %s", rec.Code, method)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
				t.Errorf("origin = %q, want https://example.com", got)
			}
		})
	}
}

func TestCORS_AllowAll_DPoPHeaderIncluded(t *testing.T) {
	handler := CORS("https://vault.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/token", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("allow-headers includes DPoP", func(t *testing.T) {
		got := rec.Header().Get("Access-Control-Allow-Headers")
		if !strings.Contains(got, "DPoP") {
			t.Errorf("allow-headers = %q, should include DPoP", got)
		}
	})
}

func TestCORS_EmptyOriginFixedMode(t *testing.T) {
	// When allowAll=false and origin is empty string
	handler := CORS("", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("uses empty origin", func(t *testing.T) {
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin = %q, want empty string", got)
		}
	})
}
