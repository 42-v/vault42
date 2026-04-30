package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSPreflight(t *testing.T) {
	handler := CORS("https://example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("origin = %q, want https://example.com", got)
	}
}

func TestCORSAllowAll(t *testing.T) {
	handler := CORS("", nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without Origin header, falls back to "*"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("origin = %q, want *", got)
	}

	// With Origin header, reflects it back (required for credentials)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Origin", "http://localhost:5173")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("origin = %q, want http://localhost:5173", got)
	}
	wantVary := "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
	if got := rec2.Header().Get("Vary"); got != wantVary {
		t.Errorf("Vary = %q, want %q", got, wantVary)
	}
}
