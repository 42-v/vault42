package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNotImplemented_Envelope(t *testing.T) {
	rec := httptest.NewRecorder()
	notImplemented(rec, httptest.NewRequest(http.MethodGet, "/admin/metrics", nil))

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "not_implemented" {
		t.Errorf("error = %q, want not_implemented", body["error"])
	}
}

// The 501 replaces the handler body, not the permission gate: an unauthenticated
// caller must still be turned away before it learns anything about the route.
func TestRouter_MetricsStillGated(t *testing.T) {
	router := NewRouter(newTestAuth(nil, nil), newTestHandler(nil, nil, nil, nil), RouterOpts{DevMode: true})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/metrics", nil))

	if rec.Code == http.StatusNotImplemented {
		t.Fatal("GET /admin/metrics answered 501 without authentication; the permission gate was bypassed")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
