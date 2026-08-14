package attack

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/middleware"
)

// TestMaxBodySkipsGETRequests verifies that the MaxBody middleware
// does NOT apply body size limits to GET requests, which is needed
// for serving static frontend assets (JS/CSS files > 8KB).
func TestMaxBodySkipsGETRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.MaxBody(100)(inner) // 100 byte limit

	// GET request should pass through regardless of body
	req := httptest.NewRequest(http.MethodGet, "/some-asset.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET should pass through MaxBody, got %d", rec.Code)
	}
}

// TestMaxBodySkipsHEADRequests verifies HEAD requests bypass body limits.
func TestMaxBodySkipsHEADRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.MaxBody(100)(inner)

	req := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD should pass through MaxBody, got %d", rec.Code)
	}
}

// TestMaxBodyEnforcesOnPOST verifies that POST requests are still
// body-limited — an attacker can't send a 1GB JSON payload.
func TestMaxBodyEnforcesOnPOST(t *testing.T) {
	var bytesRead int
	var readErr error
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		bytesRead = len(data)
		readErr = err
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.MaxBody(100)(inner) // 100 byte limit

	// POST with a body four times the limit.
	bigBody := strings.NewReader(strings.Repeat("A", 400))
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bigBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// MaxBody wraps the body in http.MaxBytesReader(w, r.Body, 100), so the
	// handler can never read more than the cap: draining the body surfaces the
	// "http: request body too large" error and yields at most 100 bytes. A no-op
	// middleware would hand the handler all 400 bytes with a nil error, failing
	// both checks, so this is the assertion that makes the DoS control real.
	if readErr == nil {
		t.Errorf("expected MaxBytesReader error draining oversized body, got nil (read %d bytes)", bytesRead)
	}
	if bytesRead > 100 {
		t.Errorf("MaxBody cap breached: handler read %d bytes, want <= 100", bytesRead)
	}
}

// TestMaxBodyZeroPOSTBody verifies that empty POST bodies pass through.
func TestMaxBodyZeroPOSTBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.MaxBody(8192)(inner)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("empty POST body should pass, got %d", rec.Code)
	}
}
