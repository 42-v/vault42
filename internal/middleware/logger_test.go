package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoggerNormalRequest(t *testing.T) {
	var called bool
	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler should have been called")
	}
}

func TestLoggerStatusRecorder(t *testing.T) {
	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestLoggerHealthSilent(t *testing.T) {
	// Verify that /healthz requests still pass through to the handler
	var healthzCalled, readyzCalled bool

	healthHandler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthzCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	readyHandler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readyzCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// Test /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	healthHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", rec.Code)
	}
	if !healthzCalled {
		t.Error("/healthz handler should have been called")
	}

	// Test /readyz
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	readyHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/readyz status = %d, want 200", rec.Code)
	}
	if !readyzCalled {
		t.Error("/readyz handler should have been called")
	}
}
