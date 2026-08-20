package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryNoPanic(t *testing.T) {
	var called bool
	handler := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/safe", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler should have been called")
	}
}

// Recovery must turn any panic value into the same opaque 500, whatever was
// thrown. The two cases this replaced both panicked with a string and one of
// them was named for a nil dereference it never performed, so a real runtime
// panic (which arrives as a runtime.Error, not a string) was never exercised.
//
// The body is compared exactly because the point is that nothing about the
// panic reaches the client: a panic value that leaked into the response would
// hand an attacker a stack-shaped oracle.
func TestRecoveryWithPanic(t *testing.T) {
	tests := []struct {
		name  string
		panic func()
	}{
		{name: "a string", panic: func() { panic("something went wrong") }},
		{name: "an error", panic: func() { panic(errors.New("handler blew up")) }},
		{name: "a runtime nil dereference", panic: func() {
			var p *int
			_ = *p
		}},
		{name: "a value of no useful type", panic: func() { panic(struct{ Secret string }{"do-not-leak"}) }},
		{name: "a nil panic value", panic: func() { panic(nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := Recovery(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				tt.panic()
			}))

			req := httptest.NewRequest(http.MethodGet, "/crash", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rec.Code)
			}
			if body := rec.Body.String(); body != "{\"error\":\"internal_server_error\"}\n" {
				t.Errorf("body = %q, want the opaque internal_server_error body", body)
			}
		})
	}
}
