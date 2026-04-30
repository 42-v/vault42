package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxBody(t *testing.T) {
	handler := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Small body — should pass
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("small body: status = %d, want 200", rec.Code)
	}

	// Large body — should fail
	bigBody := strings.Repeat("x", 100)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(bigBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: status = %d, want 413", rec.Code)
	}
}
