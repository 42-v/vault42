package adminapi

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// adminapiFailingReader stands in for crypto/rand.Reader and always fails.
// Only direct io.ReadFull(rand.Reader, ...) callers get the error back, so it
// may only be installed around code that never calls rand.Read.
type adminapiFailingReader struct{}

func (adminapiFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy exhausted")
}

// adminapiSwapRandReader installs r as crypto/rand.Reader and restores the
// original when the test ends. internal/adminapi has no parallel tests, so
// the global swap cannot race.
func adminapiSwapRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

// A request must never fail because entropy did: RequestID falls back to the
// all-zero UUID and still serves the request.
func TestRequestID_EntropyFailureFallsBackToZeroUUID(t *testing.T) {
	adminapiSwapRandReader(t, adminapiFailingReader{})

	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Request-ID"); got != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("X-Request-ID = %q, want the all-zero fallback UUID", got)
	}
}

// A RemoteAddr without a port (a unix socket peer or an in-process caller)
// must not bypass the limiter: the full address becomes the rate-limit key.
func TestLoginRateLimit_PortlessRemoteAddrStillKeyed(t *testing.T) {
	rl := NewLoginRateLimit(1, time.Minute)
	handler := rl.Wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRequest("POST", "/admin/auth/login", nil)
	first.RemoteAddr = "10.9.8.7"
	w := httptest.NewRecorder()
	handler(w, first)
	if w.Code != http.StatusOK {
		t.Fatalf("first attempt: code = %d, want 200", w.Code)
	}

	second := httptest.NewRequest("POST", "/admin/auth/login", nil)
	second.RemoteAddr = "10.9.8.7"
	w = httptest.NewRecorder()
	handler(w, second)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt: code = %d, want 429", w.Code)
	}
	if !strings.Contains(w.Body.String(), "rate_limited") {
		t.Errorf("body = %q, want rate_limited", w.Body.String())
	}
}
