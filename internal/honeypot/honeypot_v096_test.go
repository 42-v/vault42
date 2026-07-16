package honeypot

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLog redirects the standard logger into a buffer for the duration of
// the test and restores the previous writer on cleanup.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// An automation User-Agent through the logging middleware must be tagged with
// risk=30 in the request log line so threat analysis can filter tool traffic.
func TestLoggingMiddleware_AutomationUARiskScore(t *testing.T) {
	buf := captureLog(t)

	a := NewAlerter("", nil, nil)
	handler := LoggingMiddleware(a)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := buf.String(); !strings.Contains(got, "risk=30") {
		t.Fatalf("log = %q, want risk=30 for automation UA", got)
	}
}

// A webhook URL that passes the scheme allowlist but is unparseable (control
// character in the path) must fail at request construction: Alert logs the
// error and returns without dispatching anything.
func TestAlert_UnparseableWebhookURL(t *testing.T) {
	buf := captureLog(t)

	a := NewAlerter("http://127.0.0.1/\n", nil, nil)
	a.Alert(context.Background(), HoneypotEvent{
		EventType: "trap_login",
		IP:        "203.0.113.7",
	})

	got := buf.String()
	if !strings.Contains(got, "honeypot: create request:") {
		t.Fatalf("log = %q, want create request failure", got)
	}
	if !strings.Contains(got, "invalid control character in URL") {
		t.Fatalf("log = %q, want net/url control character error", got)
	}
}
