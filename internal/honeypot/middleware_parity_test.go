package honeypot

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hijackableRecorder is a ResponseWriter that can stream and can be taken over,
// which is what net/http hands a handler on a real connection.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
}

func (h *hijackableRecorder) Flush() { h.flushed = true }

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, errors.New("test connection cannot be taken over")
}

// The honeypot logger sits between the router and the handler, so the
// ResponseWriter a handler sees in honeypot mode is the one this package wraps.
// A wrapper that drops http.Flusher makes every streaming response buffer until
// the handler returns, and only on the honeypot: the standard logging
// middleware forwards Flush for exactly this reason. An attacker watching when
// bytes arrive gets a difference between the two deployments that costs them one
// request, and any streaming endpoint silently changes behavior on the trap.
func TestTheHandlerBehindTheHoneypotLoggerCanStillFlushTheResponse(t *testing.T) {
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}

	var seen http.ResponseWriter
	handler := LoggingMiddleware(NewAlerter("", nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen = w
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	flusher, ok := seen.(http.Flusher)
	if !ok {
		t.Fatalf("the handler was given a %T, which cannot flush; the real chain gives it one that can", seen)
	}
	flusher.Flush()
	if !rec.flushed {
		t.Error("Flush did not reach the underlying ResponseWriter, so the response still buffers")
	}
}

// When the writer underneath genuinely cannot be taken over, the answer is an
// error. Returning success on a connection the caller does not have would leave
// a handler writing to a hijacked connection that was never hijacked.
func TestHijackingReportsAnErrorWhenTheWriterUnderneathCannotBeTakenOver(t *testing.T) {
	var seen http.ResponseWriter
	handler := LoggingMiddleware(NewAlerter("", nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen = w
		w.WriteHeader(http.StatusOK)
	}))
	// A plain recorder is not an http.Hijacker.
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	hijacker, ok := seen.(http.Hijacker)
	if !ok {
		t.Fatalf("the handler was given a %T, which cannot be hijacked", seen)
	}
	conn, rw, err := hijacker.Hijack()
	if err == nil {
		t.Fatal("Hijack claimed to have taken over a connection that cannot be taken over")
	}
	if conn != nil || rw != nil {
		t.Error("Hijack returned a connection alongside its error")
	}
}

// Same wrapper, same problem for a connection upgrade. The standard logging
// middleware forwards Hijack and says why: WebSocket support. A honeypot that
// cannot upgrade a connection the real deployment upgrades answers a probe the
// attacker did not have to pay for.
func TestTheHandlerBehindTheHoneypotLoggerCanStillHijackTheConnection(t *testing.T) {
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}

	var seen http.ResponseWriter
	handler := LoggingMiddleware(NewAlerter("", nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen = w
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	hijacker, ok := seen.(http.Hijacker)
	if !ok {
		t.Fatalf("the handler was given a %T, which cannot be hijacked; the real chain gives it one that can", seen)
	}
	if _, _, err := hijacker.Hijack(); err == nil {
		t.Error("Hijack reported success without reaching the underlying ResponseWriter")
	}
	if !rec.hijacked {
		t.Error("Hijack did not reach the underlying ResponseWriter, so no connection upgrade is possible")
	}
}
