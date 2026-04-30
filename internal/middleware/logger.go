package middleware

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/httputil"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it implements http.Flusher.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter if it implements http.Hijacker.
// Required for WebSocket support through the logging middleware.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Logger logs HTTP requests with timing. Health probes are silenced.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)

		// Don't log K8s health probes — they spam the logs
		p := r.URL.Path
		if p == "/healthz" || p == "/readyz" {
			return
		}

		log.Printf("%s %s %d %s [%s]", // #nosec G706 -- values sanitized via SafeLogValue (strips control chars)
			r.Method, httputil.SafeLogValue(r.URL.Path), rec.status,
			time.Since(start).Round(time.Microsecond),
			GetRequestID(r.Context()),
		)
	})
}
