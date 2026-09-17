package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/42-v/vault42/internal/crypto"
)

type ctxKey string

// RequestIDKey is the context key used to store the unique request identifier.
const RequestIDKey ctxKey = "request_id"

// fallbackSeq numbers the ids issued on the degraded path below. It replaces a
// clock reading, and the width it is rendered at is the width that reading had.
var fallbackSeq atomic.Uint64

// RequestID adds a unique request ID to each request context and response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := crypto.RandomHex(16)
		if err != nil {
			// The RNG is gone and this middleware runs before everything else,
			// so giving up here stops the service answering at all. It degrades
			// to a counter instead.
			//
			// It used to degrade to time.Now().UnixNano(), packed big-endian and
			// hex-encoded, under a comment saying the constant length avoided
			// leaking nanosecond precision. Fixed width removes a length
			// side-channel and nothing else: the encoding is lossless, so the
			// server's nanosecond clock was published verbatim in X-Request-ID,
			// one unhexlify and one 8-byte big-endian unpack from the exact
			// reading. A counter is not a clock and leaks nothing about one.
			//
			// The cost is that ids stop being unique across processes on this
			// path, which is acceptable: reaching it requires the OS CSPRNG to
			// have failed, and a request id's job is to join the log lines of
			// one request inside one process. The "fallback-" prefix is what
			// tells an operator which regime an id came from.
			id = fmt.Sprintf("fallback-%016x", fallbackSeq.Add(1))
		}
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}
