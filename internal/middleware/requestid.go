package middleware

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/crypto"
)

type ctxKey string

// RequestIDKey is the context key used to store the unique request identifier.
const RequestIDKey ctxKey = "request_id"

// RequestID adds a unique request ID to each request context and response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := crypto.RandomHex(16)
		if err != nil {
			// Fallback: constant-length hex to avoid leaking nanosecond precision
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
			id = "fallback-" + hex.EncodeToString(buf[:])
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
