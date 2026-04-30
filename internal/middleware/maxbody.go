package middleware

import (
	"net/http"
	"strings"
)

// MaxBody limits the request body size. GET and HEAD requests are exempt
// since they should not carry a body (and static assets served by the
// embedded frontend need to pass through without body-size restrictions).
func MaxBody(maxBytes int64) func(http.Handler) http.Handler {
	return MaxBodyWithExemptions(maxBytes, nil)
}

// MaxBodyWithExemptions limits the request body size but skips the limit
// for paths matching any of the given prefixes (e.g., "/user/blobs" for
// file uploads that enforce their own size limit via MaxBytesReader).
func MaxBodyWithExemptions(maxBytes int64, exemptPrefixes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				exempt := false
				for _, prefix := range exemptPrefixes {
					if strings.HasPrefix(r.URL.Path, prefix) {
						exempt = true
						break
					}
				}
				if !exempt {
					r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
