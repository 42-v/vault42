package middleware

import (
	"net/http"
	"strings"
)

// MaxBodyWithExemptions limits the request body size, skipping the limit for
// paths matching any of the given prefixes (e.g., "/user/blobs" for file
// uploads that enforce their own size limit via MaxBytesReader). GET and HEAD
// are exempt whatever the prefix list says, since they should not carry a body
// and static assets served by the embedded frontend must pass through.
//
// This is the only body limit internal/server installs. A no-exemption sibling,
// MaxBody, used to sit above it with no caller outside tests; the body-limit
// attack suite built its own copy of that one and certified it, so the deployed
// exemption list was never covered by anything.
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
