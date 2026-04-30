package middleware

import (
	"log"
	"net/http"
	"net/url"
)

// isLocalhostOrigin checks whether an origin is a localhost address.
// Accepts http(s)://localhost[:port] and http(s)://127.0.0.1[:port].
func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1"
}

// CORS returns a CORS middleware. It supports a primary origin, optional
// additional origins (comma-separated in config), and an allow-all dev mode.
func CORS(allowedOrigin string, additionalOrigins []string, allowAll bool) func(http.Handler) http.Handler {
	if allowAll {
		log.Println("SECURITY WARNING: CORS allow-all mode is active — localhost origins only")
	}
	// Build lookup set for O(1) matching
	origins := make(map[string]bool)
	if allowedOrigin != "" {
		origins[allowedOrigin] = true
	}
	for _, o := range additionalOrigins {
		if o != "" {
			origins[o] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := ""
			reqOrigin := r.Header.Get("Origin")
			if allowAll {
				// In dev mode, only reflect localhost origins instead of any origin.
				// This prevents exploitation if a dev server is accidentally exposed.
				if reqOrigin != "" && isLocalhostOrigin(reqOrigin) {
					origin = reqOrigin
				} else if reqOrigin == "" {
					origin = "*"
				}
				// Non-localhost origin in dev mode — reject by not setting ACAO.
				// Note: wildcard ("*") above is safe because Access-Control-Allow-Credentials
				// is only set for specific (non-wildcard) origins — credentials are never leaked.
			} else if reqOrigin != "" && origins[reqOrigin] {
				origin = reqOrigin
			} else if reqOrigin == "" {
				origin = allowedOrigin
			}

			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
			if origin != "" && origin != "*" {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
