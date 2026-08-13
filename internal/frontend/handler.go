package frontend

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves the embedded Vue SPA.
// API routes (/auth/*, /user/*, /client/*, /.well-known/*, /healthz, /readyz)
// take priority via ServeMux specificity — this handler only serves the catch-all "/".
// Any path that doesn't match a static file returns index.html for client-side routing.
func Handler() http.Handler {
	fsys, _ := fs.Sub(Assets, "dist")
	fileServer := http.FileServer(http.FS(fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the exact file (JS, CSS, images, etc.)
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := fsys.Open(path); err == nil {
				// File existence probe; close error is non-actionable.
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback: serve index.html for all other paths (client-side routing).
		//
		// The rewrite happens on a copy because the middleware wrapped around this
		// handler still holds the original request and reads r.URL.Path after
		// ServeHTTP returns: middleware.Logger writes the access-log line there, and
		// honeypot.LoggingMiddleware writes the record the honeypot profile exists to
		// collect. Every unrouted path lands in this branch, so rewriting in place
		// would file every scan probe under "/" and lose the one field that says what
		// was probed.
		fallback := *r
		spaRoot := *r.URL
		spaRoot.Path = "/"
		spaRoot.RawPath = ""
		fallback.URL = &spaRoot
		fileServer.ServeHTTP(w, &fallback)
	})
}
