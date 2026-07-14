package adminapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// brokenWriter accepts headers and then fails on the body, which is what a client that
// disconnects mid-response looks like from the handler's side.
type brokenWriter struct {
	http.ResponseWriter
}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A client vanishing halfway through a response is routine — a closed laptop, a dropped
// network, a reverse proxy timing out. It must not take the admin gateway down with it.
//
// Both the rendered pages and the embedded static assets write directly to the socket, so
// both need the write error handled rather than ignored or panicked on. This is the admin
// break-glass surface: a panic here is a process death at the moment an operator is
// reaching for the tool.
func TestFrontend_ClientDisconnectMidResponseDoesNotPanic(t *testing.T) {
	f := NewFrontendHandler()

	t.Run("a rendered page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
		w := brokenWriter{httptest.NewRecorder()}

		f.LoginPage(w, req) // must not panic
	})

	t.Run("a static asset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/static/app.js", nil)
		req.SetPathValue("path", "app.js")
		w := brokenWriter{httptest.NewRecorder()}

		f.ServeStatic(w, req) // must not panic
	})
}
