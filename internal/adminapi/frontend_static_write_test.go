package adminapi

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// staticBrokenWriter accepts headers and then fails on the body write, which
// is what a client that disconnects mid-download looks like to the handler.
type staticBrokenWriter struct {
	http.ResponseWriter
}

func (staticBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A client vanishing while an existing asset streams must be logged and
// survived, never panicked on.
func TestServeStatic_WriteErrorIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	f := NewFrontendHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/static/admin.js", nil)
	rec := httptest.NewRecorder()

	f.ServeStatic(staticBrokenWriter{rec}, req)

	if got := rec.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/javascript; charset=utf-8", got)
	}
	if !strings.Contains(buf.String(), "admin-gateway: static write error: broken pipe") {
		t.Errorf("log = %q, want the static write error entry", buf.String())
	}
}
