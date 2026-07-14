package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequestID_SetsHeaderAndContext exercises the RequestID middleware's main
// path: a fresh id is generated, echoed in the X-Request-ID header, and made
// available to downstream handlers via GetRequestID.
func TestRequestID_SetsHeaderAndContext(t *testing.T) {
	var fromCtx string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fromCtx = GetRequestID(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	hdr := rec.Header().Get("X-Request-ID")
	if hdr == "" {
		t.Fatal("X-Request-ID header not set")
	}
	if fromCtx == "" {
		t.Fatal("GetRequestID returned empty inside the handler")
	}
	if hdr != fromCtx {
		t.Errorf("header id %q != context id %q", hdr, fromCtx)
	}
}
