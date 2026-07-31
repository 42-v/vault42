package middleware

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mwcDeadEntropy is what a container with a starved or broken RNG source looks like
// to any caller of crypto/rand.
type mwcDeadEntropy struct{}

func (mwcDeadEntropy) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

// RequestID runs before everything else, so if it gave up when crypto/rand failed the
// whole service would stop answering rather than degrade. It has to keep serving, and
// the identifier it falls back to has to stay a fixed-width opaque token: the clock is
// the only entropy left, and a variable-length or human-readable timestamp publishes
// the server's nanosecond clock in a response header on every request.
func TestRequestIDServesRequestsWhenEntropyFails(t *testing.T) {
	prev := rand.Reader
	rand.Reader = mwcDeadEntropy{}
	defer func() { rand.Reader = prev }()

	const wantLen = len("fallback-") + 16

	seen := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		var served bool
		var ctxID string
		h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served = true
			ctxID = GetRequestID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		if !served {
			t.Fatal("the request never reached the handler when crypto/rand failed")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status %d, want 200: a failed RNG read turned into a failed request", rec.Code)
		}

		id := rec.Header().Get("X-Request-ID")
		if id == "" {
			t.Fatal("no X-Request-ID was issued, so the request is untraceable in the audit log")
		}
		if id != ctxID {
			t.Errorf("header id %q and context id %q disagree; logs and responses would not correlate", id, ctxID)
		}
		if !strings.HasPrefix(id, "fallback-") {
			t.Errorf("id %q is not marked as a fallback, so a degraded RNG is invisible downstream", id)
		}
		if len(id) != wantLen {
			t.Errorf("fallback id %q is %d chars, want a fixed %d: variable width leaks the clock it was built from", id, len(id), wantLen)
		}
		if strings.Contains(rec.Body.String(), "entropy") {
			t.Errorf("the RNG failure reached the response body: %q", rec.Body.String())
		}
		seen = append(seen, id)
	}

	if seen[0] == seen[1] {
		t.Errorf("both requests were issued the same fallback id %q; request ids stop identifying requests", seen[0])
	}
}
