package middleware

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// The fallback id must not carry the clock it used to be built from.
//
// The old implementation packed time.Now().UnixNano() big-endian and
// hex-encoded it, under a comment claiming the constant length avoided leaking
// nanosecond precision. It did not: the encoding is lossless, so the reading was
// published verbatim in X-Request-ID -- one unhexlify and one 8-byte big-endian
// unpack away. The test above only measured the id's LENGTH, which is exactly
// what fixed-width hex preserves, so it passed on both implementations.
//
// This asserts the property instead of the shape: consecutive fallback ids
// differ by exactly one. No clock reading can do that. Two successive
// time.Now().UnixNano() calls are hundreds or thousands of nanoseconds apart,
// and never one.
func TestFallbackRequestIDIsNotAClockReading(t *testing.T) {
	prev := rand.Reader
	rand.Reader = mwcDeadEntropy{}
	defer func() { rand.Reader = prev }()

	issue := func() string {
		h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Header().Get("X-Request-ID")
	}

	parse := func(t *testing.T, id string) uint64 {
		t.Helper()
		hexPart := strings.TrimPrefix(id, "fallback-")
		if hexPart == id {
			t.Fatalf("id %q is not a fallback id", id)
		}
		n, err := strconv.ParseUint(hexPart, 16, 64)
		if err != nil {
			t.Fatalf("fallback id %q is not 16 hex digits: %v", id, err)
		}
		return n
	}

	first := parse(t, issue())
	second := parse(t, issue())

	if second != first+1 {
		t.Errorf("consecutive fallback ids are %d and %d, a gap of %d. A counter advances by "+
			"one; a clock does not. This gap is the nanoseconds between the two requests, "+
			"which means the reading is recoverable from the response header.",
			first, second, second-first)
	}

	// And the value must not be a plausible wall-clock reading. UnixNano for any
	// date after 2001 is above 1e18; a counter starts at 1.
	const nanosIn2001 = uint64(978_307_200_000_000_000)
	if first > nanosIn2001 {
		t.Errorf("the first fallback id of the process is %d, which is in the range of a "+
			"UnixNano reading. The id is derived from the clock.", first)
	}
}
