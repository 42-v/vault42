package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheRequestLogCannotBeForgedThroughTheRequestPath is the call site the
// helper's own test names and never reached.
//
// internal/httputil/safelog_test.go justifies pinning SafeLogValue by saying
// that internal/middleware "puts that path through SafeLogValue on every
// request". It then asserts eighteen table cases against the helper and nothing
// against the middleware, so deleting the call from Logger left this package
// green — the helper was pinned, the call site was not, and the sentence
// connecting them was the only thing holding the claim up.
//
// The path is the whole attack surface here. A client chooses the request
// target, the target is percent-decoded into r.URL.Path before a handler sees
// it, and the log line is written after the handler returns. So %0a in a URL is
// a newline in a log record, and a reader tailing the log sees a second entry
// that nothing in this process wrote.
//
// tests/compliance asserts the same property structurally, over every log call
// in the tree. This one is here because a change to Logger is made by somebody
// running this package's tests.
func TestTheRequestLogCannotBeForgedThroughTheRequestPath(t *testing.T) {
	cases := map[string]struct{ encoded, decoded string }{
		"LF forges a second record":              {"%0a", "\n"},
		"CR forges a second record":              {"%0d", "\r"},
		"NUL truncates the record for a shipper": {"%00", "\x00"},
		"ESC drives the reader's terminal":       {"%1b", "\x1b"},
		"backspace rewrites the line as drawn":   {"%08", "\x08"},
		"U+0085 NEL splits a record":             {"%c2%85", ""},
		"U+2028 splits a record for a shipper":   {"%e2%80%a8", " "},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			target := "/api/users" + tc.encoded + "ADMIN-LOGIN-SUCCEEDED"

			out := captureLog(t, func() {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				// The premise: the character really does reach r.URL.Path.
				// Without this the test could pass because net/http rejected
				// the target, which proves nothing about the encoder.
				if !strings.Contains(req.URL.Path, tc.decoded) {
					t.Fatalf("URL.Path = %q, which does not carry the character under test; the "+
						"request never reproduced the attack", req.URL.Path)
				}
				Logger(ok200).ServeHTTP(httptest.NewRecorder(), req)
			})

			// log.Printf terminates the record itself, so the record is what is
			// asserted on, not the terminator.
			record := strings.TrimSuffix(out, "\n")

			if !strings.Contains(record, "/api/users") {
				t.Fatalf("log = %q, want the request line; Logger wrote none, so there is nothing "+
					"to assert about", out)
			}
			if strings.Contains(record, tc.decoded) {
				t.Errorf("log = %q, which still carries the raw %q the client chose. Logger must "+
					"put r.URL.Path through httputil.SafeLogValue.", out, tc.decoded)
			}
			if got := strings.Count(record, "\n"); got != 0 {
				t.Errorf("the request path forged %d extra log record(s):\n%s", got, out)
			}
		})
	}
}
