package adminapi

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CWE-117 on the one path that exists to record attackers.
//
// The admin gateway's LocalOnly middleware logs a CRITICAL line carrying the
// caller's RemoteAddr and User-Agent when a non-loopback client reaches it. That
// path is unauthenticated by construction — it fires before any credential is
// looked at — and the User-Agent is whatever the client sent. The sanitizer it
// used stripped only \n, \r and \t, so ESC, NUL, backspace, U+0085 (NEL) and
// U+2028 all reached the log: a log shipper splits records on NEL and U+2028 as
// readily as on a newline, and a terminal acts on ESC and BS as it draws.
//
// httputil.SafeLogValue already neutralizes the whole set and is tested; this
// pins that the admin gateway uses it.
func TestLocalOnly_UserAgentCannotForgeALogRecord(t *testing.T) {
	for name, bad := range map[string]string{
		"ESC (opens a terminal control sequence)": "curl\x1b[2Kadmin-gateway: all clear",
		"NUL":                                    "curl\x00admin-gateway: all clear",
		"backspace (rewrites the line as drawn)": "curl\x08\x08\x08admin-gateway: all clear",
		"vertical tab":                           "curl\x0badmin-gateway: all clear",
		"form feed":                              "curl\x0cadmin-gateway: all clear",
		"U+0085 NEL (a record separator)":        "curladmin-gateway: all clear",
		"U+009B (8-bit CSI)":                     "curladmin-gateway: all clear",
		"U+2028 line separator":                  "curl admin-gateway: all clear",
		"U+2029 paragraph separator":             "curl admin-gateway: all clear",
	} {
		t.Run(name, func(t *testing.T) {
			var logged bytes.Buffer
			old := log.Writer()
			log.SetOutput(&logged)
			t.Cleanup(func() { log.SetOutput(old) })

			h := LocalOnly(false, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			r := httptest.NewRequest(http.MethodGet, "/admin/config", nil)
			r.RemoteAddr = "203.0.113.9:4444"
			r.Header.Set("User-Agent", bad)

			func() {
				defer func() { _ = recover() }() // the killswitch re-panics by design
				h.ServeHTTP(httptest.NewRecorder(), r)
			}()

			out := logged.String()
			if out == "" {
				t.Fatal("the non-loopback connection was not logged at all")
			}
			for _, r := range out {
				if r < 0x20 && r != '\n' || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == ' ' || r == ' ' {
					t.Fatalf("a record-forging character reached the log: %q in %q", r, out)
				}
			}
			if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
				t.Errorf("the user agent forged a second log record:\n%s", out)
			}
		})
	}
}
