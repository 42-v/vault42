package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureBridgeLog runs fn with the standard logger redirected and returns what
// it wrote.
func captureBridgeLog(t *testing.T, fn func()) string {
	t.Helper()

	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	fn()
	return buf.String()
}

// TestBridgeLogsCarryNoFullClientAddress pins the bridge half of the same
// property internal/middleware now holds.
//
// The bridge legitimately works in whole addresses: it flags them, stores them
// in Redis for the flag TTL, serves them from /bridge/flags and posts them to
// the webhook. Those are the authenticated and configured channels an operator
// asked for. The process log is the one that is read by everybody who can reach
// a log shipper, and it is the one that was carrying the same value for free.
//
// So the split is by channel, not by value: the admin API and the webhook keep
// the full address because an operator cannot act on a /24, and the log keeps
// the masked network because a reader tailing it only needs to know which
// network is being noisy. Nothing the bridge can do is lost.
func TestBridgeLogsCarryNoFullClientAddress(t *testing.T) {
	const (
		clientIP = "203.0.113.201"
		masked   = "203.0.113.0"
	)

	t.Run("decoy hit", func(t *testing.T) {
		dh := NewDecoyHandler(NewFlagStore(time.Hour, ""), nil)

		out := captureBridgeLog(t, func() {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/wp-admin", nil)
			dh.ServeDecoy(httptest.NewRecorder(), req, clientIP, "wp-login.html", false)
		})

		assertMaskedOnly(t, out, "bridge: decoy hit", clientIP, masked)
	})

	t.Run("admin flag", func(t *testing.T) {
		ah := NewAdminHandler(NewFlagStore(time.Hour, ""), "secret-token")

		out := captureBridgeLog(t, func() {
			req := httptest.NewRequest(http.MethodPost, "/bridge/flag",
				strings.NewReader(`{"ip":"`+clientIP+`","reason":"manual"}`))
			req.Header.Set("Authorization", "Bearer secret-token")
			rec := httptest.NewRecorder()
			ah.ServeFlag(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; the flag was refused so there is no log line", rec.Code)
			}
			// The response body is an operator-facing channel and keeps the
			// address it was asked to act on.
			if !strings.Contains(rec.Body.String(), clientIP) {
				t.Errorf("admin response = %q, want the full address; masking the operator's own "+
					"answer to their own request removes the only way to confirm what was flagged",
					rec.Body.String())
			}
		})

		assertMaskedOnly(t, out, "bridge: admin flagged", clientIP, masked)
	})

	t.Run("admin unflag", func(t *testing.T) {
		fs := NewFlagStore(time.Hour, "")
		fs.Flag(clientIP, "manual", 100)
		ah := NewAdminHandler(fs, "secret-token")

		out := captureBridgeLog(t, func() {
			req := httptest.NewRequest(http.MethodDelete, "/bridge/flag",
				strings.NewReader(`{"ip":"`+clientIP+`"}`))
			req.Header.Set("Authorization", "Bearer secret-token")
			rec := httptest.NewRecorder()
			ah.ServeFlag(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; the unflag was refused so there is no log line", rec.Code)
			}
		})

		assertMaskedOnly(t, out, "bridge: admin unflagged", clientIP, masked)
	})
}

// TestAutoFlagLogsCarryNoFullClientAddress covers the three proxy.go lines,
// which are the ones that run in volume: an automated scan writes one per
// request for as long as it lasts.
func TestAutoFlagLogsCarryNoFullClientAddress(t *testing.T) {
	const (
		clientIP = "198.51.100.77"
		masked   = "198.51.100.0"
	)

	realUpstream := newUpstream(t, "real", nil)
	honeypot := newUpstream(t, "honeypot", nil)

	b, err := NewBridge(&Config{
		RealUpstream:     realUpstream.srv.URL,
		HoneypotUpstream: honeypot.srv.URL,
		FlagTTL:          time.Hour,
		RateWindow:       time.Minute,
		LoginFailWindow:  time.Minute,
		RateThreshold:    1000,
		FlagThreshold:    30,
		LogLevel:         "debug",
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	// A scanner user agent scores above FlagThreshold on its first request, so
	// one call produces the auto-flag line and the next produces the
	// already-flagged routing line.
	out := captureBridgeLog(t, func() {
		for range 2 {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			req.RemoteAddr = clientIP + ":5555"
			req.Header.Set("User-Agent", "sqlmap/1.7")
			b.ServeHTTP(httptest.NewRecorder(), req)
		}
	})

	for _, want := range []string{"bridge: auto-flagged", "bridge: routing flagged"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log = %q, want it to contain %q; the branch under test did not run", out, want)
		}
	}
	assertMaskedOnly(t, out, "bridge: auto-flagged", clientIP, masked)
}

// TestLoginFailureAutoFlagLogCarriesNoFullClientAddress covers the third
// proxy.go line, which fires from ModifyResponse rather than ServeHTTP.
func TestLoginFailureAutoFlagLogCarriesNoFullClientAddress(t *testing.T) {
	const (
		clientIP = "192.0.2.55"
		masked   = "192.0.2.0"
	)

	realUpstream := newUpstream(t, "real", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	honeypot := newUpstream(t, "honeypot", nil)

	b, err := NewBridge(&Config{
		RealUpstream:       realUpstream.srv.URL,
		HoneypotUpstream:   honeypot.srv.URL,
		FlagTTL:            time.Hour,
		RateWindow:         time.Minute,
		LoginFailWindow:    time.Minute,
		RateThreshold:      1000,
		FlagThreshold:      20,
		LoginFailThreshold: 1,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	out := captureBridgeLog(t, func() {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/login", nil)
		req.RemoteAddr = clientIP + ":5555"
		req.Header.Set("User-Agent", benignUA)
		b.ServeHTTP(httptest.NewRecorder(), req)
	})

	assertMaskedOnly(t, out, "login_failures=", clientIP, masked)
}

// assertMaskedOnly is the shared shape of every case above: the named line ran,
// it does not carry the whole address, and it does carry the network.
func assertMaskedOnly(t *testing.T, out, marker, full, masked string) {
	t.Helper()

	if !strings.Contains(out, marker) {
		t.Fatalf("log = %q, want it to contain %q; the branch under test did not run", out, marker)
	}
	if strings.Contains(out, full) {
		t.Errorf("log = %q, which carries the full client address %s. The full address belongs "+
			"on the admin API and the webhook, not in the process log.", out, full)
	}
	if !strings.Contains(out, masked) {
		t.Errorf("log = %q, want the masked network %s; a reader still has to be able to tell "+
			"which network the line is about.", out, masked)
	}
}

// TestAnUnparseableAddressIsLoggedAsAConstant closes the last way a raw value
// reaches the process log through the masking.
//
// /bridge/flag takes its address out of a JSON body and never checks that it is
// one: FlagStore is keyed by string, so anything non-empty can be flagged and
// then unflagged, and whatever it was goes to log.Printf. obfuscatedIP's job is
// that the log line names a network and nothing else, and a value it cannot
// parse has no network to name. Returning it unchanged would mean the one input
// the masking cannot understand is the one input it passes through — which is
// the shape of every mask that has ever failed open.
//
// The constant is also the right answer for the operator: "invalid_ip" says the
// value was not an address, which is information, where an echo of the string
// would just be the string.
func TestAnUnparseableAddressIsLoggedAsAConstant(t *testing.T) {
	const junk = "not-an-address-198.51.100.9"

	fs := NewFlagStore(time.Hour, "")
	fs.Flag(junk, "manual", 100)
	ah := NewAdminHandler(fs, "secret-token")

	out := captureBridgeLog(t, func() {
		req := httptest.NewRequest(http.MethodDelete, "/bridge/flag",
			strings.NewReader(`{"ip":"`+junk+`"}`))
		req.Header.Set("Authorization", "Bearer secret-token")
		rec := httptest.NewRecorder()
		ah.ServeFlag(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; the unflag was refused so there is no log line", rec.Code)
		}
	})

	if !strings.Contains(out, "bridge: admin unflagged") {
		t.Fatalf("log = %q, want it to contain the unflag line; the branch under test did not run", out)
	}
	if strings.Contains(out, junk) {
		t.Errorf("log = %q, which echoes the caller's string verbatim. A value the mask cannot parse "+
			"is the one value it must not pass through.", out)
	}
	if !strings.Contains(out, "invalid_ip") {
		t.Errorf("log = %q, want the invalid_ip constant so the line still says what happened", out)
	}
}
