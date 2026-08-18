package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"
)

// The bridge is the gateway the vault's trust model assumes exists. Several
// upstream controls believe a header purely because their peer is a declared
// proxy: the tenant slug, the TLS fingerprint that binds a bearer token to a
// device, the real-IP header and the geo header. The bridge stamped three
// headers of its own and deleted none of the client's, so every one of those
// controls could be handed its answer by the caller it was checking.

// upstreamEcho starts a fake upstream that records the headers it was given.
func upstreamEcho(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header { return got }
}

func testBridge(t *testing.T, mutate func(*Config)) (*Bridge, func() http.Header) {
	t.Helper()
	realUp, headers := upstreamEcho(t)
	honeypot, _ := upstreamEcho(t)
	cfg := &Config{
		RealUpstream:       realUp.URL,
		HoneypotUpstream:   honeypot.URL,
		RateThreshold:      60,
		RateWindow:         time.Minute,
		LoginFailThreshold: 5,
		LoginFailWindow:    15 * time.Minute,
		FlagTTL:            time.Hour,
		FlagThreshold:      100,
		MaxBodyBytes:       1 << 20,
		MaxInflight:        512,
	}
	if mutate != nil {
		mutate(cfg)
	}
	b, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	t.Cleanup(b.Close)
	return b, headers
}

// TestBridgeStripsHeadersTheUpstreamTrustsByPeer is the F-18 regression.
func TestBridgeStripsHeadersTheUpstreamTrustsByPeer(t *testing.T) {
	b, headers := testBridge(t, func(c *Config) {
		c.RealIPHeader = "CF-Connecting-IP"
		c.StripHeaders = []string{"X-Custom-Fingerprint"}
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	forged := map[string]string{
		"X-Vault-App":           "victim-tenant",
		"X-TLS-Fingerprint":     "t13d1516h2_victimja4",
		"CF-Connecting-IP":      "9.9.9.9",
		"CF-IPCountry":          "XX",
		"True-Client-IP":        "9.9.9.9",
		"X-Client-IP":           "9.9.9.9",
		"X-Forwarded-Host":      "evil.example",
		"X-Custom-Fingerprint":  "operator-renamed",
		"X-Country-Code":        "XX",
		"X-GeoIP-Country":       "XX",
		"X-Harmless-Passthough": "keep-me",
		"X-Forwarded-For":       "192.0.2.1",
	}
	for k, v := range forged {
		req.Header.Set(k, v)
	}

	b.ServeHTTP(httptest.NewRecorder(), req)

	got := headers()
	if got == nil {
		t.Fatal("the upstream never saw the request")
	}
	for k := range forged {
		if k == "X-Harmless-Passthough" || k == "X-Forwarded-For" {
			continue
		}
		if v := got.Get(k); v != "" && v == forged[k] {
			t.Errorf("%s reached the upstream as %q; the bridge must be the sole author of "+
				"anything the upstream trusts because its peer sent it", k, v)
		}
	}
	if got.Get("X-Harmless-Passthough") != "keep-me" {
		t.Error("an unrelated header was stripped; the strip list is not a denylist for everything")
	}
	// The bridge still authors its own attribution.
	if got.Get("X-Real-IP") != "203.0.113.5" {
		t.Errorf("X-Real-IP = %q, want the peer address the bridge resolved", got.Get("X-Real-IP"))
	}
	// ReverseProxy appends the peer address to X-Forwarded-For after the
	// bridge has stamped it, so the value is the bridge's own twice over. What
	// matters is that nothing the client wrote survives in it.
	xff := got.Get("X-Forwarded-For")
	if !strings.HasPrefix(xff, "203.0.113.5") {
		t.Errorf("X-Forwarded-For = %q, want it to start with the bridge's own stamp", xff)
	}
	if strings.Contains(xff, "9.9.9.9") || strings.Contains(xff, "192.0.2.1") {
		t.Errorf("X-Forwarded-For = %q still carries a client-supplied hop", xff)
	}
}

// TestBridgeRealIPBranchValidatesLikeTheXFFBranch is the F-21 regression. The
// real-IP branch used to return the raw header: junk minted one fresh scoring
// identity per request, so a scanner rotating a garbage value was never flagged.
func TestBridgeRealIPBranchValidatesLikeTheXFFBranch(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) {
		c.RealIPHeader = "X-Client-IP"
		c.TrustedProxies = mustCIDRs(t, "10.0.0.0/8")
	})

	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{"junk is refused and the peer is used", "not-an-ip", "10.0.0.1"},
		{"a valid address is honored", "203.0.113.9", "203.0.113.9"},
		{"the rightmost element wins", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"a trusted hop is skipped", "203.0.113.9, 10.0.0.7", "203.0.113.9"},
		{"junk after a real hop does not resurrect the client value", "203.0.113.9, bogus", "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:443"
			req.Header.Set("X-Client-IP", tc.header)
			if got := b.clientIP(req); got != tc.want {
				t.Fatalf("clientIP(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestBridgeJoinsEveryForwardedForLine is the F-24 regression. Header.Get reads
// the FIRST field line only, so a peer that appends X-Forwarded-For as its own
// line left the walk reading the client's line and dropping the real hop.
func TestBridgeJoinsEveryForwardedForLine(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) {
		c.TrustedProxies = mustCIDRs(t, "10.0.0.0/8")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Add("X-Forwarded-For", "192.0.2.66")  // the client's own line
	req.Header.Add("X-Forwarded-For", "203.0.113.9") // appended by the real hop

	if got := b.clientIP(req); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want 203.0.113.9 — only the first header line was read, so the "+
			"client's own value won", got)
	}
}

// TestBridgeCapsXFFHopWalk is the F10 regression: the walk is bounded by a hop
// count, not by MaxHeaderBytes.
func TestBridgeCapsXFFHopWalk(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) {
		c.TrustedProxies = mustCIDRs(t, "10.0.0.0/8")
	})

	parts := make([]string, 4000)
	parts[0] = "203.0.113.50"
	for i := 1; i < len(parts); i++ {
		parts[i] = "10.0.0.2"
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", strings.Join(parts, ", "))

	// Every one of the last maxXFFHops entries is a trusted hop, so the walk
	// runs out of budget and falls through to the peer rather than parsing
	// four thousand addresses.
	if got := b.clientIP(req); got != "10.0.0.1" {
		t.Fatalf("clientIP = %q; a 4000-hop header should be capped at %d and fall through to the peer",
			got, maxXFFHops)
	}
}

// TestBridgeDoesNotFlagACoercedBrowser is the F-19 regression. A cross-site
// <img> tag pointed at a decoy path used to flag whoever loaded the attacker's
// page, and their whole NAT egress with them, for FlagTTL.
func TestBridgeDoesNotFlagACoercedBrowser(t *testing.T) {
	b, _ := testBridge(t, nil)

	coerced := httptest.NewRequest(http.MethodGet, "/wp-admin/x.png", nil)
	coerced.RemoteAddr = "203.0.113.77:5000"
	coerced.Header.Set("User-Agent", "Mozilla/5.0")
	coerced.Header.Set("Sec-Fetch-Site", "cross-site")
	coerced.Header.Set("Sec-Fetch-Mode", "no-cors")
	coerced.Header.Set("Sec-Fetch-Dest", "image")
	b.ServeHTTP(httptest.NewRecorder(), coerced)

	if b.flags.IsFlagged("203.0.113.77") {
		t.Fatal("a cross-site no-cors subresource load flagged the visitor; an attacker only has " +
			"to put an <img> tag on any page to route a third party to the honeypot")
	}

	// A scanner walking the same path directly still flags.
	direct := httptest.NewRequest(http.MethodGet, "/wp-admin/x.png", nil)
	direct.RemoteAddr = "198.51.100.4:5000"
	direct.Header.Set("User-Agent", "curl/8.0")
	b.ServeHTTP(httptest.NewRecorder(), direct)

	if !b.flags.IsFlagged("198.51.100.4") {
		t.Fatal("a direct decoy hit was not flagged; the coercion check must not disable detection")
	}

	// A cross-site NAVIGATION still flags: the visitor sees the page, so it is
	// not the silent coercion the check exists for, and it is what a scanner
	// following links produces.
	nav := httptest.NewRequest(http.MethodGet, "/wp-admin/", nil)
	nav.RemoteAddr = "198.51.100.5:5000"
	nav.Header.Set("User-Agent", "Mozilla/5.0")
	nav.Header.Set("Sec-Fetch-Site", "cross-site")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	nav.Header.Set("Sec-Fetch-Dest", "document")
	b.ServeHTTP(httptest.NewRecorder(), nav)

	if !b.flags.IsFlagged("198.51.100.5") {
		t.Fatal("a cross-site navigation to a decoy was not flagged; only forced subresource " +
			"loads are meant to be exempt")
	}

	// no-cors with a document destination is not a shape a browser produces for
	// a subresource, so it does not earn the exemption either.
	odd := httptest.NewRequest(http.MethodGet, "/wp-admin/", nil)
	odd.RemoteAddr = "198.51.100.6:5000"
	odd.Header.Set("User-Agent", "Mozilla/5.0")
	odd.Header.Set("Sec-Fetch-Site", "cross-site")
	odd.Header.Set("Sec-Fetch-Mode", "no-cors")
	odd.Header.Set("Sec-Fetch-Dest", "document")
	b.ServeHTTP(httptest.NewRecorder(), odd)

	if !b.flags.IsFlagged("198.51.100.6") {
		t.Fatal("no-cors with a document destination was exempted; the exemption is for " +
			"subresource destinations only")
	}
}

// TestBridgeTruncatesTheDecoyReason is the F-20 regression: a 1 MB request line
// became a 1 MB flag reason held for FlagTTL and a 1 MB webhook body.
func TestBridgeTruncatesTheDecoyReason(t *testing.T) {
	b, _ := testBridge(t, nil)

	long := "/wp-admin/" + strings.Repeat("a", 200_000)
	req := httptest.NewRequest(http.MethodGet, long, nil)
	req.RemoteAddr = "198.51.100.9:5000"
	req.Header.Set("User-Agent", "curl/8.0")
	b.ServeHTTP(httptest.NewRecorder(), req)

	entries := b.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag entries = %d, want the decoy hit to be flagged once", len(entries))
	}
	if len(entries[0].Reason) > maxReasonPathLen+len("decoy:...") {
		t.Fatalf("flag reason is %d bytes, want it truncated near %d — it is held for FlagTTL in "+
			"memory and in Redis, and copied into the webhook body", len(entries[0].Reason), maxReasonPathLen)
	}
}

// TestBridgeReadyzNamesNothingToAnAnonymousCaller is the F-22 regression.
func TestBridgeReadyzNamesNothingToAnAnonymousCaller(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) { c.AdminToken = "s3cret" })

	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous readyz = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "honeypot") {
		t.Fatalf("anonymous readyz body names the honeypot: %q", body)
	}

	authed := httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil)
	authed.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	b.ServeHTTP(rec, authed)
	if !strings.Contains(rec.Body.String(), "honeypot") {
		t.Fatalf("an operator holding the admin token lost the diagnostic body: %q", rec.Body.String())
	}
}

// TestBridgeReadyzCachesItsUpstreamProbes is the other half of F-22: the probe
// was an unmetered 2x amplifier, one upstream request into each upstream per
// anonymous call.
func TestBridgeReadyzCachesItsUpstreamProbes(t *testing.T) {
	var probes int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes++
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	hh := NewHealthHandler(up.URL, up.URL)
	for i := 0; i < 20; i++ {
		hh.Readyz(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil), false)
	}
	if probes > 2 {
		t.Fatalf("20 readiness calls produced %d upstream probes; the cache is not holding", probes)
	}
}

// TestBridgeCapsTheRequestBody is the F6 regression.
func TestBridgeCapsTheRequestBody(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) { c.MaxBodyBytes = 1024 })

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(strings.Repeat("x", 8192)))
	req.RemoteAddr = "203.0.113.30:5000"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)

	// The proxy fails the copy rather than streaming an unbounded body through.
	if rec.Code == http.StatusOK {
		t.Fatalf("an 8 KiB body passed a 1 KiB cap with status %d", rec.Code)
	}
}

// TestBridgeShedsAboveTheInflightCap is the other half of F6: one goroutine and
// one upstream socket per request, with nothing counting them.
func TestBridgeShedsAboveTheInflightCap(t *testing.T) {
	b, _ := testBridge(t, func(c *Config) { c.MaxInflight = 1 })

	// Fill the single slot and hold it.
	b.inflight <- struct{}{}
	defer func() { <-b.inflight }()

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "203.0.113.40:5000"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 shed rather than a queued goroutine", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a shed request carried no Retry-After")
	}
}

// TestBridgeUpstreamTransportIsBounded pins the transport limits, because a
// default transport sets neither a connection cap nor a response-header
// deadline and that is what turns a silent upstream into an unbounded
// connection table.
func TestBridgeUpstreamTransportIsBounded(t *testing.T) {
	b, _ := testBridge(t, nil)

	for name, p := range map[string]*httputil.ReverseProxy{
		"real":     b.realProxy,
		"honeypot": b.honeypotProxy,
	} {
		tr, ok := p.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s proxy uses %T, want a configured *http.Transport (nil means http.DefaultTransport, "+
				"which has neither a connection cap nor a response-header deadline)", name, p.Transport)
		}
		if tr.MaxConnsPerHost == 0 {
			t.Errorf("%s transport has no MaxConnsPerHost", name)
		}
		if tr.ResponseHeaderTimeout == 0 {
			t.Errorf("%s transport has no ResponseHeaderTimeout", name)
		}
		if tr.IdleConnTimeout == 0 {
			t.Errorf("%s transport has no IdleConnTimeout", name)
		}
		if tr.TLSHandshakeTimeout == 0 {
			t.Errorf("%s transport has no TLSHandshakeTimeout", name)
		}
	}
}

// TestSafeLogValueNeutralizesRecordForgery covers the log sanitiser: an address
// arriving in a header the operator declared trusted used to reach log.Printf
// raw, and a U+0085 in it forged a whole record.
func TestSafeLogValueNeutralizesRecordForgery(t *testing.T) {
	got := safeLogValue("203.0.113.1\n2026/01/01 forged: admin login")
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("safeLogValue kept a line break: %q", got)
	}
	if got := safeLogValue("1.2.3.4\u0085forged"); strings.Contains(got, "\u0085") {
		t.Fatalf("safeLogValue kept NEL: %q", got)
	}
	// U+2028 and U+2029 split a record for a log shipper exactly as a newline
	// does. httputil.SafeLogValue was widened to cover them in 27b1735; this
	// copy was written afterwards and was not, so a bridge log line stayed
	// splittable by an attacker-controlled value.
	for name, sep := range map[string]string{"line separator": "\u2028", "paragraph separator": "\u2029"} {
		if got := safeLogValue("1.2.3.4" + sep + "forged"); strings.Contains(got, sep) {
			t.Errorf("safeLogValue kept the unicode %s: %q", name, got)
		}
	}
	long := safeLogValue(strings.Repeat("a", 500))
	if len(long) > 200 {
		t.Fatalf("safeLogValue returned %d bytes, want it truncated", len(long))
	}
	if got := safeLogValue("203.0.113.1"); got != "203.0.113.1" {
		t.Fatalf("safeLogValue mangled an ordinary address: %q", got)
	}
}

// mustCIDRs parses trusted-proxy ranges for a test config.
func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		out = append(out, n)
	}
	return out
}
