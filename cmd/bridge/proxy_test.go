package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// benignUA is a browser user agent that scores zero. Tests that are not about
// automation detection must send it explicitly, because Go's own HTTP client
// identifies as "Go-http-client", which ScoreAutomationUA treats as a scanner.
// Leaving the default in place would quietly flag the test client partway
// through any test that makes more than three requests.
const benignUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// recordedRequest is what an upstream saw, captured before the handler answers
// so assertions can be made on the request the bridge actually produced rather
// than inferred from the response.
type recordedRequest struct {
	Method     string
	Path       string
	RawQuery   string
	Host       string
	Header     http.Header
	Body       []byte
	RemoteAddr string
}

// upstream stands in for one of the two vaults.
type upstream struct {
	name string
	srv  *httptest.Server

	mu   sync.Mutex
	reqs []recordedRequest
}

// newUpstream starts a vault stand-in. A nil handler installs the default, which
// records the request and answers with a JSON document naming itself, so a test
// can tell which of the two upstreams answered by reading the body.
func newUpstream(t *testing.T, name string, h http.HandlerFunc) *upstream {
	t.Helper()

	u := &upstream{name: name}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h != nil {
			u.record(r, nil)
			h(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body) // #nosec G104 -- a read error is captured as a short body
		u.record(r, body)

		w.Header().Set("X-Upstream", u.name)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{%q:%q,%q:%q}", "upstream", u.name, "probe", r.Header.Get("X-Probe"))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) record(r *http.Request, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reqs = append(u.reqs, recordedRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		RawQuery:   r.URL.RawQuery,
		Host:       r.Host,
		Header:     r.Header.Clone(),
		Body:       body,
		RemoteAddr: r.RemoteAddr,
	})
}

func (u *upstream) requests() []recordedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]recordedRequest(nil), u.reqs...)
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

// only returns the single request this upstream received, failing if it saw any
// other number. Most proxy assertions care as much about "exactly one request
// reached the upstream" as about what that request contained.
func (u *upstream) only(t *testing.T) recordedRequest {
	t.Helper()
	reqs := u.requests()
	if len(reqs) != 1 {
		t.Fatalf("%s upstream saw %d requests, want exactly 1", u.name, len(reqs))
	}
	return reqs[0]
}

// fixture is a bridge wired to two live upstreams and exposed on a real
// listener, so tests exercise the whole net/http stack rather than a handler in
// isolation. A proxy's interesting behavior lives in the transport, and a
// httptest.NewRecorder cannot show connection reuse, streaming or hop-by-hop
// header handling.
type fixture struct {
	cfg      *Config
	bridge   *Bridge
	front    *httptest.Server
	real     *upstream
	honeypot *upstream
}

// testConfig is a bridge configuration with detection effectively disabled, so
// that a test which is not about scoring cannot be perturbed by it. Tests about
// detection lower the thresholds explicitly.
func testConfig(realURL, honeypotURL string) *Config {
	return &Config{
		ListenAddr:         "127.0.0.1:0",
		RealUpstream:       realURL,
		HoneypotUpstream:   honeypotURL,
		RateThreshold:      1_000_000,
		RateWindow:         time.Minute,
		LoginFailThreshold: 1_000_000,
		LoginFailWindow:    15 * time.Minute,
		FlagTTL:            time.Hour,
		FlagThreshold:      1_000_000,
		LogLevel:           "info",
	}
}

func newFixture(t *testing.T, realH, honeypotH http.HandlerFunc, mutate func(*Config)) *fixture {
	t.Helper()

	f := &fixture{
		real:     newUpstream(t, "real", realH),
		honeypot: newUpstream(t, "honeypot", honeypotH),
	}
	f.cfg = testConfig(f.real.srv.URL, f.honeypot.srv.URL)
	if mutate != nil {
		mutate(f.cfg)
	}

	b, err := NewBridge(f.cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	f.bridge = b
	t.Cleanup(b.Close)

	f.front = httptest.NewServer(b)
	t.Cleanup(f.front.Close)

	return f
}

// do sends a request through the bridge with a benign user agent unless the
// caller already set one.
func (f *fixture) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", benignUA)
	}
	resp, err := f.front.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// get is the common case: a plain GET whose body is read and closed.
func (f *fixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.front.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// servedBy reports which upstream answered, using the marker the default
// upstream handler writes into its response.
func servedBy(t *testing.T, body string) string {
	t.Helper()
	got := servedByOrEmpty(body)
	if got == "" {
		t.Fatalf("response %q is not an upstream marker document", body)
	}
	return got
}

// servedByOrEmpty is the variant safe to call from a spawned goroutine, where
// t.Fatalf is not, since it would stop that goroutine rather than the test and
// leave a WaitGroup waiting forever.
func servedByOrEmpty(body string) string {
	var doc struct {
		Upstream string `json:"upstream"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return ""
	}
	return doc.Upstream
}

// rawExchange writes bytes straight onto the bridge's listener and reads the
// whole reply. It exists for the cases the net/http client refuses to produce:
// forged hop-by-hop headers and malformed request lines.
func rawExchange(t *testing.T, addr, raw string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close() // #nosec G104 -- test client cleanup

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// TestNewBridgeRejectsUnparseableUpstreams keeps a typo in BRIDGE_REAL_UPSTREAM
// from producing a running bridge that proxies to nowhere. LoadConfig does not
// validate the upstream URLs at all, so NewBridge is the only place the mistake
// can still be caught before the listener opens.
func TestNewBridgeRejectsUnparseableUpstreams(t *testing.T) {
	tests := []struct {
		name     string
		real     string
		honeypot string
	}{
		{"real upstream", "://missing-scheme", "http://honeypot:8080"},
		{"honeypot upstream", "http://real:8080", "http://[::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(tt.real, tt.honeypot)
			b, err := NewBridge(cfg)
			if err == nil {
				b.Close()
				t.Fatal("NewBridge accepted an unparseable upstream URL")
			}
			if b != nil {
				t.Errorf("NewBridge returned %v alongside an error, want nil", b)
			}
		})
	}
}

// TestNewBridgeWiresLoginInspection is a structural check with a behavioral
// consequence: login-failure scoring only ever runs from ModifyResponse on the
// real proxy. If that hook is attached to the honeypot proxy, or to neither,
// failed logins stop scoring and the detection signal documented in
// docs/bridge.md silently disappears. The honeypot must stay unhooked, since
// counting failures against traffic already in the honeypot would only inflate
// scores for IPs that are flagged anyway.
func TestNewBridgeWiresLoginInspection(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	if f.bridge.realProxy.ModifyResponse == nil {
		t.Error("realProxy has no ModifyResponse, so login failures cannot be scored")
	}
	if f.bridge.honeypotProxy.ModifyResponse != nil {
		t.Error("honeypotProxy has a ModifyResponse hook, which would score traffic that is already flagged")
	}
	if f.bridge.webhook != nil {
		t.Error("an empty BRIDGE_WEBHOOK_URL produced a non-nil sender")
	}
}

// ---------------------------------------------------------------------------
// Proxy semantics
// ---------------------------------------------------------------------------

// TestBridgeForwardsRequestFaithfully is the baseline every other proxy
// assertion rests on. The bridge sits in front of an authentication service, so
// a dropped query string or a mangled body is not a cosmetic bug: it is a login
// that fails for a reason no log will explain.
func TestBridgeForwardsRequestFaithfully(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	body := `{"email":"user@example.com","password":"correct horse"}`
	req, err := http.NewRequest(http.MethodPost, f.front.URL+"/auth/login?next=%2Fdashboard&lang=sk", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "session=abc123; theme=dark")
	req.Header.Add("X-Multi", "one")
	req.Header.Add("X-Multi", "two")

	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse

	got := f.real.only(t)
	if got.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.Method)
	}
	if got.Path != "/auth/login" {
		t.Errorf("path = %q, want /auth/login", got.Path)
	}
	if got.RawQuery != "next=%2Fdashboard&lang=sk" {
		t.Errorf("query = %q, want the client's query verbatim", got.RawQuery)
	}
	if string(got.Body) != body {
		t.Errorf("body = %q, want %q", got.Body, body)
	}
	if got.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got.Header.Get("Content-Type"))
	}
	if got.Header.Get("Cookie") != "session=abc123; theme=dark" {
		t.Errorf("Cookie = %q, want it forwarded intact", got.Header.Get("Cookie"))
	}
	if got.Header.Get("User-Agent") != benignUA {
		t.Errorf("User-Agent = %q, want the client's own", got.Header.Get("User-Agent"))
	}
	// A repeated header must arrive as two values, not as one joined string,
	// because the vault's own parsing of Set-Cookie style headers depends on it.
	if multi := got.Header.Values("X-Multi"); len(multi) != 2 || multi[0] != "one" || multi[1] != "two" {
		t.Errorf("X-Multi = %q, want [one two]", multi)
	}
	if f.honeypot.count() != 0 {
		t.Errorf("honeypot saw %d requests for clean traffic, want 0", f.honeypot.count())
	}
}

// TestBridgeOverwritesClientSuppliedRealIP is a security assertion. X-Real-IP is
// what the vault behind the bridge uses to rate limit and to audit, so a client
// that could set its own would be able to attribute its brute force attempt to
// somebody else's address and evade the vault's own per-IP limits.
func TestBridgeOverwritesClientSuppliedRealIP(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	req, err := http.NewRequest(http.MethodGet, f.front.URL+"/whoami", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Real-IP", "9.9.9.9")
	req.Header.Set("X-Forwarded-Proto", "http")

	resp := f.do(t, req)
	resp.Body.Close()

	got := f.real.only(t)
	if ip := got.Header.Get("X-Real-IP"); ip != "127.0.0.1" {
		t.Errorf("X-Real-IP = %q, want the true peer address 127.0.0.1", ip)
	}
	// The bridge terminates the client's TLS upstream of itself, so it asserts
	// https regardless of what the client claimed.
	if proto := got.Header.Get("X-Forwarded-Proto"); proto != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", proto)
	}
}

// TestBridgeAppendsToClientSuppliedForwardedFor documents a real weakness rather
// than a designed behavior.
//
// setProxyHeaders appends the resolved client IP to whatever X-Forwarded-For the
// client sent, and it does so unconditionally, without regard to whether the
// peer is in BRIDGE_TRUSTED_PROXIES. The bridge itself is not fooled, since
// clientIP ignores X-Forwarded-For from an untrusted peer, but the header it
// hands the vault upstream still carries the forged entry in the leftmost
// position, which is exactly the position most X-Forwarded-For parsers treat as
// the originating client.
//
// The test asserts the current behavior so the forwarding is visible and so a
// fix, which would be to replace the header rather than extend it when the peer
// is untrusted, shows up here as a deliberate change.
func TestBridgeAppendsToClientSuppliedForwardedFor(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	req, err := http.NewRequest(http.MethodGet, f.front.URL+"/whoami", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	resp := f.do(t, req)
	resp.Body.Close()

	xff := f.real.only(t).Header.Get("X-Forwarded-For")
	entries := strings.Split(xff, ", ")
	if len(entries) == 0 {
		t.Fatalf("X-Forwarded-For = %q, want at least one entry", xff)
	}
	if entries[0] != "1.2.3.4" {
		t.Fatalf("X-Forwarded-For = %q; the forged leftmost entry is gone, so the header is now replaced rather than appended and this test needs updating", xff)
	}
	if entries[len(entries)-1] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want the true peer appended last", xff)
	}

	// The bridge's own decision is unaffected: the forged address is not what
	// the request was scored or routed as.
	if ip := f.real.only(t).Header.Get("X-Real-IP"); ip != "127.0.0.1" {
		t.Errorf("X-Real-IP = %q, want 127.0.0.1; the forged X-Forwarded-For changed the routing identity", ip)
	}
}

// TestBridgeSetsForwardedForWhenClientSendsNone covers the other branch of
// setProxyHeaders, the one that runs for every ordinary request.
func TestBridgeSetsForwardedForWhenClientSendsNone(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	resp, _ := f.get(t, "/whoami")
	resp.Body.Close()

	xff := f.real.only(t).Header.Get("X-Forwarded-For")
	for _, entry := range strings.Split(xff, ", ") {
		if strings.TrimSpace(entry) != "127.0.0.1" {
			t.Errorf("X-Forwarded-For = %q, want only the true peer address", xff)
		}
	}
}

// TestBridgeStripsHopByHopHeaders keeps per-connection headers from leaking
// through to the vault. The request is written raw because net/http's client
// refuses to send most of these, and a proxy that forwarded them would let a
// client smuggle a Proxy-Authorization or a Connection-named header into a
// service that never expected to see one.
func TestBridgeStripsHopByHopHeaders(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	raw := "GET /probe HTTP/1.1\r\n" +
		"Host: bridge.test\r\n" +
		"User-Agent: " + benignUA + "\r\n" +
		"Connection: close, X-Hop-Token\r\n" +
		"X-Hop-Token: must-not-arrive\r\n" +
		"Keep-Alive: timeout=5, max=100\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Proxy-Authorization: Basic c2VjcmV0\r\n" +
		"Trailer: X-Checksum\r\n" +
		"X-Kept: must-arrive\r\n" +
		"\r\n"

	reply := rawExchange(t, f.front.Listener.Addr().String(), raw)
	if !strings.HasPrefix(reply, "HTTP/1.1 200") {
		t.Fatalf("response = %q, want a 200", firstLine(reply))
	}

	got := f.real.only(t)

	stripped := []string{
		"X-Hop-Token",
		"Keep-Alive",
		"Proxy-Connection",
		"Proxy-Authorization",
		"Trailer",
	}
	for _, name := range stripped {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("%s reached the upstream as %q, want it stripped", name, v)
		}
	}

	if got.Header.Get("X-Kept") != "must-arrive" {
		t.Errorf("X-Kept = %q, want it forwarded", got.Header.Get("X-Kept"))
	}
	if got.Header.Get("User-Agent") != benignUA {
		t.Errorf("User-Agent = %q, want it forwarded", got.Header.Get("User-Agent"))
	}
	// The client's Connection header governs the client's connection only. The
	// transport writes its own for the upstream hop.
	if v := got.Header.Get("Connection"); strings.Contains(strings.ToLower(v), "x-hop-token") {
		t.Errorf("Connection = %q, want the client's token list not forwarded", v)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// TestBridgePassesResponsesThroughUnchanged covers the reply direction. The
// bridge's whole premise is that a client cannot tell it is there, which fails
// immediately if a redirect loses its Location, a session cookie is dropped, or
// an error status is rewritten into something friendlier.
func TestBridgePassesResponsesThroughUnchanged(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string][]string
		body    string
	}{
		{
			name:    "redirect keeps its Location",
			status:  http.StatusMovedPermanently,
			headers: map[string][]string{"Location": {"https://auth.example.com/login"}},
			body:    "",
		},
		{
			name:    "unauthorized keeps its challenge",
			status:  http.StatusUnauthorized,
			headers: map[string][]string{"WWW-Authenticate": {`Bearer realm="vault42"`}},
			body:    `{"error":"invalid_credentials"}`,
		},
		{
			name:   "server error is not softened",
			status: http.StatusInternalServerError,
			body:   `{"error":"internal"}`,
		},
		{
			name:   "rate limit keeps Retry-After",
			status: http.StatusTooManyRequests,
			headers: map[string][]string{
				"Retry-After":           {"60"},
				"X-Ratelimit-Remaining": {"0"},
			},
			body: "slow down",
		},
		{
			name:   "several Set-Cookie headers survive as separate values",
			status: http.StatusOK,
			headers: map[string][]string{
				"Set-Cookie": {
					"access=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
					"refresh=def; Path=/auth; HttpOnly; Secure; SameSite=Strict",
				},
			},
			body: `{"ok":true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				for k, vs := range tt.headers {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body) // #nosec G104 -- test upstream response
			}, nil, nil)

			// The client must not follow redirects, or the assertion would be
			// about the redirect target rather than about the proxied response.
			client := f.front.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}

			req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("User-Agent", benignUA)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			for k, want := range tt.headers {
				got := resp.Header.Values(k)
				if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(body) != tt.body {
				t.Errorf("body = %q, want %q", body, tt.body)
			}
		})
	}
}

// TestBridgeAddsNoIdentifyingResponseHeaders is the transparency guarantee
// docs/bridge.md makes in as direct a form as it can be tested: the header names
// a client sees through the bridge must be the same ones it would see talking to
// the vault directly. A stray X-Proxy or Via header would tell an attacker the
// deception layer exists, which is the one thing the design cannot afford.
func TestBridgeAddsNoIdentifyingResponseHeaders(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	direct, err := http.Get(f.real.srv.URL + "/probe") // #nosec G107 -- httptest URL
	if err != nil {
		t.Fatalf("direct GET: %v", err)
	}
	direct.Body.Close()

	proxied, _ := f.get(t, "/probe")
	proxied.Body.Close()

	names := func(h http.Header) []string {
		var out []string
		for k := range h {
			// Date and Content-Length vary with the response bytes and the
			// clock, not with whether a proxy is in the path.
			if k == "Date" || k == "Content-Length" {
				continue
			}
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	gotNames := names(proxied.Header)
	wantNames := names(direct.Header)
	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Errorf("through the bridge the response carries %v, direct it carries %v", gotNames, wantNames)
	}
}

// TestBridgeStreamsResponseIncrementally proves the bridge does not buffer a
// response before relaying it. Vault42 streams at least one long-lived endpoint,
// and a proxy that accumulated the body would turn a stream into a stall and
// would also make the bridge's memory a function of the largest response any
// client can ask for.
func TestBridgeStreamsResponseIncrementally(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{})

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "first-chunk") // #nosec G104 -- test upstream response
		flusher.Flush()

		close(arrived)
		<-release

		io.WriteString(w, "second-chunk") // #nosec G104 -- test upstream response
		flusher.Flush()
	}, nil, nil)

	req, err := http.NewRequest(http.MethodGet, f.front.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()

	<-arrived

	// The first chunk must be readable while the upstream is still holding the
	// second one. If the bridge buffered, this read would block until release.
	buf := make([]byte, len("first-chunk"))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, buf)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read first chunk: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the first chunk did not arrive while the upstream held the second, so the bridge buffered the response")
	}

	if string(buf) != "first-chunk" {
		t.Errorf("first chunk = %q, want %q", buf, "first-chunk")
	}

	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "second-chunk" {
		t.Errorf("second chunk = %q, want %q", rest, "second-chunk")
	}
}

// TestBridgeStreamsRequestBodyIncrementally is the same guarantee in the upload
// direction. A bridge that read a request body to completion before dialing the
// upstream would let any client pin bridge memory by opening a slow upload, and
// would break any endpoint that reacts to a body as it arrives.
func TestBridgeStreamsRequestBodyIncrementally(t *testing.T) {
	firstSeen := make(chan struct{})

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		head := make([]byte, len("first-part"))
		if _, err := io.ReadFull(r.Body, head); err != nil {
			t.Errorf("upstream read of the first part: %v", err)
			return
		}
		if string(head) != "first-part" {
			t.Errorf("upstream first read = %q, want %q", head, "first-part")
		}
		close(firstSeen)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read of the rest: %v", err)
			return
		}
		if string(rest) != "second-part" {
			t.Errorf("upstream second read = %q, want %q", rest, "second-part")
		}
		w.WriteHeader(http.StatusNoContent)
	}, nil, nil)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, f.front.URL+"/upload", pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", benignUA)

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := f.front.Client().Do(req) //nolint:bodyclose // handed to respCh and closed by the receiving select below
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	if _, err := io.WriteString(pw, "first-part"); err != nil {
		t.Fatalf("write first part: %v", err)
	}

	select {
	case <-firstSeen:
	case err := <-errCh:
		t.Fatalf("request failed before the upstream saw the first part: %v", err)
	case <-time.After(5 * time.Second):
		pw.Close() // #nosec G104 -- unblocking the request on failure
		t.Fatal("the upstream never saw the first part while the client held the rest, so the bridge buffered the request body")
	}

	if _, err := io.WriteString(pw, "second-part"); err != nil {
		t.Fatalf("write second part: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}

	select {
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	case err := <-errCh:
		t.Fatalf("request: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the request never completed")
	}
}

// TestBridgeCarriesLargeBodiesIntact checks that nothing in the path imposes a
// silent size limit or corrupts a body big enough to cross many buffer
// boundaries. The bridge sets no MaxBytesReader, so the assertion is that a body
// well past any internal buffer arrives byte for byte in both directions.
func TestBridgeCarriesLargeBodiesIntact(t *testing.T) {
	const size = 4 << 20

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	wantSum := sha256.Sum256(payload)

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(got)
		w.Header().Set("X-Received-Bytes", fmt.Sprint(len(got)))
		w.Header().Set("X-Received-Sha256", hex.EncodeToString(sum[:]))
		// Echo it back so the response direction is exercised at the same size.
		w.Write(got) // #nosec G104 -- test upstream response
	}, nil, nil)

	req, err := http.NewRequest(http.MethodPost, f.front.URL+"/upload", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Received-Bytes"); got != fmt.Sprint(size) {
		t.Errorf("upstream received %s bytes, want %d", got, size)
	}
	if got := resp.Header.Get("X-Received-Sha256"); got != hex.EncodeToString(wantSum[:]) {
		t.Errorf("upstream body digest = %s, want %s", got, hex.EncodeToString(wantSum[:]))
	}

	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read echoed body: %v", err)
	}
	if len(echoed) != size {
		t.Fatalf("echoed body is %d bytes, want %d", len(echoed), size)
	}
	if sha256.Sum256(echoed) != wantSum {
		t.Error("the echoed body does not match what was sent")
	}
}

// TestBridgeReturnsBadGatewayWhenUpstreamIsUnreachable is the outage path. A
// vault that is down must produce a gateway error, not a panic and not a hung
// connection, and the honeypot must not be used as a silent fallback: routing
// clean traffic into the honeypot on a real outage would serve fabricated data
// to legitimate users.
func TestBridgeReturnsBadGatewayWhenUpstreamIsUnreachable(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RealUpstream = "http://" + deadAddr(t)
	})

	resp, _ := f.get(t, "/auth/login")
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if f.honeypot.count() != 0 {
		t.Errorf("honeypot saw %d requests when the real upstream was down, want 0", f.honeypot.count())
	}
}

// TestBridgeReturnsBadGatewayOnGarbageFromUpstream covers a vault that answers
// with something that is not HTTP at all, which is what a misrouted service or a
// TLS listener addressed over plaintext looks like on the wire.
func TestBridgeReturnsBadGatewayOnGarbageFromUpstream(t *testing.T) {
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream ResponseWriter is not a Hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()                                                      // #nosec G104 -- test upstream cleanup
		conn.Write([]byte("\x16\x03\x01 this is not an HTTP response\r\n\r\n")) // #nosec G104 -- deliberate garbage
	}))
	defer garbage.Close()

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RealUpstream = garbage.URL
	})

	resp, _ := f.get(t, "/auth/login")
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

// TestBridgeDoesNotSilentlyTruncateAShortenedResponse is the mid-response failure
// case. The upstream promises a Content-Length and then dies partway through, so
// the headers are already on the wire when the failure happens and the bridge
// cannot turn it into a 502. What it must not do is close cleanly and leave the
// client holding a short body that still looks like a successful 200: for an
// authentication API that is a truncated JSON document parsed as a valid one.
func TestBridgeDoesNotSilentlyTruncateAShortenedResponse(t *testing.T) {
	const declared = 4096

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(declared))
		w.WriteHeader(http.StatusOK)
		w.Write(bytes.Repeat([]byte("x"), 16)) // #nosec G104 -- deliberately short write
	}, nil, nil)

	resp, err := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, f.front.URL+"/truncated", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", benignUA)
		return f.front.Client().Do(req)
	}()
	if err != nil {
		// Failing at the response line is an acceptable outcome too: the client
		// still learns that the exchange did not complete.
		return
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr == nil && len(body) == declared {
		t.Fatal("the client received a complete body from an upstream that never sent one")
	}
	if readErr == nil {
		t.Errorf("reading a truncated body returned %d bytes and no error, want an error", len(body))
	}
}

// TestBridgeVerifiesUpstreamTLS pins that the proxy does not disable certificate
// verification. The bridge is the only thing standing between the internet and
// the real vault's credentials, so an InsecureSkipVerify on the upstream leg
// would make the hop into the cluster trivially interceptable. A self-signed
// upstream must therefore fail rather than be trusted.
func TestBridgeVerifiesUpstreamTLS(t *testing.T) {
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should not be reachable") // #nosec G104 -- test upstream response
	}))
	defer tlsUpstream.Close()

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RealUpstream = tlsUpstream.URL
	})

	resp, body := f.get(t, "/auth/login")
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d with body %q, want %d; the bridge trusted a self-signed upstream certificate",
			resp.StatusCode, body, http.StatusBadGateway)
	}
}

// TestBridgeReusesUpstreamConnections checks that the proxy pools its upstream
// connections. Without reuse every request from the internet becomes a fresh TCP
// handshake against the vault, which turns a burst of scanner traffic into a
// connection flood on the service the bridge exists to protect.
func TestBridgeReusesUpstreamConnections(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	for i := 0; i < 4; i++ {
		resp, _ := f.get(t, fmt.Sprintf("/probe/%d", i))
		resp.Body.Close()
	}

	reqs := f.real.requests()
	if len(reqs) != 4 {
		t.Fatalf("upstream saw %d requests, want 4", len(reqs))
	}
	for i, r := range reqs[1:] {
		if r.RemoteAddr != reqs[0].RemoteAddr {
			t.Errorf("request %d came from %s, request 0 came from %s: the upstream connection was not reused",
				i+1, r.RemoteAddr, reqs[0].RemoteAddr)
		}
	}
}

// TestBridgeToleratesASlowUpstream records that the bridge imposes no deadline
// of its own on a proxied request. The only limits are the ones main sets on the
// server, so a slow but healthy vault is relayed rather than cut off partway.
func TestBridgeToleratesASlowUpstream(t *testing.T) {
	const delay = 400 * time.Millisecond

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("X-Upstream", "real")
		io.WriteString(w, `{"upstream":"real","probe":""}`) // #nosec G104 -- test upstream response
	}, nil, nil)

	start := time.Now()
	resp, body := f.get(t, "/slow")
	resp.Body.Close()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d with body %q, want 200", resp.StatusCode, body)
	}
	if servedBy(t, body) != "real" {
		t.Errorf("served by %q, want real", servedBy(t, body))
	}
	if elapsed < delay {
		t.Errorf("response took %v, want at least the upstream's %v", elapsed, delay)
	}
}

// TestBridgeCancelsUpstreamWorkWhenTheClientGoesAway matters because the clients
// this proxy serves include the ones deliberately abandoning requests. If a
// canceled request left the vault working, an attacker could pile up upstream
// work at no cost to itself, which is a denial of service against the service
// the bridge is protecting.
func TestBridgeCancelsUpstreamWorkWhenTheClientGoesAway(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan bool, 1)

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			canceled <- true
		case <-time.After(5 * time.Second):
			canceled <- false
		}
	}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.front.URL+"/slow", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", benignUA)

	go func() {
		resp, err := f.front.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	<-started
	cancel()

	select {
	case got := <-canceled:
		if !got {
			t.Error("the upstream request context never fired after the client canceled")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream handler never returned")
	}
}

// TestBridgeRejectsMalformedRequestsWithoutProxying keeps garbage off the
// vault's socket. A request line net/http cannot parse must be answered by the
// bridge's own server with a 400, and the upstream must see nothing at all,
// since forwarding unparsed bytes is how request smuggling starts.
func TestBridgeRejectsMalformedRequestsWithoutProxying(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"not a request line", "TOTAL GARBAGE\r\n\r\n"},
		{"missing HTTP version", "GET /probe\r\nHost: x\r\n\r\n"},
		{"invalid header name", "GET /probe HTTP/1.1\r\nHost: x\r\nBad Header: v\r\n\r\n"},
		{"space in the path", "GET /pro be HTTP/1.1\r\nHost: x\r\n\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil, nil, nil)

			reply := rawExchange(t, f.front.Listener.Addr().String(), tt.raw)
			if !strings.HasPrefix(reply, "HTTP/1.1 400") {
				t.Errorf("response = %q, want a 400", firstLine(reply))
			}
			if f.real.count() != 0 || f.honeypot.count() != 0 {
				t.Errorf("a malformed request reached an upstream: real=%d honeypot=%d",
					f.real.count(), f.honeypot.count())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Routing and detection
// ---------------------------------------------------------------------------

// TestBridgeRoutesFlaggedTrafficToHoneypotTransparently is the core deception
// behavior. The switch has to be invisible, so the honeypot must receive the
// same request the real vault would have, down to the body and the headers: a
// request that arrived at the honeypot stripped of its cookie would produce a
// different failure than the attacker was expecting and give the game away.
func TestBridgeRoutesFlaggedTrafficToHoneypotTransparently(t *testing.T) {
	f := newFixture(t, nil, nil, nil)
	f.bridge.flags.Flag("127.0.0.1", "manual", 100)

	body := `{"email":"victim@example.com","password":"guess"}`
	req, err := http.NewRequest(http.MethodPost, f.front.URL+"/auth/login?attempt=3", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "session=stolen")

	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if servedBy(t, string(got)) != "honeypot" {
		t.Fatalf("flagged traffic served by %q, want honeypot", servedBy(t, string(got)))
	}
	if f.real.count() != 0 {
		t.Errorf("real vault saw %d requests from a flagged IP, want 0", f.real.count())
	}

	hp := f.honeypot.only(t)
	if hp.Method != http.MethodPost || hp.Path != "/auth/login" || hp.RawQuery != "attempt=3" {
		t.Errorf("honeypot saw %s %s?%s, want POST /auth/login?attempt=3", hp.Method, hp.Path, hp.RawQuery)
	}
	if string(hp.Body) != body {
		t.Errorf("honeypot body = %q, want %q", hp.Body, body)
	}
	if hp.Header.Get("Cookie") != "session=stolen" {
		t.Errorf("honeypot Cookie = %q, want it forwarded intact", hp.Header.Get("Cookie"))
	}
	if hp.Header.Get("X-Real-IP") != "127.0.0.1" {
		t.Errorf("honeypot X-Real-IP = %q, want 127.0.0.1", hp.Header.Get("X-Real-IP"))
	}
}

// TestBridgeReleasesTrafficWhenTheFlagExpires is the other half of the TTL
// contract, seen from the request path rather than from the store. A false
// positive has to heal on its own, otherwise the only remedy is an operator
// noticing and calling the admin API.
func TestBridgeReleasesTrafficWhenTheFlagExpires(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.FlagTTL = 120 * time.Millisecond
	})

	f.bridge.flags.Flag("127.0.0.1", "manual", 100)

	resp, body := f.get(t, "/probe")
	resp.Body.Close()
	if servedBy(t, body) != "honeypot" {
		t.Fatalf("served by %q while flagged, want honeypot", servedBy(t, body))
	}

	time.Sleep(200 * time.Millisecond)

	resp, body = f.get(t, "/probe")
	resp.Body.Close()
	if servedBy(t, body) != "real" {
		t.Errorf("served by %q after the flag expired, want real", servedBy(t, body))
	}
}

// TestBridgeAutoFlagsOnAutomationUserAgent walks the scoring path end to end for
// the cheapest signal. The request that crosses the threshold must itself be
// diverted, not just the ones after it, because a scanner that got one real
// answer has already learned something true about the production vault.
func TestBridgeAutoFlagsOnAutomationUserAgent(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.FlagThreshold = 30
	})

	req, err := http.NewRequest(http.MethodGet, f.front.URL+"/auth/login", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")

	resp := f.do(t, req) //nolint:bodyclose // closed on the next line; bodyclose cannot see through f.do
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if servedBy(t, string(body)) != "honeypot" {
		t.Errorf("the flagging request was served by %q, want honeypot", servedBy(t, string(body)))
	}
	if f.real.count() != 0 {
		t.Errorf("the real vault answered %d scanner requests, want 0", f.real.count())
	}

	entries := f.bridge.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].IP != "127.0.0.1" {
		t.Errorf("flagged IP = %q, want 127.0.0.1", entries[0].IP)
	}
	if entries[0].Reason != "auto:automation_ua" {
		t.Errorf("reason = %q, want auto:automation_ua", entries[0].Reason)
	}
	if entries[0].Score != 30 {
		t.Errorf("score = %d, want 30", entries[0].Score)
	}
}

// TestBridgeScoreAccumulatesUntilTheThreshold shows that the score is a running
// total across requests rather than a per-request verdict. Three scanner
// requests at thirty points each stay under a hundred and are answered by the
// real vault; the fourth crosses and is not.
func TestBridgeScoreAccumulatesUntilTheThreshold(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.FlagThreshold = 100
	})

	var served []string
	for i := 0; i < 4; i++ {
		req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", "curl/8.5.0")

		resp := f.do(t, req)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		served = append(served, servedBy(t, string(body)))

		wantScore := 30 * (i + 1)
		if got := f.bridge.scores.Get("127.0.0.1"); got != wantScore {
			t.Errorf("after request %d the score is %d, want %d", i+1, got, wantScore)
		}
	}

	want := []string{"real", "real", "real", "honeypot"}
	if strings.Join(served, ",") != strings.Join(want, ",") {
		t.Errorf("requests were served by %v, want %v", served, want)
	}
}

// TestBridgeAutoFlagsOnRateExceeded covers the second signal and, with it, the
// reason precedence: when a request trips both the user agent rule and the rate
// rule, the recorded reason is the rate one. The reason string is what an
// operator reads in the flag list when deciding whether a flag was a false
// positive, so which signal wins is worth pinning.
func TestBridgeAutoFlagsOnRateExceeded(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RateThreshold = 2
		cfg.RateWindow = time.Minute
		cfg.FlagThreshold = 50
	})

	var served []string
	for i := 0; i < 3; i++ {
		resp, body := f.get(t, "/probe")
		resp.Body.Close()
		served = append(served, servedBy(t, body))
	}

	want := []string{"real", "real", "honeypot"}
	if strings.Join(served, ",") != strings.Join(want, ",") {
		t.Fatalf("requests were served by %v, want %v", served, want)
	}

	entries := f.bridge.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].Reason != "auto:rate_exceeded" {
		t.Errorf("reason = %q, want auto:rate_exceeded", entries[0].Reason)
	}
}

// TestBridgeRatePenaltyOutranksTheUserAgentReason makes the precedence explicit
// with both signals firing on the same request.
func TestBridgeRatePenaltyOutranksTheUserAgentReason(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RateThreshold = 1
		cfg.RateWindow = time.Minute
		cfg.FlagThreshold = 80
	})

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", "nikto/2.5.0")
		resp := f.do(t, req)
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
		resp.Body.Close()
	}

	entries := f.bridge.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].Reason != "auto:rate_exceeded" {
		t.Errorf("reason = %q, want auto:rate_exceeded to win over the user agent reason", entries[0].Reason)
	}
	// Both signals scored: 30 for the agent on each request plus 50 for the rate
	// on the second one.
	if entries[0].Score != 110 {
		t.Errorf("score = %d, want 110 (30 + 30 + 50)", entries[0].Score)
	}
}

// TestBridgeDoesNotFlagOrdinaryTraffic is the false-positive guard. A browser
// making a normal number of requests must never be diverted, because the cost of
// a false positive here is a real user quietly served fabricated data by a
// system that shows no sign anything is wrong.
func TestBridgeDoesNotFlagOrdinaryTraffic(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.RateThreshold = 60
		cfg.FlagThreshold = 100
	})

	paths := []string{"/", "/auth/login", "/auth/refresh", "/.well-known/jwks.json", "/static/app.css"}
	for i := 0; i < 40; i++ {
		resp, body := f.get(t, paths[i%len(paths)])
		resp.Body.Close()
		if servedBy(t, body) != "real" {
			t.Fatalf("request %d to %s was served by the honeypot", i, paths[i%len(paths)])
		}
	}

	if got := f.bridge.scores.Get("127.0.0.1"); got != 0 {
		t.Errorf("score after ordinary traffic = %d, want 0", got)
	}
	if entries := f.bridge.flags.List(); len(entries) != 0 {
		t.Errorf("ordinary traffic produced flags: %+v", entries)
	}
}

// TestBridgeCountsLoginFailures drives the ModifyResponse hook through the real
// proxy. The signal is worth a dedicated test because it is the only one that
// depends on what the upstream answered rather than on what the client sent, and
// it is therefore the only one that can break without any change to the request
// path at all.
func TestBridgeCountsLoginFailures(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/auth/login" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"invalid_credentials"}`) // #nosec G104 -- test upstream response
			return
		}
		w.Header().Set("X-Upstream", "real")
		io.WriteString(w, `{"upstream":"real","probe":""}`) // #nosec G104 -- test upstream response
	}, nil, func(cfg *Config) {
		cfg.LoginFailThreshold = 3
		cfg.FlagThreshold = 60
	})

	postLogin := func() int {
		req, err := http.NewRequest(http.MethodPost, f.front.URL+"/auth/login", strings.NewReader(`{"email":"a@b.c"}`))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp := f.do(t, req)
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
		resp.Body.Close()
		return resp.StatusCode
	}

	// Below the threshold nothing scores, and the attacker sees the vault's real
	// 401 so the failure is indistinguishable from an ordinary bad password.
	for i := 0; i < 2; i++ {
		if code := postLogin(); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, code)
		}
		if got := f.bridge.scores.Get("127.0.0.1"); got != 0 {
			t.Errorf("score after %d failures = %d, want 0", i+1, got)
		}
	}

	// The third failure reaches LoginFailThreshold and scores 3 * 20 = 60, which
	// is the configured flag threshold.
	if code := postLogin(); code != http.StatusUnauthorized {
		t.Fatalf("attempt 3 status = %d, want 401", code)
	}

	if !f.bridge.flags.IsFlagged("127.0.0.1") {
		t.Fatal("three failed logins did not flag the IP")
	}
	entries := f.bridge.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].Reason != "auto:login_failures" {
		t.Errorf("reason = %q, want auto:login_failures", entries[0].Reason)
	}
	if entries[0].Score != 60 {
		t.Errorf("score = %d, want 60", entries[0].Score)
	}

	// From here on the attacker is in the honeypot.
	resp, body := f.get(t, "/probe")
	resp.Body.Close()
	if servedBy(t, body) != "honeypot" {
		t.Errorf("post-flag request served by %q, want honeypot", servedBy(t, body))
	}
}

// TestBridgeIgnoresResponsesThatAreNotFailedLogins keeps the counter from firing
// on traffic that is not a credential guess. A 401 on an expired access token is
// the single most common response an authentication service produces, and
// counting those would flag every user whose session lapsed.
func TestBridgeIgnoresResponsesThatAreNotFailedLogins(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		// Everything answers 401 except a successful login, so the only thing
		// distinguishing the cases is the method and path the hook checks.
		if r.Method == http.MethodPost && r.URL.Path == "/auth/login" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"ok":true}`) // #nosec G104 -- test upstream response
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}, nil, func(cfg *Config) {
		cfg.LoginFailThreshold = 1
		cfg.FlagThreshold = 20
	})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/auth/login"},     // right path, wrong method
		{http.MethodPost, "/auth/refresh"},  // right method, wrong path
		{http.MethodPost, "/auth/login/v2"}, // prefix, not the exact path
		{http.MethodPost, "/auth/login"},    // exact match, but a 200 rather than a 401
	}

	for _, c := range cases {
		req, err := http.NewRequest(c.method, f.front.URL+c.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp := f.do(t, req)
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
		resp.Body.Close()

		if f.bridge.flags.IsFlagged("127.0.0.1") {
			t.Fatalf("%s %s was counted as a failed login", c.method, c.path)
		}
	}

	if got := f.bridge.scores.Get("127.0.0.1"); got != 0 {
		t.Errorf("score = %d after traffic that is not a failed login, want 0", got)
	}
}

// TestBridgeLoginFailureDetectionBreaksWhenTheUpstreamHasAPathPrefix documents a
// real fail-open defect.
//
// inspectLoginResponse reads resp.Request.URL.Path, and resp.Request is the
// request the transport actually sent, which httputil.NewSingleHostReverseProxy
// has already rewritten to include the upstream URL's own path. Configure
// BRIDGE_REAL_UPSTREAM as http://vault:8080/api and the outbound path becomes
// /api/auth/login, which never equals the "/auth/login" the hook compares
// against. Failed-login scoring then silently stops: no error, no log line, and
// the detection signal documented in docs/bridge.md is simply gone.
//
// The test proves the mechanism rather than asserting it from the outside: it
// checks that the upstream really did receive the prefixed path, and that the
// same number of failures which flags an unprefixed bridge flags nothing here.
func TestBridgeLoginFailureDetectionBreaksWhenTheUpstreamHasAPathPrefix(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, nil, nil)

	// Rebuild the bridge against the same upstream, but mounted under a prefix.
	cfg := testConfig(f.real.srv.URL+"/api", f.honeypot.srv.URL)
	cfg.LoginFailThreshold = 1
	cfg.FlagThreshold = 20

	prefixed, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	defer prefixed.Close()

	front := httptest.NewServer(prefixed)
	defer front.Close()

	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodPost, front.URL+"/auth/login", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", benignUA)
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, resp.StatusCode)
		}
	}

	// The prefix really is applied on the wire, which is what defeats the hook.
	reqs := f.real.requests()
	if len(reqs) != 5 {
		t.Fatalf("upstream saw %d requests, want 5", len(reqs))
	}
	if reqs[0].Path != "/api/auth/login" {
		t.Fatalf("upstream path = %q, want /api/auth/login; the prefix is no longer applied and this test needs rewriting", reqs[0].Path)
	}

	if prefixed.flags.IsFlagged("127.0.0.1") {
		t.Error("failed-login detection now survives an upstream path prefix, so the path comparison was fixed and this test needs updating")
	}
	if got := prefixed.scores.Get("127.0.0.1"); got != 0 {
		t.Errorf("score = %d, want 0 while the defect stands", got)
	}
}

// TestBridgeNeverProxiesItsOwnPaths keeps the control plane off the vault. Every
// /bridge/ path is answered locally, including ones that do not exist, so the
// upstream can never be reached through this prefix and an unauthenticated
// caller cannot use it to probe what is behind the proxy.
func TestBridgeNeverProxiesItsOwnPaths(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.AdminToken = "test-token"
	})

	tests := []struct {
		path       string
		method     string
		auth       bool
		wantStatus int
	}{
		{"/bridge/healthz", http.MethodGet, false, http.StatusOK},
		{"/bridge/readyz", http.MethodGet, false, http.StatusOK},
		{"/bridge/flags", http.MethodGet, true, http.StatusOK},
		{"/bridge/flags", http.MethodGet, false, http.StatusUnauthorized},
		{"/bridge/flag", http.MethodGet, true, http.StatusMethodNotAllowed},
		{"/bridge/flag", http.MethodGet, false, http.StatusUnauthorized},
		{"/bridge/", http.MethodGet, false, http.StatusNotFound},
		{"/bridge/nope", http.MethodGet, false, http.StatusNotFound},
		{"/bridge/flags/extra", http.MethodGet, false, http.StatusNotFound},
		{"/bridge/../auth/login", http.MethodGet, false, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, f.front.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("User-Agent", benignUA)
			if tt.auth {
				req.Header.Set("Authorization", "Bearer test-token")
			}
			// The client would otherwise clean a dot segment out of the path
			// before it ever reaches the bridge.
			req.URL.Opaque = tt.path

			resp, err := f.front.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", tt.method, tt.path, err)
			}
			io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
			resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}

	// The readiness probe legitimately contacts both upstreams on /healthz, so
	// the assertion is on the paths rather than on the request counts: no
	// /bridge/ path may ever appear on an upstream socket.
	for name, u := range map[string]*upstream{"real": f.real, "honeypot": f.honeypot} {
		for _, r := range u.requests() {
			if r.Path != "/healthz" {
				t.Errorf("%s upstream saw %s %s, want only the readiness probe on /healthz", name, r.Method, r.Path)
			}
		}
	}
}

// TestBridgePathsWinOverFlagging shows the ordering inside ServeHTTP: the
// /bridge/ prefix is checked before the flag lookup, so an operator whose own
// address has been flagged can still reach the admin API to unflag it. Reversing
// that order would make a self-inflicted flag unrecoverable without a restart.
func TestBridgePathsWinOverFlagging(t *testing.T) {
	f := newFixture(t, nil, nil, nil)
	f.bridge.flags.Flag("127.0.0.1", "manual", 100)

	resp, _ := f.get(t, "/bridge/healthz")
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if f.honeypot.count() != 0 {
		t.Errorf("the honeypot answered a /bridge/ path for a flagged IP")
	}
}

// TestBridgeDecoyPathsAreServedLocally checks that a decoy is answered by the
// bridge itself, flags the caller, and never touches either vault. Proxying a
// /wp-admin probe to the real vault would produce a 404 from the real service,
// which tells a scanner exactly as much as a real WordPress 404 would not.
func TestBridgeDecoyPathsAreServedLocally(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	resp, body := f.get(t, "/phpmyadmin/index.php")
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, "phpMyAdmin") {
		t.Errorf("body does not look like the phpMyAdmin decoy: %.120q", body)
	}
	if f.real.count() != 0 || f.honeypot.count() != 0 {
		t.Errorf("a decoy path was proxied: real=%d honeypot=%d", f.real.count(), f.honeypot.count())
	}

	entries := f.bridge.flags.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].Reason != "decoy:/phpmyadmin/index.php" {
		t.Errorf("reason = %q, want decoy:/phpmyadmin/index.php", entries[0].Reason)
	}
	if entries[0].Score != 100 {
		t.Errorf("score = %d, want 100", entries[0].Score)
	}

	// The very next request is already in the honeypot.
	resp, body = f.get(t, "/auth/login")
	resp.Body.Close()
	if servedBy(t, body) != "honeypot" {
		t.Errorf("the request after a decoy hit was served by %q, want honeypot", servedBy(t, body))
	}
}

// TestBridgeDoesNotSwallowTheProductsOwnAdminSurface is the inverted form of a
// test that used to pin a finding.
//
// decoyPaths registered "/admin", and IsDecoyPath matches any path under a
// prefix. The admin gateway in this same repository registers thirty-odd routes
// under /admin/, starting with POST /admin/auth/login, and docs/spec.md
// publishes every one of them. So any of those requests arriving at a bridge was
// answered with a fake admin login page and flagged the caller's address for the
// full BRIDGE_FLAG_TTL, after which that operator's every request went to the
// honeypot and showed them a plausible but fabricated vault with no signal
// anything had switched.
//
// The prefix is gone, and these paths now proxy through untouched. The caller
// must also be unflagged: reaching the real vault while still being marked would
// leave the operator poisoned for the next request instead of this one.
func TestBridgeDoesNotSwallowTheProductsOwnAdminSurface(t *testing.T) {
	realAdminRoutes := []string{
		"/admin/auth/login",
		"/admin/status",
		"/admin/keys",
		"/admin/users",
		"/admin/audit",
	}

	for _, path := range realAdminRoutes {
		t.Run(path, func(t *testing.T) {
			f := newFixture(t, nil, nil, nil)

			resp, body := f.get(t, path)
			resp.Body.Close()

			if f.real.count() != 1 {
				t.Fatalf("%s did not reach the real vault (%d upstream requests); "+
					"a decoy prefix is shadowing the product's own admin surface", path, f.real.count())
			}
			if strings.Contains(body, "<!DOCTYPE") && strings.Contains(body, "login") {
				t.Errorf("%s was answered with what looks like a decoy page: %.120q", path, body)
			}
			if f.bridge.flags.IsFlagged("127.0.0.1") {
				t.Errorf("%s flagged the caller; an operator opening the admin console "+
					"would be served fabricated data for the whole flag TTL", path)
			}
		})
	}
}

// TestIsDecoyPathDoesNotOverreach bounds the collision above. The prefix rule
// must still require a path separator, so an unrelated route that merely starts
// with the same letters is proxied normally rather than swallowed.
func TestIsDecoyPathDoesNotOverreach(t *testing.T) {
	tests := []struct {
		path    string
		isDecoy bool
	}{
		{"/adminx", false},
		{"/admin-console", false},
		{"/wp-adminer", false},
		{"/pmatools", false},
		{"/api/admin", false},
		{"/auth/admin", false},
		{"/administrator", true},
		{"/administrators", false},
		{"/admin/", false},
		{"/admin/auth/login", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, got := IsDecoyPath(tt.path)
			if got != tt.isDecoy {
				t.Errorf("IsDecoyPath(%q) = %v, want %v", tt.path, got, tt.isDecoy)
			}
		})
	}
}

// TestIsDecoyPathIgnoresCase keeps the trap from being stepped around with a
// shift key. Scanners routinely request /WP-ADMIN, and the vault's own routes
// are lower case, so matching case-insensitively costs nothing and closes the
// bypass.
func TestIsDecoyPathIgnoresCase(t *testing.T) {
	for _, path := range []string{"/WP-ADMIN", "/Wp-Admin/", "/PhpMyAdmin", "/CPANEL", "/WebMail/inbox"} {
		if _, ok := IsDecoyPath(path); !ok {
			t.Errorf("IsDecoyPath(%q) = false, want true", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Client IP resolution
// ---------------------------------------------------------------------------

// TestClientIPResolution is the most security-sensitive unit in the binary. The
// resolved address is what gets flagged, what gets rate counted, and what
// decides which vault answers, so a client able to choose its own would be able
// both to shed its own flag and to plant one on somebody else's address. The
// rule that has to hold across every row below is that a header is believed only
// when the peer itself is a configured trusted proxy.
func TestClientIPResolution(t *testing.T) {
	mustCIDRs := func(t *testing.T, cidrs ...string) []*net.IPNet {
		t.Helper()
		var out []*net.IPNet
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", c, err)
			}
			out = append(out, n)
		}
		return out
	}

	tests := []struct {
		name         string
		trusted      []string
		realIPHeader string
		remoteAddr   string
		headers      map[string]string
		want         string
	}{
		{
			name:       "no proxy configuration uses the peer address",
			remoteAddr: "203.0.113.9:54321",
			want:       "203.0.113.9",
		},
		{
			name:       "an untrusted peer cannot forge X-Forwarded-For",
			remoteAddr: "203.0.113.9:54321",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			want:       "203.0.113.9",
		},
		{
			name:         "an untrusted peer cannot forge the real IP header",
			realIPHeader: "CF-Connecting-IP",
			remoteAddr:   "203.0.113.9:54321",
			headers:      map[string]string{"CF-Connecting-IP": "10.0.0.1"},
			want:         "203.0.113.9",
		},
		{
			name:         "a configured header is ignored without a trusted proxy list",
			realIPHeader: "CF-Connecting-IP",
			remoteAddr:   "10.0.0.5:1234",
			headers:      map[string]string{"CF-Connecting-IP": "198.51.100.7"},
			want:         "10.0.0.5",
		},
		{
			name:         "a trusted peer's real IP header is believed",
			trusted:      []string{"10.0.0.0/8"},
			realIPHeader: "CF-Connecting-IP",
			remoteAddr:   "10.0.0.5:1234",
			headers:      map[string]string{"CF-Connecting-IP": "198.51.100.7"},
			want:         "198.51.100.7",
		},
		{
			name:         "surrounding whitespace is trimmed from the real IP header",
			trusted:      []string{"10.0.0.0/8"},
			realIPHeader: "CF-Connecting-IP",
			remoteAddr:   "10.0.0.5:1234",
			headers:      map[string]string{"CF-Connecting-IP": "  198.51.100.7  "},
			want:         "198.51.100.7",
		},
		{
			name:         "an empty real IP header falls through to X-Forwarded-For",
			trusted:      []string{"10.0.0.0/8"},
			realIPHeader: "CF-Connecting-IP",
			remoteAddr:   "10.0.0.5:1234",
			headers: map[string]string{
				"CF-Connecting-IP": "",
				"X-Forwarded-For":  "198.51.100.8",
			},
			want: "198.51.100.8",
		},
		{
			name:       "a trusted peer's X-Forwarded-For is believed",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:1234",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "the leftmost X-Forwarded-For entry wins",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.5:1234",
			headers:    map[string]string{"X-Forwarded-For": " 198.51.100.7 , 10.0.0.9 , 10.0.0.5 "},
			want:       "198.51.100.7",
		},
		{
			name:       "a peer outside the trusted ranges is not believed",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "192.168.1.4:1234",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "192.168.1.4",
		},
		{
			name:       "an IPv6 peer address is unwrapped",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "a trusted IPv6 peer is honored",
			trusted:    []string{"2001:db8::/32"},
			remoteAddr: "[2001:db8::1]:443",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "a peer address with no port is used as-is",
			remoteAddr: "203.0.113.9",
			want:       "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig("http://real:8080", "http://honeypot:8080")
			cfg.RealIPHeader = tt.realIPHeader
			if len(tt.trusted) > 0 {
				cfg.TrustedProxies = mustCIDRs(t, tt.trusted...)
			}

			b, err := NewBridge(cfg)
			if err != nil {
				t.Fatalf("NewBridge: %v", err)
			}
			defer b.Close()

			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := b.clientIP(req); got != tt.want {
				t.Errorf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBridgeRoutesByTheResolvedClientIP joins the resolution rule to the routing
// decision. Behind a correctly configured trusted proxy, flagging one forwarded
// address must divert only that address, since every request shares the same
// peer and a bridge that keyed on the peer would flag every user of the proxy at
// once.
func TestBridgeRoutesByTheResolvedClientIP(t *testing.T) {
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.TrustedProxies = []*net.IPNet{loopback}
		cfg.RealIPHeader = "CF-Connecting-IP"
	})

	f.bridge.flags.Flag("198.51.100.7", "manual", 100)

	fetch := func(clientIP string) string {
		req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", benignUA)
		req.Header.Set("CF-Connecting-IP", clientIP)

		resp := f.do(t, req)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return servedBy(t, string(body))
	}

	if got := fetch("198.51.100.7"); got != "honeypot" {
		t.Errorf("the flagged forwarded address was served by %q, want honeypot", got)
	}
	if got := fetch("198.51.100.8"); got != "real" {
		t.Errorf("an unflagged address behind the same proxy was served by %q, want real", got)
	}

	// The forwarded identity is also what reaches the vault.
	reqs := f.real.requests()
	if len(reqs) != 1 {
		t.Fatalf("real vault saw %d requests, want 1", len(reqs))
	}
	if ip := reqs[0].Header.Get("X-Real-IP"); ip != "198.51.100.8" {
		t.Errorf("X-Real-IP = %q, want the resolved client address 198.51.100.8", ip)
	}
}

// TestIsTrustedProxy covers the predicate directly, including the two ways it
// must refuse: an empty configuration trusts nobody, and an address that is not
// an address is not silently treated as one.
func TestIsTrustedProxy(t *testing.T) {
	parse := func(t *testing.T, cidrs ...string) []*net.IPNet {
		t.Helper()
		var out []*net.IPNet
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", c, err)
			}
			out = append(out, n)
		}
		return out
	}

	tests := []struct {
		name    string
		trusted []string
		ip      string
		want    bool
	}{
		{"an empty list trusts nobody", nil, "10.0.0.1", false},
		{"an empty list rejects even loopback", nil, "127.0.0.1", false},
		{"inside the range", []string{"10.0.0.0/8"}, "10.4.5.6", true},
		{"outside the range", []string{"10.0.0.0/8"}, "192.168.1.1", false},
		{"the second range matches", []string{"10.0.0.0/8", "192.168.0.0/16"}, "192.168.1.1", true},
		{"a single host range", []string{"203.0.113.5/32"}, "203.0.113.5", true},
		{"just outside a single host range", []string{"203.0.113.5/32"}, "203.0.113.6", false},
		{"IPv6 inside", []string{"2001:db8::/32"}, "2001:db8::dead", true},
		{"IPv6 outside", []string{"2001:db8::/32"}, "2001:dba::1", false},
		{"an IPv4 range does not match an IPv6 address", []string{"10.0.0.0/8"}, "2001:db8::1", false},
		{"not an address at all", []string{"10.0.0.0/8"}, "not-an-ip", false},
		{"an empty address", []string{"10.0.0.0/8"}, "", false},
		{"a host:port pair is not an address", []string{"10.0.0.0/8"}, "10.0.0.1:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig("http://real:8080", "http://honeypot:8080")
			if len(tt.trusted) > 0 {
				cfg.TrustedProxies = parse(t, tt.trusted...)
			}
			b, err := NewBridge(cfg)
			if err != nil {
				t.Fatalf("NewBridge: %v", err)
			}
			defer b.Close()

			if got := b.isTrustedProxy(tt.ip); got != tt.want {
				t.Errorf("isTrustedProxy(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestExtractIP pins the fallback behavior that makes clientIP total. Anything
// that does not split into host and port is returned whole rather than turned
// into an empty string, because an empty client IP would key every such request
// to the same bucket and let one client's score flag all of them.
func TestExtractIP(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"203.0.113.9:54321", "203.0.113.9"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[::1]:8080", "::1"},
		{"203.0.113.9", "203.0.113.9"},
		{"", ""},
		{"not an address", "not an address"},
		{"/var/run/socket", "/var/run/socket"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := extractIP(tt.addr); got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scores and reaping
// ---------------------------------------------------------------------------

// TestScoreMapAddAndGet covers the accumulator's arithmetic and its per-IP
// isolation. Get on an address that never scored must be zero rather than
// absent, since ServeHTTP compares it against a threshold without checking
// whether the key exists.
func TestScoreMapAddAndGet(t *testing.T) {
	sm := NewScoreMap()

	if got := sm.Get("1.1.1.1"); got != 0 {
		t.Errorf("Get on an unknown IP = %d, want 0", got)
	}
	if got := sm.Add("1.1.1.1", 30); got != 30 {
		t.Errorf("Add returned %d, want 30", got)
	}
	if got := sm.Add("1.1.1.1", 50); got != 80 {
		t.Errorf("Add returned %d, want 80", got)
	}
	if got := sm.Get("1.1.1.1"); got != 80 {
		t.Errorf("Get = %d, want 80", got)
	}
	if got := sm.Get("2.2.2.2"); got != 0 {
		t.Errorf("a second IP picked up %d, want 0", got)
	}
	// Nothing decays a score, so a negative delta is the only way back down.
	if got := sm.Add("1.1.1.1", -80); got != 0 {
		t.Errorf("Add returned %d, want 0", got)
	}
}

// TestScoreMapConcurrentAdd is the arithmetic under contention. The score is
// read, incremented and compared against a threshold on the request path of a
// proxy that handles concurrent connections, so a lost update here is a scanner
// that never crosses the line it should have crossed.
func TestScoreMapConcurrentAdd(t *testing.T) {
	sm := NewScoreMap()

	const workers = 32
	const iterations = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			own := fmt.Sprintf("10.0.0.%d", w)
			for i := 0; i < iterations; i++ {
				sm.Add("shared", 1)
				sm.Add(own, 2)
				sm.Get("shared")
			}
		}(w)
	}
	wg.Wait()

	if got := sm.Get("shared"); got != workers*iterations {
		t.Errorf("shared score = %d, want %d", got, workers*iterations)
	}
	for w := 0; w < workers; w++ {
		ip := fmt.Sprintf("10.0.0.%d", w)
		if got := sm.Get(ip); got != 2*iterations {
			t.Errorf("%s score = %d, want %d", ip, got, 2*iterations)
		}
	}
}

// TestStartReaperDrainsExpiredState checks that the background sweep actually
// reaches all three stores it claims to. Each of them grows by one entry per
// distinct client address and none of them is bounded, so a reaper that quietly
// missed one would turn a long-running bridge under scanner traffic into a slow
// memory leak.
func TestStartReaperDrainsExpiredState(t *testing.T) {
	cfg := testConfig("http://real:8080", "http://honeypot:8080")
	cfg.FlagTTL = 20 * time.Millisecond
	cfg.RateWindow = 20 * time.Millisecond
	cfg.LoginFailWindow = 20 * time.Millisecond

	b, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	defer b.Close()

	b.flags.Flag("1.1.1.1", "test", 100)
	b.rateTracker.Record("2.2.2.2")
	b.loginFails.Record("3.3.3.3")

	b.StartReaper(10 * time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b.flags.mu.RLock()
		flags := len(b.flags.flags)
		b.flags.mu.RUnlock()

		b.rateTracker.mu.Lock()
		rates := len(b.rateTracker.buckets)
		b.rateTracker.mu.Unlock()

		b.loginFails.mu.Lock()
		logins := len(b.loginFails.buckets)
		b.loginFails.mu.Unlock()

		if flags == 0 && rates == 0 && logins == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	b.flags.mu.RLock()
	flags := len(b.flags.flags)
	b.flags.mu.RUnlock()
	b.rateTracker.mu.Lock()
	rates := len(b.rateTracker.buckets)
	b.rateTracker.mu.Unlock()
	b.loginFails.mu.Lock()
	logins := len(b.loginFails.buckets)
	b.loginFails.mu.Unlock()

	t.Errorf("after reaping: flags=%d rate buckets=%d login buckets=%d, want all zero", flags, rates, logins)
}

// TestReaperLeavesScoresBehind records a genuine unbounded-growth defect.
//
// StartReaper sweeps the flag store and both sliding-window trackers, but
// nothing ever removes an entry from the ScoreMap. Scores also never decay, so
// every address that has ever scored a single point keeps a map entry for the
// life of the process. A bridge on the public internet takes scanner traffic
// continuously from a large and changing set of addresses, which makes this a
// slow leak with no ceiling and no operator-visible signal.
//
// The lack of decay is documented in Config.FlagThreshold as a deliberate
// lifetime budget. The lack of eviction is not documented anywhere, and the two
// are separable: entries could be dropped once their address has been flagged
// and the flag has expired.
func TestReaperLeavesScoresBehind(t *testing.T) {
	cfg := testConfig("http://real:8080", "http://honeypot:8080")
	cfg.FlagTTL = 20 * time.Millisecond
	cfg.RateWindow = 20 * time.Millisecond
	cfg.LoginFailWindow = 20 * time.Millisecond

	b, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	defer b.Close()

	b.scores.Add("1.1.1.1", 30)
	b.flags.Flag("1.1.1.1", "test", 30)
	b.rateTracker.Record("1.1.1.1")

	b.StartReaper(10 * time.Millisecond)

	// Wait until the reaper has demonstrably run at least once.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b.flags.mu.RLock()
		flags := len(b.flags.flags)
		b.flags.mu.RUnlock()
		if flags == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := b.scores.Get("1.1.1.1"); got != 30 {
		t.Errorf("score after reaping = %d, want 30; scores are now evicted, so this defect was fixed and the test needs updating", got)
	}

	b.scores.mu.Lock()
	size := len(b.scores.scores)
	b.scores.mu.Unlock()
	if size != 1 {
		t.Errorf("score map holds %d entries after reaping, want 1", size)
	}
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

// TestNewWebhookSenderDisabledByEmptyURL pins the nil-return convention, which
// the callers rely on by checking for nil before sending.
func TestNewWebhookSenderDisabledByEmptyURL(t *testing.T) {
	if ws := NewWebhookSender(""); ws != nil {
		t.Errorf("NewWebhookSender(\"\") = %v, want nil", ws)
	}
	ws := NewWebhookSender("https://hooks.example.com/x")
	if ws == nil {
		t.Fatal("NewWebhookSender returned nil for a configured URL")
	}
	if ws.client == nil || ws.client.Timeout == 0 {
		t.Error("the webhook client has no timeout, so a hung receiver would block a request forever")
	}
}

// TestWebhookSenderNilReceiverIsANoOp is the safety net behind that convention.
// Send is called on the request path with the sender read straight off the
// Bridge, so a nil receiver has to be inert rather than a panic that would take
// down the connection mid-request.
func TestWebhookSenderNilReceiverIsANoOp(t *testing.T) {
	var ws *WebhookSender
	ws.Send(map[string]interface{}{"event": "auto_flag"})
}

// TestWebhookSenderPostsJSON covers the wire format an operator's receiver has
// to parse.
func TestWebhookSenderPostsJSON(t *testing.T) {
	type received struct {
		method      string
		contentType string
		body        []byte
	}
	got := make(chan received, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) // #nosec G104 -- a read error is captured as a short body
		got <- received{method: r.Method, contentType: r.Header.Get("Content-Type"), body: body}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ws := NewWebhookSender(srv.URL)
	ws.Send(map[string]interface{}{
		"event":  "auto_flag",
		"ip":     "203.0.113.9",
		"score":  130,
		"reason": "auto:automation_ua",
	})

	select {
	case r := <-got:
		if r.method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.method)
		}
		if r.contentType != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.contentType)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(r.body, &doc); err != nil {
			t.Fatalf("body %q is not JSON: %v", r.body, err)
		}
		if doc["event"] != "auto_flag" || doc["ip"] != "203.0.113.9" || doc["reason"] != "auto:automation_ua" {
			t.Errorf("payload = %v, want the event, ip and reason preserved", doc)
		}
		if score, ok := doc["score"].(float64); !ok || score != 130 {
			t.Errorf("score = %v, want 130", doc["score"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the webhook receiver was never called")
	}
}

// TestWebhookSenderSwallowsFailures keeps a broken alerting integration from
// becoming an outage. Every one of these is a failure mode of somebody else's
// service, and none of them may propagate into the request that triggered the
// alert.
func TestWebhookSenderSwallowsFailures(t *testing.T) {
	t.Run("payload that cannot be marshaled", func(t *testing.T) {
		reached := make(chan struct{}, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached <- struct{}{}
		}))
		defer srv.Close()

		ws := NewWebhookSender(srv.URL)
		ws.Send(map[string]interface{}{"event": "auto_flag", "bad": make(chan int)})

		select {
		case <-reached:
			t.Error("an unmarshallable payload was still posted")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("receiver refuses the connection", func(t *testing.T) {
		ws := NewWebhookSender("http://" + deadAddr(t) + "/hook")
		ws.Send(map[string]interface{}{"event": "auto_flag"})
	})

	t.Run("receiver answers with an error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()

		ws := NewWebhookSender(srv.URL)
		ws.Send(map[string]interface{}{"event": "auto_flag"})
	})

	t.Run("URL that cannot be requested", func(t *testing.T) {
		ws := NewWebhookSender("://not-a-url")
		ws.Send(map[string]interface{}{"event": "auto_flag"})
	})
}

// TestBridgeSendsWebhookOnAutoFlag joins the sender to the detection path, since
// the alert is the only way an operator learns a flag happened without polling
// the admin API.
func TestBridgeSendsWebhookOnAutoFlag(t *testing.T) {
	payloads := make(chan map[string]interface{}, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			t.Errorf("webhook body: %v", err)
			return
		}
		payloads <- doc
	}))
	defer hook.Close()

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.FlagThreshold = 30
		cfg.WebhookURL = hook.URL
	})

	req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", "gobuster/3.6")
	resp := f.do(t, req)
	io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
	resp.Body.Close()

	select {
	case doc := <-payloads:
		if doc["event"] != "auto_flag" {
			t.Errorf("event = %v, want auto_flag", doc["event"])
		}
		if doc["ip"] != "127.0.0.1" {
			t.Errorf("ip = %v, want 127.0.0.1", doc["ip"])
		}
		if doc["reason"] != "auto:automation_ua" {
			t.Errorf("reason = %v, want auto:automation_ua", doc["reason"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook fired for an auto flag")
	}
}

// TestBridgeSendsWebhookOnLoginFailureFlag covers the second auto-flag site,
// which carries an extra field the first one does not.
func TestBridgeSendsWebhookOnLoginFailureFlag(t *testing.T) {
	payloads := make(chan map[string]interface{}, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			t.Errorf("webhook body: %v", err)
			return
		}
		payloads <- doc
	}))
	defer hook.Close()

	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, nil, func(cfg *Config) {
		cfg.LoginFailThreshold = 1
		cfg.FlagThreshold = 20
		cfg.WebhookURL = hook.URL
	})

	req, err := http.NewRequest(http.MethodPost, f.front.URL+"/auth/login", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.do(t, req)
	io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
	resp.Body.Close()

	select {
	case doc := <-payloads:
		if doc["reason"] != "login_failures" {
			t.Errorf("reason = %v, want login_failures", doc["reason"])
		}
		if count, ok := doc["failure_count"].(float64); !ok || count != 1 {
			t.Errorf("failure_count = %v, want 1", doc["failure_count"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook fired for a login-failure flag")
	}
}

// TestWebhookDispatchIsSynchronousAndObservable records a timing side channel.
//
// Send is called inline from ServeHTTP and from ServeDecoy, and it waits on an
// HTTP POST to an operator-supplied URL with a five second client timeout. The
// request that triggered the alert is therefore held for as long as the receiver
// takes to answer. docs/bridge.md states the attacker never knows they have been
// switched, but the flagging request is exactly the one that stalls, so a
// scanner watching its own latency sees the moment it was detected. A slow or
// hung webhook receiver turns that into seconds, and it does so on every decoy
// hit, which is also a cheap way to make the bridge's connections pile up.
//
// The fix is to dispatch the webhook from its own goroutine. The test asserts
// the current behavior so the change is visible when it is made.
func TestWebhookDispatchIsSynchronousAndObservable(t *testing.T) {
	const hookDelay = 400 * time.Millisecond

	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(hookDelay)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.WebhookURL = hook.URL
	})

	// A request that triggers no alert is the baseline.
	start := time.Now()
	resp, _ := f.get(t, "/auth/login")
	resp.Body.Close()
	clean := time.Since(start)

	// A decoy hit fires the webhook inline.
	start = time.Now()
	resp, _ = f.get(t, "/wp-admin")
	resp.Body.Close()
	trapped := time.Since(start)

	if trapped < hookDelay {
		t.Errorf("the decoy response took %v, want at least the webhook's %v; dispatch is now asynchronous and this test needs updating", trapped, hookDelay)
	}
	if clean > hookDelay {
		t.Errorf("an ordinary request took %v, which is as slow as the webhook delay; the baseline is not meaningful", clean)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestBridgeConcurrentRequestsDoNotCrossResponses is the test that would catch
// the worst possible failure in a proxy: one client receiving another client's
// response. Every request carries a unique marker that the upstream echoes into
// its body, so a crossed response shows up as a mismatch rather than as a
// coincidence. Under an authentication proxy a crossed response is a session
// token handed to the wrong person.
func TestBridgeConcurrentRequestsDoNotCrossResponses(t *testing.T) {
	f := newFixture(t, nil, nil, nil)

	const workers = 48
	const iterations = 12

	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				probe := fmt.Sprintf("w%d-i%d", w, i)

				req, err := http.NewRequest(http.MethodGet, f.front.URL+"/probe/"+probe, nil)
				if err != nil {
					errs <- err
					return
				}
				req.Header.Set("User-Agent", benignUA)
				req.Header.Set("X-Probe", probe)

				resp, err := f.front.Client().Do(req)
				if err != nil {
					errs <- fmt.Errorf("%s: %w", probe, err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					errs <- fmt.Errorf("%s: %w", probe, err)
					return
				}

				var doc struct {
					Upstream string `json:"upstream"`
					Probe    string `json:"probe"`
				}
				if err := json.Unmarshal(body, &doc); err != nil {
					errs <- fmt.Errorf("%s: body %q: %w", probe, body, err)
					return
				}
				if doc.Probe != probe {
					errs <- fmt.Errorf("request %s received the response for %q", probe, doc.Probe)
					return
				}
				if doc.Upstream != "real" {
					errs <- fmt.Errorf("request %s was served by %q, want real", probe, doc.Upstream)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if got := f.real.count(); got != workers*iterations {
		t.Errorf("the upstream saw %d requests, want %d", got, workers*iterations)
	}
	if got := f.honeypot.count(); got != 0 {
		t.Errorf("the honeypot saw %d requests, want 0", got)
	}
}

// TestBridgeConcurrentPerIPStateIsIsolated drives the handler from many
// goroutines with different client addresses at once, which is the shape of real
// traffic and the shape a loopback test client cannot produce on its own. Each
// address's own request sequence stays ordered, so the expected verdict for
// every request is exact: a scanner's fourth request is the one that crosses the
// threshold, and a browser's never does. Anything that leaked score or flag
// state between addresses shows up as a request served by the wrong upstream.
func TestBridgeConcurrentPerIPStateIsIsolated(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.FlagThreshold = 100
		cfg.RateThreshold = 1_000_000
	})

	const addresses = 24
	const requestsEach = 4

	type outcome struct {
		ip      string
		scanner bool
		served  []string
	}
	results := make(chan outcome, addresses)

	var wg sync.WaitGroup
	for i := 0; i < addresses; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			scanner := i%2 == 0
			ip := fmt.Sprintf("198.51.100.%d", i)
			ua := benignUA
			if scanner {
				ua = "nuclei/3.1.0"
			}

			var served []string
			for r := 0; r < requestsEach; r++ {
				req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
				req.RemoteAddr = ip + ":40000"
				req.Header.Set("User-Agent", ua)

				rec := httptest.NewRecorder()
				f.bridge.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					served = append(served, fmt.Sprintf("status-%d", rec.Code))
					continue
				}
				served = append(served, servedByOrEmpty(rec.Body.String()))
			}
			results <- outcome{ip: ip, scanner: scanner, served: served}
		}(i)
	}
	wg.Wait()
	close(results)

	scannerWant := strings.Join([]string{"real", "real", "real", "honeypot"}, ",")
	browserWant := strings.Join([]string{"real", "real", "real", "real"}, ",")

	seen := 0
	for got := range results {
		seen++
		want := browserWant
		if got.scanner {
			want = scannerWant
		}
		if strings.Join(got.served, ",") != want {
			t.Errorf("%s (scanner=%v) was served %v, want %s", got.ip, got.scanner, got.served, want)
		}
	}
	if seen != addresses {
		t.Fatalf("collected %d outcomes, want %d", seen, addresses)
	}

	// Exactly the scanner addresses are flagged, and each carries its own score.
	flagged := map[string]FlagEntry{}
	for _, e := range f.bridge.flags.List() {
		flagged[e.IP] = e
	}
	for i := 0; i < addresses; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		entry, ok := flagged[ip]
		if i%2 == 0 {
			if !ok {
				t.Errorf("%s should be flagged", ip)
				continue
			}
			if entry.Reason != "auto:automation_ua" {
				t.Errorf("%s reason = %q, want auto:automation_ua", ip, entry.Reason)
			}
			if entry.Score != 120 {
				t.Errorf("%s score = %d, want 120", ip, entry.Score)
			}
			continue
		}
		if ok {
			t.Errorf("%s should not be flagged, but is: %+v", ip, entry)
		}
		if got := f.bridge.scores.Get(ip); got != 0 {
			t.Errorf("%s score = %d, want 0", ip, got)
		}
	}
}

// TestBridgeConcurrentDecoyHitsFlagEveryCaller checks the trap under contention.
// A decoy hit writes to the flag store and the webhook from the request path, so
// a scan that sprays every decoy path from many addresses at once is exactly the
// traffic shape most likely to expose a race, and it is also the traffic shape
// the decoys exist to catch.
func TestBridgeConcurrentDecoyHitsFlagEveryCaller(t *testing.T) {
	var hookCalls int64
	var hookMu sync.Mutex
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hookMu.Lock()
		hookCalls++
		hookMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.WebhookURL = hook.URL
	})

	decoyPathList := []string{"/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma", "/cpanel", "/webmail", "/administrator"}

	const addresses = 28
	var wg sync.WaitGroup
	for i := 0; i < addresses; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := decoyPathList[i%len(decoyPathList)]

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = fmt.Sprintf("203.0.113.%d:40000", i)
			req.Header.Set("User-Agent", benignUA)

			rec := httptest.NewRecorder()
			f.bridge.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s from %d: status %d, want 200", path, i, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "<") {
				t.Errorf("%s from %d did not return a decoy page", path, i)
			}
		}(i)
	}
	wg.Wait()

	if f.real.count() != 0 || f.honeypot.count() != 0 {
		t.Errorf("decoy traffic was proxied: real=%d honeypot=%d", f.real.count(), f.honeypot.count())
	}

	entries := f.bridge.flags.List()
	if len(entries) != addresses {
		t.Fatalf("flag list has %d entries, want %d", len(entries), addresses)
	}
	for i := 0; i < addresses; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if !f.bridge.flags.IsFlagged(ip) {
			t.Errorf("%s was not flagged by its decoy hit", ip)
		}
	}

	hookMu.Lock()
	calls := hookCalls
	hookMu.Unlock()
	if calls != addresses {
		t.Errorf("the webhook fired %d times, want %d", calls, addresses)
	}
}

// TestBridgeConcurrentAdminAndTrafficShareTheStore runs the admin API against
// live proxy traffic. The admin handler and the request path touch the same flag
// store from different goroutines, and an operator flagging an address during an
// incident is precisely when that happens, so the two must not interfere.
func TestBridgeConcurrentAdminAndTrafficShareTheStore(t *testing.T) {
	f := newFixture(t, nil, nil, func(cfg *Config) {
		cfg.AdminToken = "test-token"
	})

	stop := make(chan struct{})
	var traffic, admin sync.WaitGroup

	// Traffic from a fixed set of addresses, some of which the operator is
	// flagging and unflagging underneath.
	for i := 0; i < 8; i++ {
		traffic.Add(1)
		go func(i int) {
			defer traffic.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
				req.RemoteAddr = fmt.Sprintf("192.0.2.%d:40000", i)
				req.Header.Set("User-Agent", benignUA)

				rec := httptest.NewRecorder()
				f.bridge.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("proxied request returned %d, want 200", rec.Code)
					return
				}
				// Whichever upstream answered, it must be one of the two and the
				// body must have arrived whole.
				if by := servedByOrEmpty(rec.Body.String()); by != "real" && by != "honeypot" {
					t.Errorf("response body %q names no upstream", rec.Body.String())
					return
				}
			}
		}(i)
	}

	for i := 0; i < 4; i++ {
		admin.Add(1)
		go func(i int) {
			defer admin.Done()
			for n := 0; n < 60; n++ {
				ip := fmt.Sprintf("192.0.2.%d", (i*2)%8)

				body := fmt.Sprintf(`{"ip":%q,"reason":"incident"}`, ip)
				req := httptest.NewRequest(http.MethodPost, "/bridge/flag", strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer test-token")
				rec := httptest.NewRecorder()
				f.bridge.admin.ServeFlag(rec, req)
				if rec.Code != http.StatusCreated {
					t.Errorf("admin flag returned %d, want 201", rec.Code)
					return
				}

				listReq := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
				listReq.Header.Set("Authorization", "Bearer test-token")
				listRec := httptest.NewRecorder()
				f.bridge.admin.ServeFlags(listRec, listReq)
				if listRec.Code != http.StatusOK {
					t.Errorf("admin list returned %d, want 200", listRec.Code)
					return
				}

				del := fmt.Sprintf(`{"ip":%q}`, ip)
				unReq := httptest.NewRequest(http.MethodDelete, "/bridge/flag", strings.NewReader(del))
				unReq.Header.Set("Authorization", "Bearer test-token")
				unRec := httptest.NewRecorder()
				f.bridge.admin.ServeFlag(unRec, unReq)
				if unRec.Code != http.StatusOK && unRec.Code != http.StatusNotFound {
					t.Errorf("admin unflag returned %d, want 200 or 404", unRec.Code)
					return
				}
			}
		}(i)
	}

	admin.Wait()
	close(stop)
	traffic.Wait()

	// The store must still be coherent: whatever is listed is flagged, and
	// whatever is flagged is listed.
	for _, e := range f.bridge.flags.List() {
		if !f.bridge.flags.IsFlagged(e.IP) {
			t.Errorf("%s is listed but IsFlagged says otherwise", e.IP)
		}
	}
}
