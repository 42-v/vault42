package honeypot

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
)

// LoggingMiddleware took an *Alerter and never read it. The identifier appeared
// once in the whole file, in the signature, so the honeypot's HTTP surface
// logged every request and raised nothing, while the parameter told every
// reader otherwise. These tests pin what it now raises, and just as importantly
// what it does not: a deception surface receives only unexpected requests, so a
// rule that fires on each one is an amplifier pointed at the operator and a rule
// that fires on none is what shipped.

// awaitEntries waits for the deferred dispatch to reach the audit spy.
//
// The alert is raised on the deferwork pool for the reason the trap login path
// gives: the response is not finished until the middleware returns, so a
// synchronous webhook post would spend its timeout on the attacker's own request
// and make the alert timeable from off-host. The process-wide pool cannot be
// drained from one test without closing it for every later one, so this polls.
func awaitEntries(t *testing.T, mu *sync.Mutex, entries *[]*model.AuditEntry, want int) []*model.AuditEntry {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := len(*entries)
		if got >= want {
			out := append([]*model.AuditEntry(nil), (*entries)...)
			mu.Unlock()
			return out
		}
		mu.Unlock()

		if time.Now().After(deadline) {
			t.Fatalf("audit entries = %d after 2s, want at least %d", got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// quietFor gives the deferred dispatch time to happen and then asserts it did
// not. A negative that returns instantly would pass against a middleware that
// alerts on everything, purely because the pool had not run yet.
func quietFor(t *testing.T, mu *sync.Mutex, entries *[]*model.AuditEntry, d time.Duration) {
	t.Helper()

	time.Sleep(d)
	mu.Lock()
	defer mu.Unlock()
	if len(*entries) != 0 {
		t.Fatalf("audit entries = %d, want none: an ordinary scan of the trap must be "+
			"logged and not alerted, or the first alert worth reading arrives buried "+
			"under every port scan the internet runs", len(*entries))
	}
}

// alertingMiddleware returns the middleware under test wired to an audit spy.
func alertingMiddleware(t *testing.T, mu *sync.Mutex, entries *[]*model.AuditEntry) http.Handler {
	t.Helper()

	a := NewAlerter("", nil, apAuditSpyLocked(mu, entries))
	return LoggingMiddleware(a)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// A request that presents a credential to the trap is the honeypot's
// threshold-one signal: there are no legitimate users here, so an Authorization
// header means the caller has stopped scanning and started spending something
// they believe is a credential.
func TestLoggingMiddleware_AlertsWhenARequestPresentsACredential(t *testing.T) {
	var mu sync.Mutex
	var entries []*model.AuditEntry
	handler := alertingMiddleware(t, &mu, &entries)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig")
	req.RemoteAddr = "203.0.113.9:5555"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := awaitEntries(t, &mu, &entries, 1)
	if got[0].EventType != audit.HoneypotTrigger {
		t.Errorf("audit event type = %q, want %q", got[0].EventType, audit.HoneypotTrigger)
	}
	if got[0].Metadata["event_type"] != EventCredentialPresented {
		t.Errorf("alert event_type = %v, want %q", got[0].Metadata["event_type"], EventCredentialPresented)
	}
}

// A DPoP proof is only ever sent by a client that believes it holds a
// sender-bound token. Nothing sends one by accident, so it is the same signal.
func TestLoggingMiddleware_AlertsOnADPoPProof(t *testing.T) {
	var mu sync.Mutex
	var entries []*model.AuditEntry
	handler := alertingMiddleware(t, &mu, &entries)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("DPoP", "eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.sig")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	awaitEntries(t, &mu, &entries, 1)
}

// The flood case, stated as a test so it cannot be regressed into by someone
// making the rule "every request to a honeypot is suspicious", which is true and
// is exactly why it is useless as an alerting rule.
func TestLoggingMiddleware_DoesNotAlertOnAnOrdinaryRequest(t *testing.T) {
	var mu sync.Mutex
	var entries []*model.AuditEntry
	handler := alertingMiddleware(t, &mu, &entries)

	for _, path := range []string{"/", "/auth/login", "/.env", "/wp-admin/setup-config.php"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", "curl/8.5.0")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	quietFor(t, &mu, &entries, 150*time.Millisecond)
}

// The bait coming back is the one event the whole deception exists to produce.
// A token this process minted, presented to this process, is not a guess about
// intent: the attacker took a trap credential and spent it.
func TestLoggingMiddleware_TrapTokenReplayIsItsOwnEvent(t *testing.T) {
	token, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "trap@example.com"})
	if err != nil {
		t.Fatalf("mint trap token: %v", err)
	}

	var mu sync.Mutex
	var entries []*model.AuditEntry
	handler := alertingMiddleware(t, &mu, &entries)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := awaitEntries(t, &mu, &entries, 1)
	if got[0].Metadata["event_type"] != EventTrapTokenReplayed {
		t.Errorf("alert event_type = %v, want %q; a token the trap itself signed came "+
			"back and was reported as an ordinary credential", got[0].Metadata["event_type"], EventTrapTokenReplayed)
	}
	if score, _ := got[0].Metadata["risk_score"].(int); score != riskTrapTokenReplayed {
		t.Errorf("risk_score = %v, want %d", got[0].Metadata["risk_score"], riskTrapTokenReplayed)
	}
}

// The alert carries the request headers, with the credential itself redacted.
// The operator needs to see what the caller sent; the alert channel is not a
// place to copy a bearer token to.
func TestLoggingMiddleware_TheAlertCarriesRedactedHeaders(t *testing.T) {
	posted := make(chan Event, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err == nil {
			posted <- e
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	handler := LoggingMiddleware(NewAlerter(srv.URL, nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer secret-value")
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case e := <-posted:
		if e.Headers["Authorization"] != "[REDACTED]" {
			t.Errorf("Authorization header reached the alert as %q; CollectHeaders redacts it",
				e.Headers["Authorization"])
		}
		if e.Headers["X-Forwarded-For"] != "198.51.100.4" {
			t.Errorf("X-Forwarded-For = %q, want the value the caller sent", e.Headers["X-Forwarded-For"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook dispatch within 2s")
	}
}

// The alert must not be timeable. Alerter.Alert posts to the operator's webhook
// with a five-second client timeout, and this middleware runs inside the
// request, so dispatching it inline would spend that timeout on the attacker's
// own connection: "did that raise an alert" becomes a question answerable with a
// stopwatch, and asking it repeatedly holds a goroutine and a socket per ask.
func TestLoggingMiddleware_TheAlertDoesNotDelayTheResponse(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(release); srv.Close() }()

	handler := LoggingMiddleware(NewAlerter(srv.URL, nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer token")

	start := time.Now()
	handler.ServeHTTP(httptest.NewRecorder(), req)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("the request took %s while the alert webhook hung; the dispatch is on the "+
			"request path, so an attacker can time whether they tripped an alert and can "+
			"hold a connection open per attempt", elapsed)
	}
}

// The bound. An attacker decides how many credential-bearing requests arrive, so
// without one this alert is a way to spend the operator's audit storage and
// their alert channel from off-host -- the amplifier the webhook budget already
// exists to prevent one layer down.
func TestLoggingMiddleware_AlertFloodIsBounded(t *testing.T) {
	var mu sync.Mutex
	var entries []*model.AuditEntry
	handler := alertingMiddleware(t, &mu, &entries)

	const flood = 400
	for i := 0; i < flood; i++ {
		req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		req.Header.Set("Authorization", "Bearer token")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	awaitEntries(t, &mu, &entries, 1)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	got := len(entries)
	mu.Unlock()

	if got > webhookBurst+2 {
		t.Errorf("%d of %d flooded requests raised an alert; the burst allowance is %d, so "+
			"an attacker sets how much of the operator's alert channel and audit store they "+
			"spend", got, flood, webhookBurst)
	}
	if got == 0 {
		t.Error("the flood raised nothing at all; the bound must ration the alert, not remove it")
	}
}

// presentsTrapToken is a function of its arguments, so every way an
// attacker-supplied Authorization header can fail to be a trap token is a row
// here rather than a branch nothing reaches. The header is anonymous input: the
// scheme, the segment count, the base64 and the JSON are all things the caller
// chooses, and each one has to end in "no" rather than in a panic or a decode of
// something unbounded.
func TestPresentsTrapToken(t *testing.T) {
	const kid = "trap-kid"
	trapHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"trap-kid"}`))
	otherHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"real-kid"}`))
	noKID := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))

	cases := []struct {
		name          string
		authorization string
		kid           string
		want          bool
	}{
		{"a token signed under the trap kid", "Bearer " + trapHeader + ".e30.sig", kid, true},
		{"the scheme is matched case-insensitively", "bearer " + trapHeader + ".e30.sig", kid, true},
		{"no trap token has been minted in this process", "Bearer " + trapHeader + ".e30.sig", "", false},
		{"a real token from somewhere else", "Bearer " + otherHeader + ".e30.sig", kid, false},
		{"a JOSE header carrying no kid", "Bearer " + noKID + ".e30.sig", kid, false},
		{"a scheme that is not Bearer", "DPoP " + trapHeader + ".e30.sig", kid, false},
		{"a header shorter than the scheme", "x", kid, false},
		{"an opaque credential with no dot in it", "Bearer opaque-session-value", kid, false},
		{"an empty first segment", "Bearer .e30.sig", kid, false},
		{"a first segment longer than any real JOSE header", "Bearer " + strings.Repeat("A", maxJWTHeaderSegment+1) + ".e30.sig", kid, false},
		{"a first segment that is not base64", "Bearer !!!!.e30.sig", kid, false},
		{"a first segment that decodes to something that is not JSON", "Bearer " + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".e30.sig", kid, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := presentsTrapToken(tc.authorization, tc.kid); got != tc.want {
				t.Errorf("presentsTrapToken(%q, %q) = %t, want %t", tc.authorization, tc.kid, got, tc.want)
			}
		})
	}
}

// The two risk signals add, and the sum is clamped. Without the clamp a scripted
// client replaying a trap token scores 130 on a scale whose top is 100, which
// would sort it ahead of the trap login path's own 100 while meaning no more.
func TestRequestRisk(t *testing.T) {
	cases := []struct {
		name           string
		userAgent      string
		credentialRisk int
		want           int
	}{
		{"a browser just looking", "Mozilla/5.0", 0, 0},
		{"a scripted client just looking", "curl/8.5.0", 0, riskAutomationUA},
		{"a browser spending a credential", "Mozilla/5.0", riskCredentialPresented, riskCredentialPresented},
		{"a scripted client spending a credential", "curl/8.5.0", riskCredentialPresented, riskCredentialPresented + riskAutomationUA},
		{"a scripted client replaying a trap token clamps at the top of the scale", "curl/8.5.0", riskTrapTokenReplayed, riskTrapTokenReplayed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestRisk(tc.userAgent, tc.credentialRisk); got != tc.want {
				t.Errorf("requestRisk(%q, %d) = %d, want %d", tc.userAgent, tc.credentialRisk, got, tc.want)
			}
		})
	}
}

// mintedTrapKID must never generate the key. Its caller is the HTTP middleware
// on an anonymous request, and an RSA generation there would put several hundred
// milliseconds on whichever request arrived first -- the timing tell that
// TrapSigningKey's startup call exists to pay off before an attacker can see it.
func TestMintedTrapKIDDoesNotGenerateTheKey(t *testing.T) {
	before := mintedTrapKID()

	kid, _, err := TrapSigningKey()
	if err != nil {
		t.Fatalf("TrapSigningKey: %v", err)
	}
	if after := mintedTrapKID(); after != kid {
		t.Errorf("mintedTrapKID() = %q after the key was generated, want the generated kid %q", after, kid)
	}
	if before != "" && before != kid {
		t.Errorf("mintedTrapKID() returned %q before generation and %q after; it must report the "+
			"one key this process signs trap tokens with", before, kid)
	}
}

// A flood that the budget refuses must be reported as a number when the next
// alert gets through. Silently swallowing them would make the alert channel
// misrepresent the attack: the operator would see one credential presentation
// where there had been a thousand, and the budget would have turned a bound on
// the channel into a lie about the traffic.
func TestTakeAlertSlot_ReportsHowManyItSuppressed(t *testing.T) {
	buf := captureLog(t)

	// An empty bucket with no time elapsed against it: every call is refused.
	budget := &alertBudget{last: time.Now()}
	var suppressed atomic.Int64
	for i := 0; i < 3; i++ {
		if takeAlertSlot(budget, &suppressed) {
			t.Fatalf("call %d took a slot from an empty budget", i)
		}
	}
	if got := suppressed.Load(); got != 3 {
		t.Fatalf("suppressed = %d, want 3 refusals recorded", got)
	}
	if got := buf.String(); !strings.Contains(got, "budget exhausted") {
		t.Errorf("log = %q, want the exhaustion reported once", got)
	}

	// Enough time passes for a slot to come back.
	budget.last = time.Now().Add(-2 * webhookRefillInterval)
	if !takeAlertSlot(budget, &suppressed) {
		t.Fatal("the budget refused a slot after a refill interval had passed")
	}
	if got := buf.String(); !strings.Contains(got, "3 request alerts were suppressed") {
		t.Errorf("log = %q, want the suppressed count carried into the next dispatch", got)
	}
	if got := suppressed.Load(); got != 0 {
		t.Errorf("suppressed = %d after the count was reported, want it reset", got)
	}
}

// The alert carries what the caller actually sent, with the credential-like
// fields masked. Event.RequestBody existed and was never assigned anywhere in
// the tree, and RedactBody -- the function written to fill it -- had no caller;
// capturing what an attacker posted is most of what a deception surface is for.
func TestLoggingMiddleware_TheAlertCarriesTheRedactedRequestBody(t *testing.T) {
	posted := make(chan Event, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err == nil {
			posted <- e
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var seen string
	handler := LoggingMiddleware(NewAlerter(srv.URL, nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = string(body)
		w.WriteHeader(http.StatusOK)
	}))

	const sent = `{"email":"victim@example.com","password":"hunter2","token":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(sent))
	req.Header.Set("Authorization", "Bearer stolen")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// The handler behind the trap must still read every byte the caller sent.
	// A middleware that consumes the body to inspect it and does not put it back
	// makes the trap answer differently from the real vault, which is a tell an
	// attacker gets for the price of one request.
	if seen != sent {
		t.Errorf("the handler read %q, want the whole body %q", seen, sent)
	}

	select {
	case e := <-posted:
		if strings.Contains(e.RequestBody, "hunter2") || strings.Contains(e.RequestBody, "abc") {
			t.Errorf("the alert carries unredacted secrets: %q", e.RequestBody)
		}
		if !strings.Contains(e.RequestBody, "victim@example.com") {
			t.Errorf("the alert dropped the part worth reading: %q", e.RequestBody)
		}
		if !strings.Contains(e.RequestBody, "[REDACTED]") {
			t.Errorf("RequestBody = %q, want the password-like fields masked", e.RequestBody)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook dispatch within 2s")
	}
}

// The capture is bounded. The caller chooses the length, and an unbounded copy
// on the alerting path is a way to spend the honeypot's memory from off-host --
// and to put an arbitrarily large string in front of whoever reads the alert.
// The handler must still see the whole body: only the copy is truncated.
func TestLoggingMiddleware_TheCapturedBodyIsBounded(t *testing.T) {
	posted := make(chan Event, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err == nil {
			posted <- e
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var seenLen int
	handler := LoggingMiddleware(NewAlerter(srv.URL, nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenLen = len(body)
		w.WriteHeader(http.StatusOK)
	}))

	sent := strings.Repeat("A", maxCapturedBody*3)
	req := httptest.NewRequest(http.MethodPost, "/user/blobs", strings.NewReader(sent))
	req.Header.Set("Authorization", "Bearer stolen")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seenLen != len(sent) {
		t.Errorf("the handler read %d bytes, want all %d: the capture must put back what it took",
			seenLen, len(sent))
	}

	select {
	case e := <-posted:
		if len(e.RequestBody) > len(sent) {
			t.Errorf("the alert carries %d bytes for a %d-byte body", len(e.RequestBody), len(sent))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook dispatch within 2s")
	}

	// How many bytes the capture actually reads is asserted in TestCaptureBody:
	// a truncated body is not valid JSON, so RedactBody answers "[non-JSON body]"
	// whether the bound held or not, and this test cannot see the difference.
}

// A request with no body at all must not acquire one, and must not cost a
// capture. Most scan traffic is a bare GET.
func TestLoggingMiddleware_ABodylessRequestCapturesNothing(t *testing.T) {
	posted := make(chan Event, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err == nil {
			posted <- e
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	handler := LoggingMiddleware(NewAlerter(srv.URL, nil, nil))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Header.Set("Authorization", "Bearer stolen")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case e := <-posted:
		if e.RequestBody != "" {
			t.Errorf("RequestBody = %q for a request that carried none", e.RequestBody)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook dispatch within 2s")
	}
}

// failingBody yields a prefix and then fails, the shape a client that
// disconnects mid-upload produces.
type failingBody struct {
	prefix string
	done   bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, errors.New("connection reset")
	}
	b.done = true
	return copy(p, b.prefix), nil
}

func (b *failingBody) Close() error { return nil }

// captureBody's job is to leave the request as it found it. These are the cases
// the middleware tests cannot reach: a request built without a body at all, and
// a body that fails partway through.
func TestCaptureBody(t *testing.T) {
	t.Run("a request with no body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		r.Body = nil
		if got := captureBody(r); got != "" {
			t.Errorf("captureBody = %q, want empty", got)
		}
		if r.Body != nil {
			t.Error("captureBody gave a body to a request that had none")
		}
	})

	t.Run("http.NoBody", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		r.Body = http.NoBody
		if got := captureBody(r); got != "" {
			t.Errorf("captureBody = %q, want empty", got)
		}
	})

	t.Run("a body that fails after yielding bytes", func(t *testing.T) {
		buf := captureLog(t)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		r.Body = &failingBody{prefix: `{"password":"hunter2"}`}

		got := captureBody(r)
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("captureBody = %q, want the bytes that did arrive, redacted", got)
		}
		if !strings.Contains(buf.String(), "reading request body for the alert") {
			t.Errorf("log = %q, want the read failure reported", buf.String())
		}
	})

	t.Run("reads no more than the cap", func(t *testing.T) {
		body := &countingBody{remaining: maxCapturedBody * 3}
		r := httptest.NewRequest(http.MethodPost, "/user/blobs", nil)
		r.Body = body

		captureBody(r)

		if body.read > maxCapturedBody {
			t.Errorf("captureBody read %d bytes, want no more than %d. The caller chooses the "+
				"length, so an unbounded copy is a way to spend this process's memory from "+
				"off-host.", body.read, maxCapturedBody)
		}
		if body.read == 0 {
			t.Error("captureBody read nothing; the bound must truncate the copy, not remove it")
		}
	})

	t.Run("a body that fails before yielding anything", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		r.Body = &failingBody{prefix: "", done: true}
		if got := captureBody(r); got != "" {
			t.Errorf("captureBody = %q, want empty when nothing was read", got)
		}
	})
}

// countingBody reports how many bytes were taken from it, so the capture's bound
// is asserted against the read rather than against what survived redaction.
type countingBody struct {
	remaining int
	read      int
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > b.remaining {
		n = b.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'A'
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (b *countingBody) Close() error { return nil }
