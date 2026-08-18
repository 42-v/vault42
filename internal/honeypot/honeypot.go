// Package honeypot provides threat observation capabilities for the Vault's
// honeypot deployment profile. It detects trap credential usage, suspicious
// request patterns, and dispatches alerts via webhook.
package honeypot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/deferwork"
	"github.com/42-v/vault42/internal/httputil"
)

// The attacker decides how often the trap fires, so they decide how many webhook
// posts leave the host unless something bounds it. Without a bound, a login loop
// against a trap address is an amplifier pointed at the operator's own alert
// channel, and the first alert (the one worth reading) arrives buried under
// thousands of copies. Each dispatch also holds a goroutine and a connection for
// up to the client timeout, so the same loop is a way to spend the honeypot's
// memory and sockets from off-host.
//
// The bound covers the outbound channel only. Every trigger is still audited.
const (
	// webhookBurst is how many alerts can leave back to back from a cold start.
	webhookBurst = 20
	// webhookRefillInterval is how long one dispatch slot takes to come back,
	// so a sustained attack costs the alert channel 20 posts a minute.
	webhookRefillInterval = 3 * time.Second
)

// alertBudget is a token bucket over webhook dispatches.
type alertBudget struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newAlertBudget(now time.Time) *alertBudget {
	return &alertBudget{tokens: webhookBurst, last: now}
}

// take reports whether a dispatch may go out now, spending a slot when it may.
func (b *alertBudget) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() / webhookRefillInterval.Seconds()
		if b.tokens > webhookBurst {
			b.tokens = webhookBurst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Event contains details about a suspicious activity detected in honeypot mode.
type Event struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"`
	IP          string            `json:"ip"`
	UserAgent   string            `json:"user_agent"`
	Email       string            `json:"email,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	RequestBody string            `json:"request_body,omitempty"`
	RiskScore   int               `json:"risk_score"`
}

// Alerter sends honeypot alerts via webhook and logs them to the audit trail.
type Alerter struct {
	webhookURL string
	trapUsers  map[string]bool
	auditLog   *audit.Logger
	client     *http.Client
	budget     *alertBudget
	// suppressed counts alerts dropped since the last dispatch, so a flood is
	// reported as a number rather than silently swallowed.
	suppressed atomic.Int64
}

// NewAlerter creates a honeypot alerter. The trapUsers slice is normalized to
// lowercase for case-insensitive matching. The webhookURL must use https:// or
// http:// scheme; invalid URLs are silently dropped (alerts will only be logged).
func NewAlerter(webhookURL string, trapUsers []string, auditLog *audit.Logger) *Alerter {
	// Validate webhook URL scheme to prevent SSRF via misconfiguration.
	sanitizedURL := ""
	if webhookURL != "" {
		if strings.HasPrefix(webhookURL, "https://") || strings.HasPrefix(webhookURL, "http://") {
			sanitizedURL = webhookURL
		} else {
			log.Printf("honeypot: ignoring webhook URL with disallowed scheme: %q", webhookURL)
		}
	}

	trap := make(map[string]bool, len(trapUsers))
	for _, u := range trapUsers {
		trap[strings.ToLower(strings.TrimSpace(u))] = true
	}
	return &Alerter{
		webhookURL: sanitizedURL,
		trapUsers:  trap,
		auditLog:   auditLog,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		budget: newAlertBudget(time.Now()),
	}
}

// IsTrapUser checks if the given identifier (email or username) matches a configured trap account.
func (a *Alerter) IsTrapUser(identifier string) bool {
	return a.trapUsers[strings.ToLower(strings.TrimSpace(identifier))]
}

// Alert sends a JSON POST to the webhook URL with attack details and logs an audit event.
// Webhook dispatch is best-effort — errors are logged but do not propagate.
func (a *Alerter) Alert(ctx context.Context, event Event) {
	// Audit log the trigger
	if a.auditLog != nil {
		a.auditLog.Log(ctx, audit.HoneypotTrigger, "", "", event.IP, event.UserAgent, "", "", // #nosec G104 -- audit is best-effort
			map[string]interface{}{
				"event_type": event.EventType,
				"email":      event.Email,
				"risk_score": event.RiskScore,
			})
	}

	// Send webhook
	if a.webhookURL == "" {
		return
	}

	// The audit entry above is written for every trigger; only the outbound
	// dispatch is rationed, so a flood costs the operator's alert channel but
	// never the record of what was tried.
	if !a.budget.take(time.Now()) {
		if a.suppressed.Add(1) == 1 {
			log.Print("honeypot: webhook alert budget exhausted, further alerts suppressed until it refills")
		}
		return
	}
	suppressed := a.suppressed.Swap(0)
	if suppressed > 0 {
		log.Printf("honeypot: %d webhook alerts were suppressed since the last dispatch", suppressed)
	}

	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("honeypot: marshal alert: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhookURL, bytes.NewReader(body)) // #nosec G107 -- webhookURL is operator-configured via VAULT_HONEYPOT_WEBHOOK env var, not user input
	if err != nil {
		log.Printf("honeypot: create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req) // #nosec G107 -- see above
	if err != nil {
		log.Printf("honeypot: webhook dispatch failed: %v", err)
		return
	}
	resp.Body.Close() // #nosec G104 -- best-effort webhook cleanup

	// Audit log the alert dispatch
	if a.auditLog != nil {
		meta := map[string]interface{}{
			"webhook_status": resp.StatusCode,
			"event_type":     event.EventType,
		}
		if suppressed > 0 {
			meta["suppressed_since_last"] = suppressed
		}
		a.auditLog.Log(ctx, audit.HoneypotAlert, "", "", event.IP, event.UserAgent, "", "", meta) // #nosec G104 -- audit is best-effort
	}

	if resp.StatusCode >= 400 {
		log.Printf("honeypot: webhook returned %d", resp.StatusCode)
	}
}

// RedactBody replaces password-like fields in a JSON body with "[REDACTED]".
func RedactBody(body string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return "[non-JSON body]"
	}
	for _, key := range []string{"password", "secret", "token", "code"} {
		if _, ok := m[key]; ok {
			m[key] = "[REDACTED]"
		}
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// CollectHeaders extracts request headers into a string map, skipping
// Authorization and Cookie for safety.
func CollectHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "cookie" {
			headers[k] = "[REDACTED]"
			continue
		}
		headers[k] = strings.Join(v, ", ")
	}
	return headers
}

// IsAutomationUA checks if the User-Agent string suggests an automated tool.
func IsAutomationUA(ua string) bool {
	lower := strings.ToLower(ua)
	patterns := []string{
		"curl", "wget", "python-requests", "python-urllib",
		"httpie", "go-http-client", "java/", "libwww-perl",
		"scrapy", "bot", "crawler", "spider", "nikto",
		"sqlmap", "nmap", "masscan", "zap", "burp",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// The event types the HTTP surface raises, and what each one is worth.
//
// Choosing what a deception surface alerts on is the whole design problem. Every
// request that arrives is by definition unexpected -- nobody has a reason to
// visit a trap -- so "alert on the unexpected" degenerates into alerting on all
// of it, which is an amplifier the attacker points at the operator's own channel
// and which buries the first alert worth reading under a week of internet
// background scanning. Alerting on none of it is what shipped.
//
// What separates the two is whether the caller has spent something. Scanning is
// free and constant. Presenting a credential is not: it means the caller has
// stopped enumerating and is spending a value they obtained somewhere, and on a
// honeypot there is no legitimate user for that value to belong to. That is
// exceptional on a single occurrence, which is what makes it a threshold-one
// rule rather than a windowed count.
//
// Volume-shaped detection -- one source failing over and over, one subject
// attacked from everywhere -- is deliberately not built here. It is a windowed
// counter with per-class thresholds and a cooldown, it belongs to the whole
// service rather than to the honeypot profile, and a second one built inside
// this package would be the copy that has to be deleted later.
const (
	// EventCredentialPresented is a caller spending something they believe is a
	// credential against the trap.
	EventCredentialPresented = "honeypot_credential_presented"
	// EventTrapTokenReplayed is a token this process minted arriving back at it.
	// It is not an inference about intent: the bait was taken and spent.
	EventTrapTokenReplayed = "honeypot_trap_token_replayed"
)

// Risk scores on the 0-100 scale internal/audit already uses, so an alert from
// here sorts against one from the trap login path rather than against a private
// scale. trapLogin files 100; a replayed trap token is the same certainty about
// the same attacker and is scored the same.
const (
	riskAutomationUA        = 30
	riskCredentialPresented = 60
	riskTrapTokenReplayed   = 100
)

// maxJWTHeaderSegment bounds the base64 segment this package will decode out of
// an Authorization header. A real JOSE header is a few dozen bytes; net/http
// will hand over a megabyte of them. The caller is anonymous and chooses the
// length, so the decode is bounded rather than trusted.
const maxJWTHeaderSegment = 1024

// maxCapturedBody bounds what an alert copies out of a request body.
//
// The caller chooses the length, so an unbounded copy would be a way to spend
// this process's memory from off-host and to put an arbitrarily long string in
// front of whoever reads the alert. Four kilobytes is half the global body cap
// and comfortably more than any credential-bearing request the real vault
// accepts, so a truncated capture means the caller was not sending a login.
const maxCapturedBody = 4096

// captureBody copies the front of a request body for the alert and puts back
// exactly what it took.
//
// Putting it back is the part that matters. A middleware that consumes the body
// to inspect it and does not restore it makes the trap answer differently from
// the real vault on every request with a body, which is a tell an attacker buys
// for the price of one POST. The handler behind this reads the same bytes in the
// same order it would have read; only the copy in the alert is truncated.
//
// The global body cap is applied outside this middleware, so what is read here
// is already bounded by it, and the bytes handed back are not counted twice: the
// limit reader upstream has already delivered them.
func captureBody(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}

	captured, err := io.ReadAll(io.LimitReader(r.Body, maxCapturedBody))
	if len(captured) == 0 {
		// Nothing was taken, so there is nothing to put back. An error with no
		// bytes is the handler's to surface on its own read, not this one's.
		return ""
	}
	if err != nil {
		log.Printf("honeypot: reading request body for the alert: %v", err)
	}

	r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(captured), r.Body), Closer: r.Body}
	return RedactBody(string(captured))
}

// readCloser rejoins a replayed prefix to the rest of a body while leaving Close
// with the original, so the server still closes what it opened.
type readCloser struct {
	io.Reader
	io.Closer
}

// credentialAlert classifies one request and reports the alert it deserves, if
// any. It reads only the request, so the decision is made before the handler
// runs and cannot be changed by what the handler does to r.
func credentialAlert(r *http.Request) (eventType string, risk int, ok bool) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" && r.Header.Get("DPoP") == "" {
		return "", 0, false
	}

	if presentsTrapToken(authorization, mintedTrapKID()) {
		return EventTrapTokenReplayed, riskTrapTokenReplayed, true
	}
	return EventCredentialPresented, riskCredentialPresented, true
}

// presentsTrapToken reports whether an Authorization header carries a JWT whose
// kid is the one this process signs trap tokens under.
//
// The kid is read out of the JOSE header and the signature is deliberately not
// verified. Verifying would be strictly more work on an anonymous caller's
// request for an answer that changes nothing: a caller holding the trap's kid
// either replayed a token the trap issued them or forged the header of one, and
// either way they are engaging with the trap on purpose. The alert reports what
// was observed -- a token claiming the trap's key -- and claims no more.
//
// kid is passed in rather than read here so this is a function of its arguments
// and nothing else: every branch below is then reachable from a table without a
// test having to reach into the package's process-wide signing key and put it
// back. An empty kid means no trap token has ever been minted in this process,
// and a token that does not exist cannot have come back.
func presentsTrapToken(authorization, kid string) bool {
	if kid == "" {
		return false
	}

	const bearer = "bearer "
	if len(authorization) < len(bearer) || !strings.EqualFold(authorization[:len(bearer)], bearer) {
		return false
	}

	segment, _, found := strings.Cut(strings.TrimSpace(authorization[len(bearer):]), ".")
	if !found || segment == "" || len(segment) > maxJWTHeaderSegment {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}

	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	return header.KID == kid
}

// LoggingMiddleware wraps an HTTP handler to log every request and response in
// honeypot mode, and raises an alert for the requests that deserve one.
//
// Every request is logged; that record is the threat-analysis surface and is
// unbounded on purpose. Only credential presentation is alerted, and only within
// a budget. See the event constants above for why that is the line.
func LoggingMiddleware(alerter *Alerter) func(http.Handler) http.Handler {
	// A budget of this middleware's own, on top of the one Alerter keeps over its
	// webhook. Alerter.Alert writes the audit row before it consults its own
	// budget -- deliberately, so a trap login is never lost -- which means an
	// unbounded caller here would spend the honeypot's audit storage instead of
	// its webhook quota. The attacker chooses how many credential-bearing
	// requests arrive, so the bound belongs on this side of the call too.
	budget := newAlertBudget(time.Now())
	var suppressed atomic.Int64

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 200}

			// Classified, budgeted and dispatched before the handler runs. The
			// alert has to describe the request as it arrived, and a handler
			// downstream is free to add headers to r; doing the work here also
			// means a flood that the budget refuses costs no allocation at all.
			eventType, credentialRisk, alertable := credentialAlert(r)
			risk := requestRisk(r.UserAgent(), credentialRisk)
			if alertable && alerter != nil && takeAlertSlot(budget, &suppressed) {
				// The slot is spent before anything is copied, so a flood the
				// budget refuses costs neither a header map nor a body read.
				event := Event{
					Timestamp:   start,
					EventType:   eventType,
					IP:          r.RemoteAddr,
					UserAgent:   r.UserAgent(),
					Headers:     CollectHeaders(r),
					RequestBody: captureBody(r),
					RiskScore:   risk,
				}
				// Deferred for the reason the trap login path defers its own:
				// this runs inside the request, and Alert opens a connection to
				// the operator's endpoint with a five-second timeout. Inline,
				// that timeout is latency on the attacker's own connection --
				// which makes the alert timeable, and holds a goroutine and a
				// socket for every request they choose to send.
				deferwork.Go(func(ctx context.Context) { alerter.Alert(ctx, event) })
			}

			next.ServeHTTP(rw, r)

			log.Printf("honeypot: %s %s %s %d %s ua=%q risk=%d", // #nosec G706 -- sanitized via SafeLogValue
				httputil.SafeLogValue(r.Method), httputil.SafeLogValue(r.URL.Path), httputil.SafeLogValue(r.RemoteAddr),
				rw.status, time.Since(start).Round(time.Millisecond),
				httputil.SafeLogValue(r.UserAgent()), risk)
		})
	}
}

// requestRisk scores one request on the 0-100 audit scale.
//
// The two signals add because they are independent -- a scripted client spending
// a credential is worse than either alone -- and the sum is clamped because the
// scale has a top and a score above it would sort ahead of trapLogin's 100 while
// meaning less.
func requestRisk(userAgent string, credentialRisk int) int {
	risk := credentialRisk
	if IsAutomationUA(userAgent) {
		risk += riskAutomationUA
	}
	if risk > riskTrapTokenReplayed {
		risk = riskTrapTokenReplayed
	}
	return risk
}

// takeAlertSlot reports whether this request may raise an alert, spending a slot
// from the budget when it may and counting it when it may not.
//
// A refusal is counted rather than dropped, and the count is carried into the
// next alert that does get through, so a flood is reported as a number. Silently
// swallowing them would make the alert channel misrepresent the attack: the
// operator would see one credential presentation where there had been a
// thousand, and the bound on the channel would have become a lie about the
// traffic.
func takeAlertSlot(budget *alertBudget, suppressed *atomic.Int64) bool {
	if !budget.take(time.Now()) {
		if suppressed.Add(1) == 1 {
			log.Print("honeypot: request alert budget exhausted, further alerts suppressed until it refills")
		}
		return false
	}
	if n := suppressed.Swap(0); n > 0 {
		log.Printf("honeypot: %d request alerts were suppressed since the last dispatch", n)
	}
	return true
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush and Hijack forward to the wrapped writer, the same two the standard
// logging middleware's recorder forwards.
//
// This wrapper is the one the handler sees, and only in the honeypot profile.
// Swallowing the two capabilities would make a streaming response buffer and a
// connection upgrade fail on the trap while both work on the real deployment,
// which is a difference an attacker gets for the price of one request.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("honeypot: underlying ResponseWriter does not implement http.Hijacker")
}

// Err returns a formatted error for honeypot operations.
func Err(msg string) error {
	return fmt.Errorf("honeypot: %s", msg)
}
