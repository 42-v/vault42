package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bridge is the main reverse proxy that routes between real and honeypot Vaults.
type Bridge struct {
	cfg           *Config
	realProxy     *httputil.ReverseProxy
	honeypotProxy *httputil.ReverseProxy
	flags         *FlagStore
	rateTracker   *RateTracker
	loginFails    *LoginFailTracker
	scores        *ScoreMap
	decoys        *DecoyHandler
	admin         *AdminHandler
	health        *HealthHandler
	webhook       *WebhookSender
	// inflight caps concurrently proxied requests. nil when the operator has
	// disabled the cap.
	inflight chan struct{}
}

// ScoreMap tracks cumulative scores per IP.
type ScoreMap struct {
	mu     sync.Mutex
	scores map[string]scoreEntry
}

type scoreEntry struct {
	n    int
	seen time.Time
}

// NewScoreMap creates a new score tracker.
func NewScoreMap() *ScoreMap {
	return &ScoreMap{scores: make(map[string]scoreEntry)}
}

// Add adds a score delta and returns the new total.
//
// At maxTrackedIPs a previously unseen address is scored but not stored: live
// totals do not decay, so entries survive for FlagTTL (24h by default) and an
// address-varying flood otherwise chooses the map size. Refusing the insert
// costs nothing an attacker did not already have — one score of `delta` is what
// a fresh address gets either way — and the reaper drains the map on its tick.
func (sm *ScoreMap) Add(ip string, delta int) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	ent, tracked := sm.scores[ip]
	if !tracked && len(sm.scores) >= maxTrackedIPs {
		return delta
	}
	ent.n += delta
	ent.seen = time.Now()
	sm.scores[ip] = ent
	return ent.n
}

// Get returns the current score for an IP.
func (sm *ScoreMap) Get(ip string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.scores[ip].n
}

// Reap drops addresses that have not scored within maxAge. Live totals are
// left alone: decaying an active score would reset a scanner's budget every
// sweep and let it stay under the flag threshold indefinitely.
func (sm *ScoreMap) Reap(maxAge time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, ent := range sm.scores {
		if ent.seen.Before(cutoff) {
			delete(sm.scores, ip)
		}
	}
}

// NewBridge creates the bridge proxy.
func NewBridge(cfg *Config) (*Bridge, error) {
	realURL, err := url.Parse(cfg.RealUpstream)
	if err != nil {
		return nil, err
	}
	honeypotURL, err := url.Parse(cfg.HoneypotUpstream)
	if err != nil {
		return nil, err
	}

	webhook := NewWebhookSender(cfg.WebhookURL)

	b := &Bridge{
		cfg:           cfg,
		realProxy:     newBoundedProxy(realURL),
		honeypotProxy: newBoundedProxy(honeypotURL),
		flags:         NewFlagStore(cfg.FlagTTL, cfg.RedisAddr),
		rateTracker:   NewRateTracker(cfg.RateWindow),
		loginFails:    NewLoginFailTracker(cfg.LoginFailWindow),
		scores:        NewScoreMap(),
		webhook:       webhook,
	}

	if cfg.MaxInflight > 0 {
		b.inflight = make(chan struct{}, cfg.MaxInflight)
	}

	b.decoys = NewDecoyHandler(b.flags, webhook)
	b.admin = NewAdminHandler(b.flags, cfg.AdminToken)
	b.health = NewHealthHandler(cfg.RealUpstream, cfg.HoneypotUpstream)

	// Remember the inbound path before Director rewrites URL.Path to include
	// the upstream prefix. inspectLoginResponse has to compare that inbound
	// path, not the outbound one.
	b.realProxy.Director = rememberInboundPath(b.realProxy.Director)
	// ModifyResponse on realProxy: inspect login failures
	b.realProxy.ModifyResponse = b.inspectLoginResponse

	return b, nil
}

// Upstream transport bounds. http.DefaultTransport sets neither
// MaxConnsPerHost nor ResponseHeaderTimeout, so an upstream that accepts a
// connection and then goes quiet — a wedged honeypot, a vault whose pool is
// exhausted — held one bridge goroutine and one socket per in-flight request
// until the 30s write timeout, with nothing capping how many of those there
// could be.
const (
	upstreamMaxConnsPerHost     = 256
	upstreamMaxIdleConnsPerHost = 32
	upstreamResponseHeaderTO    = 10 * time.Second
	upstreamIdleConnTimeout     = 90 * time.Second
	upstreamTLSHandshakeTO      = 5 * time.Second
	upstreamExpectContinueTO    = 1 * time.Second
	upstreamDialTimeout         = 5 * time.Second
	upstreamKeepAlive           = 30 * time.Second
)

// newBoundedProxy builds a reverse proxy whose transport has explicit limits.
func newBoundedProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	p.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   upstreamDialTimeout,
			KeepAlive: upstreamKeepAlive,
		}).DialContext,
		MaxConnsPerHost:       upstreamMaxConnsPerHost,
		MaxIdleConns:          upstreamMaxConnsPerHost,
		MaxIdleConnsPerHost:   upstreamMaxIdleConnsPerHost,
		IdleConnTimeout:       upstreamIdleConnTimeout,
		ResponseHeaderTimeout: upstreamResponseHeaderTO,
		TLSHandshakeTimeout:   upstreamTLSHandshakeTO,
		ExpectContinueTimeout: upstreamExpectContinueTO,
		ForceAttemptHTTP2:     true,
	}
	return p
}

// inboundPathKey is the request-context slot for the path the client sent,
// captured before NewSingleHostReverseProxy joins it onto the upstream URL.
type inboundPathKey struct{}

func rememberInboundPath(director func(*http.Request)) func(*http.Request) {
	return func(req *http.Request) {
		*req = *req.WithContext(context.WithValue(req.Context(), inboundPathKey{}, req.URL.Path))
		director(req)
	}
}

func inboundPath(r *http.Request) string {
	if v, ok := r.Context().Value(inboundPathKey{}).(string); ok {
		return v
	}
	return r.URL.Path
}

// ServeHTTP is the main request handler.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := b.clientIP(r)

	// Bridge admin/health paths — never proxied
	if strings.HasPrefix(r.URL.Path, "/bridge/") {
		b.handleBridgePath(w, r)
		return
	}

	// One request body, one goroutine and one upstream socket per caller, all
	// bounded here rather than by whatever the client and the upstream agree
	// to between them.
	if b.cfg.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, b.cfg.MaxBodyBytes)
	}
	if b.inflight != nil {
		select {
		case b.inflight <- struct{}{}:
			defer func() { <-b.inflight }()
		default:
			// Shed rather than queue: a queued request still holds a goroutine
			// and a connection, which is the resource the cap exists to protect.
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	// Decoy paths — flag + serve fake page
	if tmpl, ok := IsDecoyPath(r.URL.Path); ok {
		b.decoys.ServeDecoy(w, r, ip, tmpl, coercedSubresource(r))
		return
	}

	// Already flagged — route to honeypot
	if b.flags.IsFlagged(ip) {
		if b.cfg.LogLevel == "debug" {
			log.Printf("bridge: routing flagged %s to honeypot", obfuscatedIP(ip)) // #nosec G706 -- masked network, never a full address
		}
		b.setProxyHeaders(r, ip)
		b.honeypotProxy.ServeHTTP(w, r)
		return
	}

	// Score the request
	score := 0

	// UA detection
	uaScore := ScoreAutomationUA(r.UserAgent())
	if uaScore > 0 {
		score += uaScore
	}

	// Rate tracking
	count := b.rateTracker.Record(ip)
	if count > b.cfg.RateThreshold {
		score += 50
	}

	// Accumulate score
	if score > 0 {
		total := b.scores.Add(ip, score)
		if total >= b.cfg.FlagThreshold && !coercedSubresource(r) {
			// score is only nonzero via the UA or rate branches. Rate
			// wins when both fire. The old auto:score default was
			// unreachable and is gone.
			reason := "auto:automation_ua"
			if count > b.cfg.RateThreshold {
				reason = "auto:rate_exceeded"
			}
			b.flags.Flag(ip, reason, total)
			log.Printf("bridge: auto-flagged %s score=%d reason=%s", obfuscatedIP(ip), total, reason) // #nosec G706 -- masked network, reason is a constant

			if b.webhook != nil {
				b.webhook.Send(map[string]interface{}{
					"event":  "auto_flag",
					"ip":     ip,
					"score":  total,
					"reason": reason,
				})
			}

			b.setProxyHeaders(r, ip)
			b.honeypotProxy.ServeHTTP(w, r)
			return
		}
	}

	// Clean — route to real
	b.setProxyHeaders(r, ip)
	b.realProxy.ServeHTTP(w, r)
}

func (b *Bridge) handleBridgePath(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/bridge/healthz":
		b.health.Healthz(w, r)
	case "/bridge/readyz":
		// An unauthenticated caller gets a status code and nothing else.
		//
		// The body named the honeypot ("honeypot":"up"), which is the one thing
		// the design promises the client cannot learn — and the probe fanned
		// out to BOTH upstreams on every call, unscored and unlimited, so it
		// doubled as a free amplifier. The kubelet reads the code; an operator
		// who wants the per-upstream detail presents the admin token.
		b.health.Readyz(w, r, b.admin.authenticate(r))
	case "/bridge/flag":
		b.admin.ServeFlag(w, r)
	case "/bridge/flags":
		b.admin.ServeFlags(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (b *Bridge) inspectLoginResponse(resp *http.Response) error {
	// Only inspect POST /auth/login returning 401. Compare the inbound
	// path: resp.Request.URL.Path is the outbound URL after Director has
	// joined the upstream prefix, so BRIDGE_REAL_UPSTREAM=.../api would
	// make it /api/auth/login and silently skip every failure.
	if resp.Request.Method != http.MethodPost {
		return nil
	}
	if inboundPath(resp.Request) != "/auth/login" {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}

	ip := b.clientIP(resp.Request)
	count := b.loginFails.Record(ip)

	if count >= b.cfg.LoginFailThreshold {
		failScore := count * 20
		total := b.scores.Add(ip, failScore)
		if total >= b.cfg.FlagThreshold {
			b.flags.Flag(ip, "auto:login_failures", total)
			log.Printf("bridge: auto-flagged %s login_failures=%d score=%d", obfuscatedIP(ip), count, total) // #nosec G706 -- masked network, never a full address

			if b.webhook != nil {
				b.webhook.Send(map[string]interface{}{
					"event":         "auto_flag",
					"ip":            ip,
					"score":         total,
					"reason":        "login_failures",
					"failure_count": count,
				})
			}
		}
	}

	return nil
}

// coercedSubresource reports whether the browser itself is telling us this
// request was made by a page the visitor did not choose to talk to us.
//
// A flag costs the caller 24 hours of being served fabricated key, user and
// audit data, and the flagged identity is the client address — so a NAT egress
// takes a whole office with it. An attacker only had to put
// <img src="https://auth.example.com/wp-admin/x.png"> on any page they control:
// the browser sends it, we flag the visitor. Sixty-one such tags cross the
// default rate threshold with no decoy path at all.
//
// The signature is all three fetch-metadata headers agreeing that this is a
// cross-site subresource the page pulled in: Sec-Fetch-Site: cross-site,
// Sec-Fetch-Mode: no-cors, and a Sec-Fetch-Dest that is a subresource rather
// than a document. Fetch metadata is set by the browser and cannot be
// overridden by the page, so a coerced <img> or <script> lands here while a
// cross-site NAVIGATION — which the visitor sees, and which a scanner following
// links produces — still flags, as does any client that sends no fetch metadata
// at all.
//
// A caller sending these three headers by hand evades flagging. That is the
// trade, and it is the right way round: what it costs is deception coverage,
// not a security control — an unflagged attacker reaches the real vault, which
// still has every rate limit, lockout and authentication check it had before.
// What it buys is that an attacker can no longer aim the honeypot at people who
// have never visited this service.
func coercedSubresource(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "no-cors") {
		return false
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Dest")) {
	case "image", "script", "style", "font", "audio", "video", "track", "manifest", "object", "embed":
		return true
	default:
		return false
	}
}

// obfuscatedIP renders a client address for a log line: IPv4 keeps its /24,
// IPv6 keeps its /64, anything that does not parse becomes the constant
// "invalid_ip".
//
// It mirrors httputil.ObfuscatedIP, which cmd/bridge cannot import because this
// binary is deliberately stdlib-only. It is the only sanitiser this package
// carries: every value a client chooses reaches a bridge log line either through
// this function, which returns a masked network or the constant "invalid_ip" and
// so can never carry attacker text, or through a %q verb, which escapes the
// control characters and the U+2028/U+2029 separators a log shipper splits on.
//
// The bridge keeps whole addresses where an operator has to act on one: the
// flag store, /bridge/flags and the webhook body. The process log is read by
// everyone who can reach a log shipper and only needs to name the network, so
// that is all it gets. See docs/PRIVACY.md section 3.3.
func obfuscatedIP(v string) string {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return "invalid_ip"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// defaultStrippedHeaders are the request headers the vault trusts because of
// who its peer is, and which the bridge therefore has to author or delete.
//
// internal/middleware/appcontext.go believes X-Vault-App from a trusted peer
// and picks the tenant branding for unauthenticated auth emails from it.
// internal/middleware/ratelimit.go believes the TLS-fingerprint header from a
// trusted peer and uses it to bind a bearer token to a device — its own comment
// describes an attacker replaying a stolen token with the victim's fingerprint
// as the attack the trust gate closed, and that gate is satisfied by the
// bridge. internal/middleware/ipaccess.go believes the geo header, and
// ClientIP believes the real-IP header. Every one of them was forwarded
// verbatim from the client.
//
// The invariant: the bridge must be the sole author of anything the upstream
// trusts by peer identity. Operator-renamed headers go in BRIDGE_STRIP_HEADERS.
var defaultStrippedHeaders = []string{
	"X-Vault-App",
	"X-TLS-Fingerprint",
	"X-Real-IP",
	"X-Forwarded-Host",
	"CF-Connecting-IP",
	"CF-IPCountry",
	"True-Client-IP",
	"X-Client-IP",
	"X-Country-Code",
	"X-GeoIP-Country",
}

func (b *Bridge) setProxyHeaders(r *http.Request, ip string) {
	// A Connection header is hop-by-hop: net/http's reverse proxy deletes every
	// header the client lists there before forwarding. It runs that deletion
	// after this function, so a caller sending "Connection: X-Real-IP" would
	// strip the stamp below and hand the vault a request with no attributable
	// client address. Drop our own header names from the client's Connection
	// token list first; unrelated tokens (close, upgrade) are left in place.
	stripConnectionTokens(r.Header, "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-For")

	// Delete before stamping. Everything the upstream trusts because the bridge
	// sent it must come from the bridge; a value the client supplied for one of
	// these names is a value the upstream's own check would have been handed by
	// the attacker it was checking.
	for _, h := range defaultStrippedHeaders {
		r.Header.Del(h)
	}
	if b.cfg.RealIPHeader != "" {
		r.Header.Del(b.cfg.RealIPHeader)
	}
	for _, h := range b.cfg.StripHeaders {
		r.Header.Del(h)
	}

	r.Header.Set("X-Real-IP", ip)
	r.Header.Set("X-Forwarded-Proto", "https")
	// Only extend a client-supplied XFF when the peer is a trusted proxy.
	// Otherwise the leftmost entry is whatever the client wrote, which is
	// the value most parsers treat as the originating address.
	prior := r.Header.Get("X-Forwarded-For")
	if prior != "" && b.isTrustedProxy(extractIP(r.RemoteAddr)) {
		r.Header.Set("X-Forwarded-For", prior+", "+ip)
	} else {
		r.Header.Set("X-Forwarded-For", ip)
	}
}

// stripConnectionTokens removes the named header tokens from the request's
// Connection header. net/http's reverse proxy treats every token listed there
// as a hop-by-hop header and deletes the matching header before forwarding.
// Leaving the bridge's own header names in an attacker-supplied Connection line
// would let an unauthenticated caller strip the stamps this proxy relies on.
// Token matching is case-insensitive and other tokens are preserved.
func stripConnectionTokens(h http.Header, protected ...string) {
	values := h.Values("Connection")
	if len(values) == 0 {
		return
	}

	drop := make(map[string]bool, len(protected))
	for _, p := range protected {
		drop[strings.ToLower(p)] = true
	}

	var kept []string
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			t := strings.TrimSpace(tok)
			if t == "" || drop[strings.ToLower(t)] {
				continue
			}
			kept = append(kept, t)
		}
	}

	h.Del("Connection")
	if len(kept) > 0 {
		h.Set("Connection", strings.Join(kept, ", "))
	}
}

// maxXFFHops caps the right-to-left walk over X-Forwarded-For.
//
// MaxHeaderBytes is 1 MiB, so a header of "203.0.113.1, " repeated is ~70k
// hops, each one a ParseIP and a walk of the trusted-proxy list, plus the 1 MiB
// allocation — per request, before anything else happens. No real deployment
// has more than a handful of hops.
const maxXFFHops = 32

// joinHeader concatenates every field line of a header.
//
// Header.Get returns only the FIRST line. A peer that appends X-Forwarded-For
// as a separate field line rather than comma-joining it (nginx, ALB and
// Cloudflare all comma-join; not every proxy does) left the rightmost walk
// reading the client's own line and dropping the real appended hop, which is
// leftmost trust reopened.
func joinHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		return strings.Join(values, ",")
	}
}

// rightmostUntrusted walks a comma-separated forwarded-for list right to left
// and returns the first address that parses and is not a declared proxy.
//
// The walk is capped at maxXFFHops and every candidate goes through ParseIP,
// because the result becomes a score bucket key, a rate bucket key, a flag
// identity and a log field: an unvalidated value mints a fresh identity per
// request, which is scoring fully evaded.
func (b *Bridge) rightmostUntrusted(value string) string {
	parts := strings.Split(value, ",")
	if len(parts) > maxXFFHops {
		parts = parts[len(parts)-maxXFFHops:]
	}
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if b.isTrustedProxy(candidate) {
			continue
		}
		if net.ParseIP(candidate) != nil {
			return candidate
		}
		break
	}
	return ""
}

func (b *Bridge) clientIP(r *http.Request) string {
	// Check real IP header from trusted proxy
	if b.cfg.RealIPHeader != "" {
		if value := joinHeader(r, b.cfg.RealIPHeader); value != "" {
			// Validate it came from a trusted proxy, then validate the value
			// itself exactly as the X-Forwarded-For branch below does. This
			// branch used to return the raw string: junk minted one fresh
			// identity per request (40 sqlmap-UA requests rotating a junk
			// header produced 0 flags and 40 score buckets), and pointing
			// BRIDGE_REAL_IP_HEADER at X-Forwarded-For returned the client's
			// own leftmost entry and bypassed the walk entirely.
			remoteIP := extractIP(r.RemoteAddr)
			if b.isTrustedProxy(remoteIP) {
				if ip := b.rightmostUntrusted(value); ip != "" {
					return ip
				}
			}
		}
	}

	// X-Forwarded-For from trusted proxies. A load balancer that appends to
	// this header (nginx proxy_add_x_forwarded_for, AWS ALB) leaves the
	// client-supplied entries on the left and adds each real hop on the right,
	// so the closest hop this bridge did not itself vouch for is the rightmost
	// entry that is not a trusted proxy. Walk right to left, skipping trusted
	// proxies, and return the first address that parses. Taking the leftmost
	// entry would return whatever the client wrote, letting an unauthenticated
	// caller both evade its own scoring and frame another address.
	if xff := joinHeader(r, "X-Forwarded-For"); xff != "" {
		remoteIP := extractIP(r.RemoteAddr)
		if b.isTrustedProxy(remoteIP) {
			if ip := b.rightmostUntrusted(xff); ip != "" {
				return ip
			}
		}
	}

	return extractIP(r.RemoteAddr)
}

func (b *Bridge) isTrustedProxy(ip string) bool {
	if len(b.cfg.TrustedProxies) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range b.cfg.TrustedProxies {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// StartReaper starts background goroutines to clean up expired state.
func (b *Bridge) StartReaper(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			b.flags.Reap()
			b.rateTracker.Reap()
			b.loginFails.Reap()
			b.scores.Reap(b.cfg.FlagTTL)
		}
	}()
}

// Close cleans up bridge resources and waits for in-flight webhook deliveries
// so a shutdown does not drop the event that triggered it.
func (b *Bridge) Close() {
	b.flags.Close()
	b.webhook.Close()
}

const (
	// webhookWorkers caps how many deliveries are in flight at once. The
	// request path raises events at whatever rate a caller can generate them,
	// so without a cap the caller decides how many connections this process
	// opens against the operator's alerting endpoint.
	webhookWorkers = 8

	// webhookQueueDepth is the burst a slow receiver may fall behind by before
	// events are dropped. Deep enough that ordinary detection never reaches it,
	// bounded so a flood costs fixed memory.
	webhookQueueDepth = 1024
)

// WebhookSender sends JSON webhook notifications through a fixed pool of
// delivery workers.
type WebhookSender struct {
	url    string
	client *http.Client
	queue  chan map[string]interface{}
	wg     sync.WaitGroup

	// mu guards closed against the queue send. Send holds it for read, Close
	// takes it for write before closing the channel, so no send can be sitting
	// in the select when the close happens.
	mu     sync.RWMutex
	closed bool

	closeOnce sync.Once
	dropOnce  sync.Once
	dropped   atomic.Uint64
}

// NewWebhookSender creates a webhook sender. Returns nil-safe (all methods are no-ops if url is empty).
func NewWebhookSender(webhookURL string) *WebhookSender {
	if webhookURL == "" {
		return nil
	}
	ws := &WebhookSender{
		url: webhookURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		queue: make(chan map[string]interface{}, webhookQueueDepth),
	}

	ws.wg.Add(webhookWorkers)
	for i := 0; i < webhookWorkers; i++ {
		go func() {
			defer ws.wg.Done()
			for payload := range ws.queue {
				ws.deliver(payload)
			}
		}()
	}

	return ws
}

// Send hands a JSON payload to the delivery workers and returns without
// waiting for the receiver. The request that triggered the alert must not
// wait: a scanner watching its own latency would otherwise see the exact
// moment it was flagged.
//
// An event is dropped rather than queued when the workers are saturated,
// because the caller controls the event rate. Blocking here would put the
// receiver's latency back on the request path, and growing without limit
// would let a scanner decide how many connections this process opens against
// the alerting endpoint. Drops are counted and reported once, not per event:
// logging each one puts the log writes on that same request path.
func (ws *WebhookSender) Send(payload map[string]interface{}) {
	if ws == nil {
		return
	}

	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if ws.closed {
		return
	}

	select {
	case ws.queue <- payload:
	default:
		ws.dropped.Add(1)
		ws.dropOnce.Do(func() {
			log.Printf("bridge: webhook receiver is not keeping up; events are being dropped")
		})
	}
}

// Close stops accepting events, waits for the queued ones to be delivered and
// reports anything that was dropped. It is safe on a nil sender and safe to
// call more than once.
func (ws *WebhookSender) Close() {
	if ws == nil {
		return
	}

	ws.closeOnce.Do(func() {
		ws.mu.Lock()
		ws.closed = true
		ws.mu.Unlock()
		close(ws.queue)
	})

	ws.wg.Wait()

	if n := ws.dropped.Load(); n > 0 {
		log.Printf("bridge: %d webhook events were dropped", n)
	}
}

func (ws *WebhookSender) deliver(payload map[string]interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("bridge: webhook marshal error: %v", err)
		return
	}

	resp, err := ws.client.Post(ws.url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("bridge: webhook dispatch failed: %v", err)
		return
	}
	resp.Body.Close() // #nosec G104 -- best-effort webhook cleanup
	if resp.StatusCode >= 400 {
		log.Printf("bridge: webhook returned %d", resp.StatusCode)
	}
}
