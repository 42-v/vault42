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
func (sm *ScoreMap) Add(ip string, delta int) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	ent := sm.scores[ip]
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
		realProxy:     httputil.NewSingleHostReverseProxy(realURL),
		honeypotProxy: httputil.NewSingleHostReverseProxy(honeypotURL),
		flags:         NewFlagStore(cfg.FlagTTL, cfg.RedisAddr),
		rateTracker:   NewRateTracker(cfg.RateWindow),
		loginFails:    NewLoginFailTracker(cfg.LoginFailWindow),
		scores:        NewScoreMap(),
		webhook:       webhook,
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

	// Decoy paths — flag + serve fake page
	if tmpl, ok := IsDecoyPath(r.URL.Path); ok {
		b.decoys.ServeDecoy(w, r, ip, tmpl)
		return
	}

	// Already flagged — route to honeypot
	if b.flags.IsFlagged(ip) {
		if b.cfg.LogLevel == "debug" {
			log.Printf("bridge: routing flagged %s to honeypot", ip) // #nosec G706 -- IP is from RemoteAddr/trusted header
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
		if total >= b.cfg.FlagThreshold {
			// score is only nonzero via the UA or rate branches. Rate
			// wins when both fire. The old auto:score default was
			// unreachable and is gone.
			reason := "auto:automation_ua"
			if count > b.cfg.RateThreshold {
				reason = "auto:rate_exceeded"
			}
			b.flags.Flag(ip, reason, total)
			log.Printf("bridge: auto-flagged %s score=%d reason=%s", ip, total, reason) // #nosec G706 -- IP and reason are controlled values

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
		b.health.Readyz(w, r)
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
			log.Printf("bridge: auto-flagged %s login_failures=%d score=%d", ip, count, total)

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

func (b *Bridge) setProxyHeaders(r *http.Request, ip string) {
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

func (b *Bridge) clientIP(r *http.Request) string {
	// Check real IP header from trusted proxy
	if b.cfg.RealIPHeader != "" {
		if ip := r.Header.Get(b.cfg.RealIPHeader); ip != "" {
			// Validate it came from a trusted proxy
			remoteIP := extractIP(r.RemoteAddr)
			if b.isTrustedProxy(remoteIP) {
				return strings.TrimSpace(ip)
			}
		}
	}

	// X-Forwarded-For from trusted proxies
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteIP := extractIP(r.RemoteAddr)
		if b.isTrustedProxy(remoteIP) {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
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
