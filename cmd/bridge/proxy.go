package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
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
	scores map[string]int
}

// NewScoreMap creates a new score tracker.
func NewScoreMap() *ScoreMap {
	return &ScoreMap{scores: make(map[string]int)}
}

// Add adds a score delta and returns the new total.
func (sm *ScoreMap) Add(ip string, delta int) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.scores[ip] += delta
	return sm.scores[ip]
}

// Get returns the current score for an IP.
func (sm *ScoreMap) Get(ip string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.scores[ip]
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

	// ModifyResponse on realProxy: inspect login failures
	b.realProxy.ModifyResponse = b.inspectLoginResponse

	return b, nil
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
			reason := "auto:score"
			if uaScore > 0 {
				reason = "auto:automation_ua"
			}
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
	// Only inspect POST /auth/login returning 401
	if resp.Request.Method != http.MethodPost {
		return nil
	}
	if resp.Request.URL.Path != "/auth/login" {
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
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
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
		}
	}()
}

// Close cleans up bridge resources.
func (b *Bridge) Close() {
	b.flags.Close()
}

// WebhookSender sends JSON webhook notifications.
type WebhookSender struct {
	url    string
	client *http.Client
}

// NewWebhookSender creates a webhook sender. Returns nil-safe (all methods are no-ops if url is empty).
func NewWebhookSender(webhookURL string) *WebhookSender {
	if webhookURL == "" {
		return nil
	}
	return &WebhookSender{
		url: webhookURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Send dispatches a JSON payload to the webhook URL. Best-effort — errors are logged.
func (ws *WebhookSender) Send(payload map[string]interface{}) {
	if ws == nil {
		return
	}
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
