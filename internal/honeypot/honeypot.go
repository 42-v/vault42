// Package honeypot provides threat observation capabilities for the Vault's
// honeypot deployment profile. It detects trap credential usage, suspicious
// request patterns, and dispatches alerts via webhook.
package honeypot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
)

// HoneypotEvent contains details about a suspicious activity detected in honeypot mode.
type HoneypotEvent struct {
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
	}
}

// IsTrapUser checks if the given identifier (email or username) matches a configured trap account.
func (a *Alerter) IsTrapUser(identifier string) bool {
	return a.trapUsers[strings.ToLower(strings.TrimSpace(identifier))]
}

// Alert sends a JSON POST to the webhook URL with attack details and logs an audit event.
// Webhook dispatch is best-effort — errors are logged but do not propagate.
func (a *Alerter) Alert(ctx context.Context, event HoneypotEvent) {
	// Audit log the trigger
	if a.auditLog != nil {
		a.auditLog.Log(ctx, audit.HoneypotTrigger, "", "", event.IP, event.UserAgent, "", "", // #nosec G104 -- audit is best-effort
			map[string]interface{}{
				"event_type": event.EventType,
				"email":      event.Email,
				"risk_score": event.RiskScore,
			}, event.RiskScore)
	}

	// Send webhook
	if a.webhookURL == "" {
		return
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
		a.auditLog.Log(ctx, audit.HoneypotAlert, "", "", event.IP, event.UserAgent, "", "", // #nosec G104 -- audit is best-effort
			map[string]interface{}{
				"webhook_status": resp.StatusCode,
				"event_type":     event.EventType,
			}, 0)
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

// LoggingMiddleware wraps an HTTP handler to log every request and response
// in honeypot mode. This captures the full request details for threat analysis.
func LoggingMiddleware(alerter *Alerter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 200}

			next.ServeHTTP(rw, r)

			riskScore := 0
			if IsAutomationUA(r.UserAgent()) {
				riskScore = 30
			}

			log.Printf("honeypot: %s %s %s %d %s ua=%q risk=%d", // #nosec G706 -- sanitized via SafeLogValue
				httputil.SafeLogValue(r.Method), httputil.SafeLogValue(r.URL.Path), httputil.SafeLogValue(r.RemoteAddr),
				rw.status, time.Since(start).Round(time.Millisecond),
				httputil.SafeLogValue(r.UserAgent()), riskScore)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// FakeLoginResponse returns a realistic-looking but fake login response.
// The access_token looks like a JWT but has a gibberish signature.
// The refresh_token is a random hex string.
func FakeLoginResponse() (map[string]interface{}, error) {
	jwt, err := GenerateFakeJWT()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"access_token": jwt,
		"token_type":   "Bearer",
		"expires_in":   900,
	}, nil
}

// FakeLoginCookie returns a fake refresh token value for the cookie.
func FakeLoginCookie() (string, error) {
	return GenerateFakeRefresh()
}

// Err returns a formatted error for honeypot operations.
func Err(msg string) error {
	return fmt.Errorf("honeypot: %s", msg)
}
