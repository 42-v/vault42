package honeypot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
)

// ---------------------------------------------------------------------------
// ConfigureFakeJWT tests
// ---------------------------------------------------------------------------

func TestConfigureFakeJWT_NoOp(t *testing.T) {
	// ConfigureFakeJWT uses sync.Once, so the first call in the test binary
	// configures and all subsequent calls are no-ops. The default values are
	// "vault"/"vault". We verify that calling it multiple times does not panic
	// and that the output still produces valid JWTs with the original iss/aud.
	ConfigureFakeJWT("should-be-ignored", "should-be-ignored", 15*time.Minute)
	ConfigureFakeJWT("also-ignored", "also-ignored", 15*time.Minute)

	token, err := GenerateFakeJWTForIdentity(TrapCaller{})
	if err != nil {
		t.Fatalf("trap mint after ConfigureFakeJWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Decode payload to check iss/aud.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	// Since sync.Once already fired (possibly with defaults "vault"/"vault"),
	// we just verify the claims are non-empty strings.
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		t.Error("iss claim should be a non-empty string")
	}
	// aud is an array on every token the vault signs, because jwt.ClaimStrings
	// marshals as one. A trap token that spelled it as a bare string could be
	// told apart from a real one by decoding a single segment.
	aud, ok := claims["aud"].([]interface{})
	if !ok || len(aud) == 0 {
		t.Errorf("aud claim should be a non-empty array like a real token's, got %#v", claims["aud"])
	}
}

// ---------------------------------------------------------------------------
// Err tests
// ---------------------------------------------------------------------------

func TestErr_Format(t *testing.T) {
	err := Err("something failed")
	if err == nil {
		t.Fatal("Err should return non-nil error")
	}
	want := "honeypot: something failed"
	if err.Error() != want {
		t.Errorf("Err message = %q, want %q", err.Error(), want)
	}
}

func TestErr_EmptyMessage(t *testing.T) {
	err := Err("")
	want := "honeypot: "
	if err.Error() != want {
		t.Errorf("Err empty message = %q, want %q", err.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// Alert with webhook error status
// ---------------------------------------------------------------------------

// An error status back from the webhook is the operator's endpoint being broken,
// not the attack going away. The dispatch still happened, so it still owes an
// audit row carrying the status the endpoint answered with -- that row is what an
// operator reads to tell "nobody attacked us" from "the alert channel is down".
// The status must not propagate: Alert is called from the request path.
func TestAlert_WebhookErrorStatusIsAuditedNotPropagated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		event  Event
	}{
		{"client error", http.StatusBadRequest, Event{EventType: "trap_login", IP: "10.0.0.1", UserAgent: "test-agent", RiskScore: 80}},
		{"server error", http.StatusInternalServerError, Event{EventType: "scan_detected", IP: "10.0.0.2", RiskScore: 50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posted int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				posted++
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			var entries []*model.AuditEntry
			a := NewAlerter(srv.URL, nil, apAuditSpy(&entries))
			a.Alert(context.Background(), tc.event)

			if posted != 1 {
				t.Fatalf("webhook posts = %d, want 1", posted)
			}
			if len(entries) != 2 {
				t.Fatalf("audit entries = %d, want the trigger and the dispatch", len(entries))
			}
			if entries[1].EventType != audit.HoneypotAlert {
				t.Errorf("dispatch audit event = %q, want %q", entries[1].EventType, audit.HoneypotAlert)
			}
			if got := entries[1].Metadata["webhook_status"]; got != tc.status {
				t.Errorf("audited webhook_status = %v, want %d", got, tc.status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Alert with failed webhook connection
// ---------------------------------------------------------------------------

// A webhook that cannot be reached at all must leave the trigger row and nothing
// else. The dispatch row is written only after client.Do returns a response, so
// its absence is what says the alert never left the host -- recording one anyway
// would tell the operator an alert was delivered when the socket never opened.
func TestAlert_WebhookConnectionFailed(t *testing.T) {
	// Use a URL that will fail to connect (closed server).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := srv.URL
	srv.Close() // Close immediately so the connection fails.

	var entries []*model.AuditEntry
	a := NewAlerter(url, nil, apAuditSpy(&entries))

	// Should not panic; connection errors are logged but not propagated.
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "10.0.0.3",
		RiskScore: 90,
	})

	assertTriggerOnly(t, entries)
}

func TestAlert_WebhookUnresolvableHost(t *testing.T) {
	var entries []*model.AuditEntry
	a := NewAlerter("http://this-host-does-not-exist.invalid:9999/webhook", nil, apAuditSpy(&entries))

	// Should not panic; DNS resolution failure is logged.
	a.Alert(context.Background(), Event{
		EventType: "probe",
		IP:        "10.0.0.4",
		RiskScore: 20,
	})

	assertTriggerOnly(t, entries)
}

// assertTriggerOnly reports that Alert recorded the trap firing and did not
// record a webhook dispatch.
func assertTriggerOnly(t *testing.T, entries []*model.AuditEntry) {
	t.Helper()

	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want only the trigger: a dispatch that never reached the endpoint must not be audited as one", len(entries))
	}
	if entries[0].EventType != audit.HoneypotTrigger {
		t.Errorf("audit event type = %q, want %q", entries[0].EventType, audit.HoneypotTrigger)
	}
}

// ---------------------------------------------------------------------------
// NewAlerter with invalid URL scheme
// ---------------------------------------------------------------------------

// The webhook URL arrives from an operator-set env var, so this gate is the only
// thing between a typo and the process issuing requests to whatever the typo
// names. Anything that is not http:// or https:// is dropped to empty, which
// makes Alert audit-only rather than an SSRF primitive an attacker could aim by
// getting a scheme past the check.
func TestNewAlerter_OnlyHTTPSchemesSurviveTheWebhookGate(t *testing.T) {
	for _, tc := range []struct {
		name, url, want string
	}{
		{"ftp is not a transport this process speaks", "ftp://example.com/webhook", ""},
		{"file:// would read the local disk", "file:///etc/passwd", ""},
		{"javascript: is not fetchable at all", "javascript:alert(1)", ""},
		{"https is kept verbatim", "https://hooks.example.com/alert", "https://hooks.example.com/alert"},
		{"http is kept verbatim", "http://localhost:8080/webhook", "http://localhost:8080/webhook"},
		{"unset means audit-only", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAlerter(tc.url, []string{"trap@test.com"}, nil)

			if a.webhookURL != tc.want {
				t.Errorf("NewAlerter(%q).webhookURL = %q, want %q", tc.url, a.webhookURL, tc.want)
			}
			// A rejected URL costs the webhook and nothing else: the trap list is
			// what decides who gets served the fake session.
			if !a.IsTrapUser("trap@test.com") {
				t.Errorf("NewAlerter(%q) lost the trap list along with the URL", tc.url)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CollectHeaders with Cookie header
// ---------------------------------------------------------------------------

func TestCollectHeaders_CookieRedacted(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/me", nil)
	r.Header.Set("Cookie", "session=abc123; refresh=secret_token")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", "req-42")

	headers := CollectHeaders(r)

	if headers["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie header = %q, want [REDACTED]", headers["Cookie"])
	}
	if headers["Accept"] != "application/json" {
		t.Errorf("Accept header = %q, want application/json", headers["Accept"])
	}
	if headers["X-Request-Id"] != "req-42" {
		t.Errorf("X-Request-Id header = %q, want req-42", headers["X-Request-Id"])
	}
}

func TestCollectHeaders_BothAuthAndCookieRedacted(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/login", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.xxx.yyy")
	r.Header.Set("Cookie", "refresh=token123")
	r.Header.Set("Content-Type", "application/json")

	headers := CollectHeaders(r)

	if headers["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q, want [REDACTED]", headers["Authorization"])
	}
	if headers["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie = %q, want [REDACTED]", headers["Cookie"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", headers["Content-Type"])
	}
}

func TestCollectHeaders_NoSensitiveHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/health", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	headers := CollectHeaders(r)

	for k, v := range headers {
		if v == "[REDACTED]" {
			t.Errorf("header %q should not be redacted", k)
		}
	}
}

func TestCollectHeaders_MultiValueHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Accept-Encoding", "gzip")
	r.Header.Add("Accept-Encoding", "deflate")

	headers := CollectHeaders(r)

	val := headers["Accept-Encoding"]
	if !strings.Contains(val, "gzip") || !strings.Contains(val, "deflate") {
		t.Errorf("Accept-Encoding = %q, want both gzip and deflate", val)
	}
}

// ---------------------------------------------------------------------------
// Alert with invalid-scheme alerter (webhook URL was sanitized away)
// ---------------------------------------------------------------------------

// The scheme gate is only worth anything if Alert then behaves as though no
// webhook were configured. The dispatch row is written after a response comes
// back, so exactly one audit entry -- the trigger -- is the evidence that nothing
// was sent to the ftp:// host the operator (or an attacker who reached the
// config) wrote down.
func TestAlert_SanitizedScheme_NoWebhookSent(t *testing.T) {
	var entries []*model.AuditEntry
	a := NewAlerter("ftp://evil.com/exfil", nil, apAuditSpy(&entries))

	// Should not panic and should not attempt to send to ftp://.
	a.Alert(context.Background(), Event{
		EventType: "probe",
		IP:        "10.0.0.5",
		RiskScore: 10,
	})

	assertTriggerOnly(t, entries)
}
