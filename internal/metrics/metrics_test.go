package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCollectorHandler(t *testing.T) {
	active := int64(2)
	rejected := int64(5)

	c := NewCollector(
		func() int64 { return active },
		func() int64 { return rejected },
		func() int { return 4 },
	)

	// Simulate some counters
	c.RecordLoginAttempt()
	c.RecordLoginAttempt()
	c.RecordLoginAttempt()
	c.RecordLoginSuccess()
	c.RecordLoginFailed()
	c.RecordLoginFailed()
	c.RecordTokenIssued()
	c.RecordTokenRefreshed()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	c.Handler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}

	body := rec.Body.String()

	// Verify all metrics are present with correct values
	checks := map[string]string{
		"vault_argon2_active":          "vault_argon2_active 2",
		"vault_argon2_max":             "vault_argon2_max 4",
		"vault_argon2_rejected_total":  "vault_argon2_rejected_total 5",
		"vault_login_attempts_total":   "vault_login_attempts_total 3",
		"vault_login_success_total":    "vault_login_success_total 1",
		"vault_login_failed_total":     "vault_login_failed_total 2",
		"vault_tokens_issued_total":    "vault_tokens_issued_total 1",
		"vault_tokens_refreshed_total": "vault_tokens_refreshed_total 1",
	}

	for name, expected := range checks {
		if !strings.Contains(body, expected) {
			t.Errorf("missing or wrong value for %s: expected %q in output", name, expected)
		}
	}

	// Verify TYPE annotations exist
	typeChecks := []string{
		"# TYPE vault_argon2_active gauge",
		"# TYPE vault_argon2_max gauge",
		"# TYPE vault_argon2_rejected_total counter",
		"# TYPE vault_login_attempts_total counter",
		"# TYPE vault_login_success_total counter",
		"# TYPE vault_login_failed_total counter",
		"# TYPE vault_tokens_issued_total counter",
		"# TYPE vault_tokens_refreshed_total counter",
	}
	for _, tc := range typeChecks {
		if !strings.Contains(body, tc) {
			t.Errorf("missing TYPE annotation: %q", tc)
		}
	}
}

func TestCollectorCounterIncrements(t *testing.T) {
	c := NewCollector(
		func() int64 { return 0 },
		func() int64 { return 0 },
		func() int { return 4 },
	)

	// Verify counters start at 0
	if v := c.loginAttempts.Load(); v != 0 {
		t.Errorf("loginAttempts should start at 0, got %d", v)
	}

	c.RecordLoginAttempt()
	c.RecordLoginAttempt()
	if v := c.loginAttempts.Load(); v != 2 {
		t.Errorf("loginAttempts should be 2, got %d", v)
	}

	c.RecordTokenIssued()
	if v := c.tokensIssued.Load(); v != 1 {
		t.Errorf("tokensIssued should be 1, got %d", v)
	}
}
