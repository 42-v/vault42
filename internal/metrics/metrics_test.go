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

// The mint and document-store counters are the only signal an operator has that
// a signing oracle or a service-scoped store is in use, and each has to move on
// its own: a Record call that bumped a neighbour would make an alert fire on the
// wrong subsystem. Counting is half the job, so the exposition output is checked
// too, with values rather than names alone. A counter that increments but never
// reaches /metrics is invisible to every scrape.
func TestCollectorMintAndServiceDocumentCounters(t *testing.T) {
	c := NewCollector(
		func() int64 { return 0 },
		func() int64 { return 0 },
		func() int { return 4 },
	)

	// Distinct counts per counter, so a Record wired to the wrong field cannot
	// pass by coincidence.
	c.RecordMintIssued()
	c.RecordMintIssued()
	c.RecordMintRejected()
	c.RecordSvcDocWrite()
	c.RecordSvcDocWrite()
	c.RecordSvcDocWrite()
	c.RecordSvcDocRead()
	c.RecordSvcDocRead()
	c.RecordSvcDocRead()
	c.RecordSvcDocRead()
	c.RecordSvcDocRejected()
	c.RecordSvcDocRejected()
	c.RecordSvcDocRejected()
	c.RecordSvcDocRejected()
	c.RecordSvcDocRejected()

	counters := []struct {
		name string
		got  int64
		want int64
	}{
		{"mintIssued", c.mintIssued.Load(), 2},
		{"mintRejected", c.mintRejected.Load(), 1},
		{"svcDocWrites", c.svcDocWrites.Load(), 3},
		{"svcDocReads", c.svcDocReads.Load(), 4},
		{"svcDocRejects", c.svcDocRejects.Load(), 5},
	}
	for _, tc := range counters {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	exposition := []string{
		"# TYPE vault_mint_issued_total counter",
		"vault_mint_issued_total 2",
		"# TYPE vault_mint_rejected_total counter",
		"vault_mint_rejected_total 1",
		"# TYPE vault_svcdoc_writes_total counter",
		"vault_svcdoc_writes_total 3",
		"# TYPE vault_svcdoc_reads_total counter",
		"vault_svcdoc_reads_total 4",
		"# TYPE vault_svcdoc_rejected_total counter",
		"vault_svcdoc_rejected_total 5",
	}
	for _, want := range exposition {
		if !strings.Contains(body, want) {
			t.Errorf("missing from /metrics output: %q", want)
		}
	}

	// A minted token asserts a subject vault42 never authenticated. Folding it
	// into the ordinary issuance counter would hide exactly the number an
	// operator wants to alert on, so the two must stay separate.
	if !strings.Contains(body, "vault_tokens_issued_total 0") {
		t.Error("minting moved vault_tokens_issued_total: mint counts must not be folded into ordinary token issuance")
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

// additional table driven edge coverage for New and Handler
func TestNewCollector_AndHandler_Edge(t *testing.T) {
	tests := []struct {
		name string
		act  func() int64
		rej  func() int64
		maxc func() int
	}{
		{"zeros", func() int64 { return 0 }, func() int64 { return 0 }, func() int { return 0 }},
		{"nilsafe", func() int64 { return 0 }, func() int64 { return 0 }, func() int { return 10 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector(tt.act, tt.rej, tt.maxc)
			rec := httptest.NewRecorder()
			c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("code=%d", rec.Code)
			}
		})
	}
}

func TestCollector_NilAccessors_Recovered(t *testing.T) {
	c := NewCollector(nil, nil, nil)
	defer func() { _ = recover() }()
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest("GET", "/", nil))
}

// TestCollector_Table exercises all recorders and handler edges in table form.
func TestCollector_Table(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Collector)
	}{
		{"record all", func(c *Collector) {
			c.RecordLoginAttempt()
			c.RecordLoginSuccess()
			c.RecordLoginFailed()
			c.RecordTokenIssued()
			c.RecordTokenRefreshed()
		}},
		{"multiple", func(c *Collector) {
			for i := 0; i < 3; i++ {
				c.RecordLoginAttempt()
				c.RecordLoginFailed()
			}
		}},
		{"handler after records", func(c *Collector) {
			c.RecordLoginSuccess()
			rec := httptest.NewRecorder()
			c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/m", nil))
			if rec.Code != http.StatusOK {
				t.Error("bad code")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector(func() int64 { return 0 }, func() int64 { return 0 }, func() int { return 1 })
			tt.run(c)
		})
	}
}
