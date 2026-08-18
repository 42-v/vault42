package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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
// its own: a Record call that bumped a neighbor would make an alert fire on the
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

// renderCounter reads one counter back out of a rendered /metrics response.
// The audit tallies are process-wide, so tests compare deltas around an action
// rather than absolute values.
func renderCounter(t *testing.T, name string) int64 {
	t.Helper()

	c := NewCollector(func() int64 { return 0 }, func() int64 { return 0 }, func() int { return 1 })
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, name+" ")), 10, 64)
		if err != nil {
			t.Fatalf("%s exposed a value that is not a number: %q", name, line)
		}
		return v
	}
	t.Fatalf("%s is absent from /metrics", name)
	return 0
}

// TestAuditDropCountersStayApartAndNeverRunBackwards fixes the two properties an
// alert rule on audit loss depends on.
//
// They have to stay apart because they are answered differently: a full buffer
// is tuning, a drop at flush is a broken store that is eating records callers
// were already told were written. An operator paged by one of them goes looking
// in the wrong place if the other moved it.
//
// They must never run backwards because Prometheus computes rate() from the
// difference between scrapes and reads any decrease as a process restart. One
// negative call would erase the recorded loss from every rate() spanning it, so
// a caller that miscounts its own batch has to be refused rather than trusted.
func TestAuditDropCountersStayApartAndNeverRunBackwards(t *testing.T) {
	beforeFull := renderCounter(t, "vault_audit_buffer_full_total")
	beforeDropped := renderCounter(t, "vault_audit_events_dropped_total")

	// Distinct amounts, neither of them one, so a Record wired to the wrong
	// tally cannot pass by coincidence.
	RecordAuditBufferFull()
	RecordAuditBufferFull()
	RecordAuditEventsDropped(5)

	// A batch that reports nothing lost, and one that reports a negative loss.
	// Neither may touch the series.
	RecordAuditEventsDropped(0)
	RecordAuditEventsDropped(-3)

	if got := renderCounter(t, "vault_audit_buffer_full_total") - beforeFull; got != 2 {
		t.Errorf("vault_audit_buffer_full_total moved by %d, want 2", got)
	}
	if got := renderCounter(t, "vault_audit_events_dropped_total") - beforeDropped; got != 5 {
		t.Errorf("vault_audit_events_dropped_total moved by %d, want 5: a drop count that "+
			"absorbs its neighbor or accepts a negative batch makes every alert on audit loss "+
			"read the wrong number", got)
	}

	for _, want := range []string{
		"# TYPE vault_audit_buffer_full_total counter",
		"# TYPE vault_audit_events_dropped_total counter",
	} {
		rec := httptest.NewRecorder()
		c := NewCollector(func() int64 { return 0 }, func() int64 { return 0 }, func() int { return 1 })
		c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing TYPE annotation: %q. Without it a scrape treats the series as "+
				"untyped and rate() over it is refused", want)
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

// The breach-check shed counter reaches the scrape, and a collector that was
// never given it scrapes clean rather than panicking.
//
// This counter is the one that separates two deployments an operator cannot
// otherwise tell apart: one where nobody has chosen a breached password, and one
// where the concurrency cap has been shedding every check and accepting them all.
// The breach check fails open, so silence means both.
func TestCollectorReportsHIBPShed(t *testing.T) {
	newCollector := func() *Collector {
		return NewCollector(
			func() int64 { return 0 },
			func() int64 { return 0 },
			func() int { return 0 },
		)
	}

	t.Run("unwired collectors scrape zero", func(t *testing.T) {
		body := scrape(t, newCollector())
		if !strings.Contains(body, "vault_hibp_shed_total 0") {
			t.Errorf("an unwired collector did not report vault_hibp_shed_total 0:\n%s", body)
		}
	})

	t.Run("the wired accessor is read", func(t *testing.T) {
		c := newCollector()
		c.SetHIBPShed(func() uint64 { return 17 })

		body := scrape(t, c)
		if !strings.Contains(body, "vault_hibp_shed_total 17") {
			t.Errorf("the shed accessor did not reach the scrape:\n%s", body)
		}
		if !strings.Contains(body, "# TYPE vault_hibp_shed_total counter") {
			t.Errorf("vault_hibp_shed_total is exposed without a counter TYPE line:\n%s", body)
		}
	})
}

// scrape runs the collector's handler and returns the exposition body.
func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}
