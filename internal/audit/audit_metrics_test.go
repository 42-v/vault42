package audit

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/metrics"
)

// scrapeCounter reads one counter out of a real /metrics response.
//
// The value is taken from the exposition rather than from the atomic behind it
// because the exposition is the only thing a Prometheus server ever sees. A
// counter that increments correctly and is never rendered is invisible to every
// scrape, every alert rule and every dashboard, which is the same as not
// existing.
func scrapeCounter(t *testing.T, name string) int64 {
	t.Helper()

	c := metrics.NewCollector(
		func() int64 { return 0 },
		func() int64 { return 0 },
		func() int { return 1 },
	)
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics returned %d", rec.Code)
	}

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

	t.Fatalf("%s is absent from /metrics, so an operator has no way to alert on it", name)
	return 0
}

// discardAuditWarnings silences the per-drop warning the overflow path writes.
// At the volumes these tests drive it buries any real failure output.
func discardAuditWarnings(t *testing.T) {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
}

// TestAuditEntriesDroppedByAFailedFlushAreVisibleOnTheMetricsEndpoint covers the
// worst of the two loss conditions.
//
// These entries were already accepted. Every caller that logged one was told the
// audit write succeeded, and then the store rejected the batch and the retry had
// nowhere to put it, so each is a confirmed hole in an append-only trail that has
// no second copy. Before this counter reached the exposition the only record of
// that was an int64 inside a running process: nothing scraped it, so a service
// could lose audit records continuously and every dashboard would stay green. A
// silent audit gap is the exact condition an attacker wants, and an operator
// cannot page on a number nobody can read.
//
// The buffer-full counter is checked at the same time because this drop did not
// happen at enqueue. If one Record call moved both series, an operator responding
// to the alert would go resize a buffer while the database that is eating audit
// records stays broken.
func TestAuditEntriesDroppedByAFailedFlushAreVisibleOnTheMetricsEndpoint(t *testing.T) {
	discardAuditWarnings(t)

	const capacity = 4

	beforeDropped := scrapeCounter(t, "vault_audit_events_dropped_total")
	beforeFull := scrapeCounter(t, "vault_audit_buffer_full_total")

	repo := &gatedAuditRepo{
		fail:    true,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	l := NewLoggerWithBufferSize(repo, time.Hour, capacity)

	logSeries(t, l, "older", capacity)

	flushed := make(chan error, 1)
	go func() { flushed <- l.Flush(context.Background()) }()

	// The batch is in flight and the buffer is empty, so the events logged next
	// refill it completely and the rejected batch has nowhere to go.
	<-repo.entered
	logSeries(t, l, "newer", capacity)
	close(repo.release)

	if err := <-flushed; err == nil {
		t.Fatal("Flush reported success while the store was rejecting every batch")
	}
	if got := l.DroppedTotal(); got != capacity {
		t.Fatalf("DroppedTotal = %d, want %d: the test did not drive the loss it is measuring", got, capacity)
	}

	if got := scrapeCounter(t, "vault_audit_events_dropped_total") - beforeDropped; got != capacity {
		t.Errorf("vault_audit_events_dropped_total moved by %d, want %d: %d audit records were "+
			"discarded for good and the scrape an operator alerts on did not account for them",
			got, capacity, capacity)
	}
	if got := scrapeCounter(t, "vault_audit_buffer_full_total") - beforeFull; got != 0 {
		t.Errorf("vault_audit_buffer_full_total moved by %d on a flush-time loss, want 0: the two "+
			"conditions need different remediation, and folding them together sends the operator "+
			"to tune a buffer while the store keeps rejecting batches", got)
	}
}

// TestAuditEventsMeetingAFullBufferAreVisibleOnTheMetricsEndpoint covers the
// saturation condition, which is the one an attacker can drive on purpose.
//
// Flooding a service with events it must log fills the in-memory buffer, and
// every non-critical event that arrives after that is discarded outright. That is
// a usable technique for hiding activity in the noise, and it needs its own
// series: it means the process is producing audit events faster than the flush
// interval drains them, which is fixed by resizing the buffer or shedding load,
// not by anything done to the database.
//
// The flush-time counter is asserted flat for the same reason as above, from the
// other side.
func TestAuditEventsMeetingAFullBufferAreVisibleOnTheMetricsEndpoint(t *testing.T) {
	discardAuditWarnings(t)

	const (
		capacity = 1
		// Two more events than the buffer can hold, so the expected delta is not
		// the capacity, not the number logged, and not one. A counter wired to
		// the wrong event cannot match it by coincidence.
		logged  = 3
		refused = logged - capacity
	)

	beforeFull := scrapeCounter(t, "vault_audit_buffer_full_total")
	beforeDropped := scrapeCounter(t, "vault_audit_events_dropped_total")

	repo := &gatedAuditRepo{}
	l := NewLoggerWithBufferSize(repo, time.Hour, capacity)

	// LoginSuccess is deliberately not a critical event type. A critical one is
	// written synchronously instead of being lost, so it would prove nothing
	// about a counter that is meant to track events the buffer turned away.
	logSeries(t, l, "flood", logged)

	if got := scrapeCounter(t, "vault_audit_buffer_full_total") - beforeFull; got != refused {
		t.Errorf("vault_audit_buffer_full_total moved by %d, want %d: %d events met a full buffer "+
			"and were discarded, and a flat counter tells an operator flooding the audit path is "+
			"free of consequences", got, refused, refused)
	}
	if got := scrapeCounter(t, "vault_audit_events_dropped_total") - beforeDropped; got != 0 {
		t.Errorf("vault_audit_events_dropped_total moved by %d on buffer saturation, want 0: it "+
			"reports entries the store lost, and inflating it with enqueue-time refusals makes "+
			"every alert on database-side audit loss fire on load instead", got)
	}
}
