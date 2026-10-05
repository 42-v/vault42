package honeypot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// apAuditSpyLocked is the concurrent counterpart of apAuditSpy: Alert is called
// from one goroutine per trap login, so the spy that records what it wrote has to
// be safe for that or the test races before the code under test can.
func apAuditSpyLocked(mu *sync.Mutex, entries *[]*model.AuditEntry) *audit.Logger {
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			mu.Lock()
			defer mu.Unlock()
			*entries = append(*entries, e)
			return nil
		},
	}
	return audit.NewLogger(repo, 0)
}

// trapFloodSize is the number of trap logins one attacker drives in this test.
// A real flood is limited only by how fast the login endpoint answers.
const trapFloodSize = 200

// floodAlerter fires trapFloodSize alerts the way production does, one goroutine
// each, and returns once every dispatch has finished.
func floodAlerter(a *Alerter) {
	var wg sync.WaitGroup
	for i := 0; i < trapFloodSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Alert(context.Background(), Event{
				EventType: "trap_login",
				IP:        "203.0.113.9",
				UserAgent: "curl/8.5.0",
				Email:     "trap@example.test",
				RiskScore: 100,
			})
		}()
	}
	wg.Wait()
}

// The attacker chooses how often the trap fires: every login with a trap address
// is one, and each one used to become an outbound POST to whatever the operator
// pointed the webhook at. That turns the honeypot into a request amplifier aimed
// at the operator's own alert channel, and buries the first alert (the one that
// matters) under thousands of identical ones. The number of outbound requests an
// attacker can drive must stay far below the number of requests they send.
func TestAFloodOfTrapLoginsCannotFloodTheOperatorsAlertChannel(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	floodAlerter(NewAlerter(srv.URL, nil, nil))

	got := posts.Load()
	if got < 1 {
		t.Error("the trap fired and the operator was told nothing at all")
	}
	// 25 is the burst allowance plus room for a refill during the run. The point
	// of the bound is the gap between this and trapFloodSize.
	if got > 25 {
		t.Errorf("%d trap logins produced %d webhook posts; the attacker still controls the volume", trapFloodSize, got)
	}
}

// Rate limiting the outbound channel must not cost the record. The audit entry
// is the honeypot's only durable evidence of what was tried, it is what an
// operator reads afterwards, and an attacker who can suppress it by sending more
// traffic can erase their own reconnaissance.
func TestEveryTrapTriggerIsStillAuditedWhileWebhookAlertsAreSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var mu sync.Mutex
	var entries []*model.AuditEntry
	logger := apAuditSpyLocked(&mu, &entries)

	floodAlerter(NewAlerter(srv.URL, nil, logger))

	mu.Lock()
	defer mu.Unlock()
	triggers := 0
	for _, e := range entries {
		if e.EventType == "honeypot_trigger" {
			triggers++
		}
	}
	if triggers != trapFloodSize {
		t.Errorf("audited %d trap triggers out of %d attempts; the missing ones left no record", triggers, trapFloodSize)
	}
}

// rewindAlertBudget refills the bucket by moving its clock back, so a test can
// reach the recovery path without waiting out the refill interval.
func rewindAlertBudget(a *Alerter, d time.Duration) {
	a.budget.mu.Lock()
	a.budget.last = a.budget.last.Add(-d)
	a.budget.mu.Unlock()
}

// suppressedLogLine matches the line a dispatch writes when it carries a count.
var suppressedLogLine = regexp.MustCompile(`honeypot: (\d+) webhook alerts were suppressed since the last dispatch`)

// What was dropped has to be recoverable, or the rate limit becomes a way for an
// attacker to hide the size of what they did: the operator would see twenty
// alerts and no indication that twenty thousand attempts sat behind them. The
// count goes out with the next alert that gets through, in the log and in the
// durable audit entry.
//
// "Next" is decided by the order goroutines reach the counter, not the order
// they reached the budget. A flood goroutine that won a slot and was descheduled
// before collecting the count can carry part of it on its own dispatch, so the
// total is split across alerts. That loses nothing, and it is what this checks:
// every suppressed alert is reported exactly once, summed over the log and over
// the audit trail. Pinning the whole count to the recovery alert failed on CI
// whenever the scheduler interleaved that way (177 of 180).
func TestTheNumberOfSuppressedAlertsIsReportedWhenTheChannelRecovers(t *testing.T) {
	buf := captureLog(t)

	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var mu sync.Mutex
	var entries []*model.AuditEntry
	a := NewAlerter(srv.URL, nil, apAuditSpyLocked(&mu, &entries))

	floodAlerter(a)
	if posts.Load() >= trapFloodSize {
		t.Fatalf("the flood was not rationed at all (%d posts), so there is nothing to report", posts.Load())
	}

	// One more once the flood has drained. The budget is spent and no dispatch
	// is in flight to collect it, so the recovery alert below is certain to
	// carry a count of its own.
	a.Alert(context.Background(), Event{EventType: "trap_login", IP: "203.0.113.9"})
	wantSuppressed := trapFloodSize + 1 - posts.Load()

	rewindAlertBudget(a, time.Minute)
	a.Alert(context.Background(), Event{EventType: "trap_login", IP: "203.0.113.9"})

	var logged int64
	for _, m := range suppressedLogLine.FindAllStringSubmatch(buf.String(), -1) {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			t.Fatalf("unparseable count in %q: %v", m[0], err)
		}
		logged += n
	}
	if logged != wantSuppressed {
		t.Errorf("the log reports %d suppressed alerts in total, want %d", logged, wantSuppressed)
	}

	mu.Lock()
	defer mu.Unlock()
	last := entries[len(entries)-1]
	if last.EventType != "honeypot_alert" {
		t.Fatalf("last audit entry is %q, want the alert dispatch", last.EventType)
	}
	if got, _ := last.Metadata["suppressed_since_last"].(int64); got < 1 {
		t.Errorf("the recovery alert's audit entry records suppressed_since_last = %v, want the backlog", last.Metadata["suppressed_since_last"])
	}
	var audited int64
	for _, e := range entries {
		if e.EventType != "honeypot_alert" {
			continue
		}
		if n, ok := e.Metadata["suppressed_since_last"].(int64); ok {
			audited += n
		}
	}
	if audited != wantSuppressed {
		t.Errorf("the audit trail records %d suppressed alerts in total, want %d", audited, wantSuppressed)
	}
}

// A dropped alert must not be a silent drop, and it must not be a log line per
// dropped alert either: the second is the same denial of service moved from the
// webhook to the operator's log. One line per episode, then the count when the
// channel recovers.
func TestSuppressedWebhookAlertsAreAnnouncedOncePerEpisodeRatherThanPerAlert(t *testing.T) {
	buf := captureLog(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	floodAlerter(NewAlerter(srv.URL, nil, nil))

	announcements := strings.Count(buf.String(), "honeypot: webhook alert budget exhausted")
	if announcements == 0 {
		t.Error("alerts were dropped and nothing said so; the operator cannot tell a quiet trap from a suppressed one")
	}
	if announcements > 1 {
		t.Errorf("%d suppression lines for one episode; the attacker now drives the log volume instead", announcements)
	}
}
