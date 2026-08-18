package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/alert"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// spySink records the alerts a logger raised.
type spySink struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (s *spySink) Deliver(_ context.Context, a alert.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
}

func (s *spySink) all() []alert.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]alert.Alert, len(s.alerts))
	copy(out, s.alerts)
	return out
}

// alertingLogger returns a logger wired to a recording sink.
func alertingLogger(t *testing.T, repo repository.AuditRepository, flushEvery time.Duration, bufferSize int) (*Logger, *spySink) {
	t.Helper()
	sink := &spySink{}
	l := NewLoggerWithBufferSize(repo, flushEvery, bufferSize)
	l.SetDetector(alert.NewDetector(sink, 64))
	t.Cleanup(func() { _ = l.Close(context.Background()) })
	return l, sink
}

// The requirement AU-6 actually states is analysis, not review. The smallest
// honest version of analysis is a count that says something no single event
// says: a run of failed logins below the rule's threshold is ordinary traffic
// and must raise nothing, and the run that crosses it must raise exactly one
// alert rather than one per attempt.
func TestAlerting_ARunBelowTheThresholdRaisesNothingAndOneAboveItRaisesOneAlert(t *testing.T) {
	rule, ok := AlertRule(LoginFailure)
	if !ok {
		t.Fatal("login_failure is no longer watched; CR-15's central case is unwatched")
	}

	t.Run("below", func(t *testing.T) {
		repo := &mockAuditRepo{}
		l, sink := alertingLogger(t, repo, 0, 0)
		for i := 0; i < rule.Threshold-1; i++ {
			if err := l.Log(context.Background(), LoginFailure, "user-1", "", "203.0.113.7", "ua", "", "",
				map[string]interface{}{"reason": "invalid_password"}); err != nil {
				t.Fatalf("log: %v", err)
			}
		}
		if got := sink.all(); len(got) != 0 {
			t.Fatalf("%d failures below a threshold of %d raised %d alerts, want 0: %+v",
				rule.Threshold-1, rule.Threshold, len(got), got)
		}
		if len(repo.entries) != rule.Threshold-1 {
			t.Fatalf("stored %d entries, want %d: the trail is unaffected by the alerting",
				len(repo.entries), rule.Threshold-1)
		}
	})

	t.Run("above", func(t *testing.T) {
		repo := &mockAuditRepo{}
		l, sink := alertingLogger(t, repo, 0, 0)
		const attempts = 400
		for i := 0; i < attempts; i++ {
			// No source address, so only the per-subject counter can fire and
			// the count below is the number of alerts one run produced.
			if err := l.Log(context.Background(), LoginFailure, "user-1", "", "", "ua", "", "",
				map[string]interface{}{"reason": "invalid_password"}); err != nil {
				t.Fatalf("log: %v", err)
			}
		}
		got := sink.all()
		if len(got) != 1 {
			t.Fatalf("%d failures against one account raised %d alerts, want exactly 1; a "+
				"notification per failed login is a mail bomb aimed at whoever receives it: %+v",
				attempts, len(got), got)
		}
		if got[0].Rule != rule.Name {
			t.Errorf("alert rule = %q, want %q", got[0].Rule, rule.Name)
		}
		if len(repo.entries) != attempts {
			t.Errorf("stored %d entries, want %d", len(repo.entries), attempts)
		}
	})
}

// An event class with no rule is recorded, scored and filterable, and raises
// nothing. Alerting on everything is the same as alerting on nothing.
func TestAlerting_AnUnwatchedEventClassRaisesNothing(t *testing.T) {
	if _, watched := AlertRule(LoginSuccess); watched {
		t.Skip("login_success has gained a rule; pick another unwatched class for this assertion")
	}
	repo := &mockAuditRepo{}
	l, sink := alertingLogger(t, repo, 0, 0)

	for i := 0; i < 1000; i++ {
		if err := l.Log(context.Background(), LoginSuccess, "user-1", "", "203.0.113.7", "ua", "", "", nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("1000 successful logins raised %d alerts: %+v", len(got), got)
	}
}

// failingRepo refuses every write.
type failingRepo struct{ mockAuditRepo }

var errStoreDown = errors.New("audit store is down")

func (r *failingRepo) Insert(context.Context, *model.AuditEntry) error { return errStoreDown }

func (r *failingRepo) InsertBatch(context.Context, []*model.AuditEntry) error { return errStoreDown }

// The detection must not be conditional on the write succeeding. The events most
// likely to be in flight during a database problem are the ones describing what
// was happening at the time, and a store outage that also switched off detection
// would be an attack window with a trigger an attacker can pull.
func TestAlerting_AStoreThatRefusesTheWriteStillRaisesTheAlert(t *testing.T) {
	rule, _ := AlertRule(LoginFailure)
	l, sink := alertingLogger(t, &failingRepo{}, 0, 0)

	var lastErr error
	for i := 0; i < rule.Threshold; i++ {
		lastErr = l.Log(context.Background(), LoginFailure, "user-1", "", "", "ua", "", "", nil)
	}

	if !errors.Is(lastErr, errStoreDown) {
		t.Errorf("Log returned %v; the store error must still reach the caller", lastErr)
	}
	if got := sink.all(); len(got) != 1 {
		t.Fatalf("a run against a dead store raised %d alerts, want 1: %+v", len(got), got)
	}
}

// isCriticalEvent already refuses an attacker the trick of flooding the buffer
// and then acting in the silence. Detection has to refuse it the same way, or
// the buffer is a switch that turns the alerting off.
func TestAlerting_AFullBufferDoesNotSilenceDetection(t *testing.T) {
	rule, _ := AlertRule(LoginNewCountry)
	if isCriticalEvent(LoginNewCountry) {
		t.Skip("login_new_country is now critical, so it never meets the dropped path")
	}
	repo := &mockAuditRepo{}
	// A buffer of one, a flush interval that will not elapse during the test:
	// every event after the first meets a full buffer and is dropped.
	l, sink := alertingLogger(t, repo, time.Hour, 1)

	for i := 0; i < rule.Threshold+1; i++ {
		if err := l.Log(context.Background(), LoginNewCountry, "user-1", "", "", "ua", "", "",
			map[string]interface{}{"country": "SK"}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	if l.DroppedTotal() == 0 {
		t.Fatal("nothing met a full buffer; this test is not exercising the dropped path")
	}
	if got := sink.all(); len(got) != 1 {
		t.Fatalf("a run that filled the buffer raised %d alerts, want 1; buffer pressure is not a "+
			"way to go silent: %+v", len(got), got)
	}
}

// docs/PRIVACY.md inventories the audit store as the place that holds a whole
// address. An alert is a process-log record, and the tree's rule for those is a
// masked network.
func TestAlerting_TheAlertCarriesAMaskedNetworkAndNeverTheAddress(t *testing.T) {
	rule, _ := AlertRule(LoginFailure)
	repo := &mockAuditRepo{}
	l, sink := alertingLogger(t, repo, 0, 0)

	const addr = "203.0.113.42"
	for i := 0; i < rule.Threshold; i++ {
		// A different subject each time, so only the source counter can fire.
		if err := l.Log(context.Background(), LoginFailure, "user-"+string(rune('a'+i)), "", addr, "ua", "", "", nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("raised %d alerts, want 1: %+v", len(got), got)
	}
	if got[0].Scope != alert.ScopeSource {
		t.Fatalf("alert scope = %q, want %q", got[0].Scope, alert.ScopeSource)
	}
	if strings.Contains(got[0].Key, addr) {
		t.Errorf("the alert carries the whole address %q; it must carry the masked network", got[0].Key)
	}
	if got[0].Key != "203.0.113.0" {
		t.Errorf("alert key = %q, want the masked network 203.0.113.0", got[0].Key)
	}
	// The audit row is the place that keeps the address.
	if len(repo.entries) == 0 || repo.entries[0].IP != addr {
		t.Error("the audit row no longer holds the whole address; masking belongs to the alert only")
	}
}

// The alert carries the class's score, so an operator routing on severity gets
// the same number a risk_score filter would have given them.
func TestAlerting_TheAlertCarriesTheEventClassSeverity(t *testing.T) {
	for _, event := range AlertedEventTypes() {
		rule, _ := AlertRule(event)
		if rule.Severity != Severity(event) {
			t.Errorf("the rule for %s carries severity %d and the table says %d; two numbers for "+
				"one class is the defect this table replaced", event, rule.Severity, Severity(event))
		}
	}
}

// A class with no legitimate traffic must not be waiting for a run. There is no
// second honeypot trigger to wait for: the first one is the whole signal.
func TestAlerting_EveryCriticalClassIsWatchedAndFiresOnTheFirstEvent(t *testing.T) {
	watched := 0
	for event, score := range severityByEvent {
		if score != SeverityCritical || event == AdminKillswitchTriggered {
			continue
		}
		watched++
		rule, ok := AlertRule(event)
		if !ok {
			t.Errorf("%s scores critical and no rule watches it. A class with no legitimate "+
				"traffic that raises nothing is the finding CR-15 recorded, one event class down.", event)
			continue
		}
		if rule.Threshold != 1 {
			t.Errorf("%s scores critical and its rule waits for %d events. There is no second one "+
				"to wait for.", event, rule.Threshold)
		}
	}
	if watched == 0 {
		t.Fatal("no critical event class was examined; this gate is vacuous")
	}
}

// Every rule has to be capable of firing and of stopping. A rule with no
// cooldown is an amplifier and a rule with no window is a lifetime counter.
func TestAlerting_EveryRuleIsWellFormed(t *testing.T) {
	events := AlertedEventTypes()
	if len(events) == 0 {
		t.Fatal("no event class is watched at all")
	}
	for _, event := range events {
		rule, _ := AlertRule(event)
		switch {
		case rule.Name == "":
			t.Errorf("the rule for %s has no name, so its alert would not say what fired", event)
		case rule.Threshold < 1:
			t.Errorf("the rule for %s has threshold %d, which fires on every event", event, rule.Threshold)
		case rule.Window <= 0:
			t.Errorf("the rule for %s has no window, so its count never decays", event)
		case rule.Cooldown <= 0:
			t.Errorf("the rule for %s has no cooldown, so a sustained run alerts per event", event)
		}
		if _, scored := severityByEvent[event]; !scored {
			t.Errorf("the rule for %s watches a class the severity table does not score", event)
		}
	}
}

// The two axes say different things -- "this account is under attack" and "this
// network is attacking" -- so a run visible on both raises one alert on each.
// What it must not do is raise more than that: two per campaign per cooldown is
// a report, and one per attempt is a flood.
func TestAlerting_ARunVisibleOnBothAxesRaisesOnePerAxisAndNoMore(t *testing.T) {
	rule, _ := AlertRule(LoginFailure)
	repo := &mockAuditRepo{}
	l, sink := alertingLogger(t, repo, 0, 0)

	for i := 0; i < rule.Threshold*20; i++ {
		if err := l.Log(context.Background(), LoginFailure, "user-1", "", "203.0.113.7", "ua", "", "", nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("%d failures raised %d alerts, want one per axis: %+v", rule.Threshold*20, len(got), got)
	}
	scopes := map[string]int{}
	for _, a := range got {
		scopes[a.Scope]++
	}
	if scopes[alert.ScopeSubject] != 1 || scopes[alert.ScopeSource] != 1 {
		t.Errorf("alerts by scope = %v, want exactly one subject and one source", scopes)
	}
}

// inspectingSink asks, at the moment it is delivered to, whether the record that
// caused the alert is already in the store.
type inspectingSink struct {
	repo             *mockAuditRepo
	delivered        int
	storedAtDelivery int
}

func (s *inspectingSink) Deliver(_ context.Context, _ alert.Alert) {
	s.delivered++
	s.repo.mu.Lock()
	defer s.repo.mu.Unlock()
	s.storedAtDelivery = len(s.repo.entries)
}

// The order is load-bearing, not cosmetic. Detection runs after the entry has
// been handled, so nothing about raising an alert can stand between an event and
// its audit row: an alert evaluated first turns a slow or broken notification
// into a failed audit write, and the audit write is the one thing on this path
// that must not be blocked.
func TestAlerting_TheRecordIsHandledBeforeTheAlertIsRaised(t *testing.T) {
	rule, _ := AlertRule(LoginFailure)
	repo := &mockAuditRepo{}
	sink := &inspectingSink{repo: repo}
	l := NewLogger(repo, 0)
	l.SetDetector(alert.NewDetector(sink, 64))

	for i := 0; i < rule.Threshold; i++ {
		if err := l.Log(context.Background(), LoginFailure, "user-1", "", "", "ua", "", "", nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	if sink.delivered != 1 {
		t.Fatalf("sink was delivered to %d times, want 1", sink.delivered)
	}
	if sink.storedAtDelivery != rule.Threshold {
		t.Errorf("the store held %d of %d records when the alert was delivered. The event that "+
			"raised the alert was not written yet, so detection is running in front of the audit "+
			"write, which is how a notification failure becomes an authentication failure.",
			sink.storedAtDelivery, rule.Threshold)
	}
}
