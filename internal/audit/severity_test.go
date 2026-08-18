package audit

import (
	"context"
	"testing"
)

// The register's finding was that risk_score is a per-call-site integer literal:
// 100 here, 45 there, 30, 20, 10 and 0 elsewhere, with the same event class
// carrying four different numbers depending on which branch reached it. A
// threshold over that means nothing. The score has to be a property of the event
// class and of nothing else.
func TestSeverity_IsAPropertyOfTheEventTypeAndNotOfTheCallSite(t *testing.T) {
	repo := &mockAuditRepo{}
	l := NewLogger(repo, 0)

	// Two call sites, two reasons, one event class.
	if err := l.Log(context.Background(), LoginFailure, "u1", "", "203.0.113.7", "ua", "", "",
		map[string]interface{}{"reason": "user_not_found"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	if err := l.Log(context.Background(), LoginFailure, "u2", "", "203.0.113.8", "ua", "", "",
		map[string]interface{}{"reason": "ip_locked"}); err != nil {
		t.Fatalf("log: %v", err)
	}

	if len(repo.entries) != 2 {
		t.Fatalf("stored %d entries, want 2", len(repo.entries))
	}
	want := Severity(LoginFailure)
	for i, e := range repo.entries {
		if e.RiskScore != want {
			t.Errorf("entry %d scored %d, want Severity(%s) = %d; the number still depends on the "+
				"branch that wrote it", i, e.RiskScore, LoginFailure, want)
		}
	}
}

// The scale is what makes the number comparable across event classes, which is
// the whole point of a threshold. A score off the scale is a private convention
// that only its author can read.
func TestSeverity_EveryScoreIsOnTheDeclaredScale(t *testing.T) {
	bands := map[int]string{
		SeverityRoutine:  "routine",
		SeverityNotable:  "notable",
		SeverityElevated: "elevated",
		SeveritySerious:  "serious",
		SeverityCritical: "critical",
	}
	if len(bands) != 5 {
		t.Fatalf("the scale collapsed to %d distinct bands; two of them are now the same number", len(bands))
	}
	if len(severityByEvent) == 0 {
		t.Fatal("the severity table is empty; every assertion here would be vacuous")
	}
	for event, score := range severityByEvent {
		if _, ok := bands[score]; !ok {
			t.Errorf("%s scores %d, which is not one of the declared bands %v", event, score, bands)
		}
	}
}

// An event class nobody scored must not silently read as harmless. Reading as
// notable instead means a new event type is visible to a review filter on the
// day it is added, and the tests/spec gate is what makes someone score it.
func TestSeverity_AnUnscoredEventIsNotSilentlyHarmless(t *testing.T) {
	if got := Severity("a_class_nobody_has_scored"); got != SeverityNotable {
		t.Errorf("an unscored event scored %d, want the notable default %d", got, SeverityNotable)
	}
}

// The admin gateway writes its killswitch row straight to the repository, so it
// cannot go through Logger.Log. It still has to score off the same table, or the
// single most severe row in the store carries a number nothing else uses.
func TestSeverity_TheDirectlyWrittenAdminRowScoresOffTheSameTable(t *testing.T) {
	if got := Severity(AdminKillswitchTriggered); got != SeverityCritical {
		t.Errorf("%s scored %d, want critical %d", AdminKillswitchTriggered, got, SeverityCritical)
	}
}
