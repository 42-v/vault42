package alert

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

// The record has to be routable without parsing it. vault42 already publishes
// SECURITY WARNING as the prefix for a degraded control, and an operator's
// pipeline routes on a prefix; an alert nobody can select on is a log line.
func TestLogSink_WritesOneRoutableRecordPerAlert(t *testing.T) {
	buf := captureLog(t)

	LogSink{}.Deliver(context.Background(), Alert{
		Rule:      "credential-stuffing",
		EventType: "login_failure",
		Scope:     ScopeSource,
		Key:       "203.0.113.0",
		Count:     40,
		Window:    5 * time.Minute,
		Severity:  25,
		Breach:    false,
		At:        time.Unix(1_700_000_000, 0),
	})

	out := buf.String()
	if lines := strings.Count(strings.TrimSpace(out), "\n"); lines != 0 {
		t.Errorf("one alert produced %d newlines inside the record; a multi-line alert cannot be "+
			"routed on its prefix: %q", lines, out)
	}
	if !strings.HasPrefix(out, "SECURITY ALERT: ") {
		t.Errorf("record does not start with the routable prefix: %q", out)
	}
	for _, want := range []string{
		"rule=credential-stuffing",
		"event_type=login_failure",
		"source=203.0.113.0",
		"count=40",
		"window=5m0s",
		"severity=25",
		"breach=false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("record is missing %q: %q", want, out)
		}
	}
}

// The breach flag is what tells an operator which alert starts a 72-hour clock,
// so it has to survive into the record rather than stay a field nobody renders.
func TestLogSink_CarriesTheBreachFlag(t *testing.T) {
	buf := captureLog(t)

	LogSink{}.Deliver(context.Background(), Alert{
		Rule:      "trap-credential-used",
		EventType: "honeypot_trigger",
		Scope:     ScopeSubject,
		Key:       "user-1",
		Count:     1,
		Window:    time.Minute,
		Severity:  100,
		Breach:    true,
	})

	if out := buf.String(); !strings.Contains(out, "breach=true") {
		t.Errorf("a breach-class alert rendered without breach=true: %q", out)
	}
}

// The end-to-end version of the injection assertion: an attacker-chosen subject
// reaches this sink through a real detector, and the record it produces must
// still be one line an operator's terminal will not act on.
func TestLogSink_RendersAnAttackerChosenSubjectAsOneInertLine(t *testing.T) {
	buf := captureLog(t)

	d := NewDetector(LogSink{}, 64)
	r := testRule()
	r.Threshold = 1
	d.Observe(context.Background(), time.Unix(1_700_000_000, 0), r, "token_minted",
		"sub\nSECURITY ALERT: rule=all-clear\x1b[2J", "")

	out := strings.TrimSuffix(buf.String(), "\n")
	if strings.Contains(out, "\n") {
		t.Errorf("the subject forged a second record: %q", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("the subject reached the operator's terminal as a control sequence: %q", out)
	}
}
