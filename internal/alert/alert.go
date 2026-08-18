// Package alert raises operator-facing notifications from security events.
//
// It exists because vault42 recorded every security-relevant event in an
// append-only store and then raised nothing from it: the only outbound channel
// was the honeypot webhook, installed only under the honeypot profile, so on a
// production deployment time-to-detection was "whenever an operator looks".
//
// Three properties shape the whole package, and all three are security
// properties rather than ergonomics:
//
//   - An alert must not become an amplifier. The attacker decides how many
//     failed logins happen, so a notification per event is a mail bomb aimed at
//     whoever receives it, and ten thousand copies of the first alert bury the
//     one worth reading. Every detection is therefore a windowed count with a
//     threshold and a cooldown, and the key space it counts over is bounded,
//     because the attacker chooses the keys too.
//
//   - An alert must not become a side channel. The values that identify an
//     event — the subject and the event type — reach the audit log from callers,
//     and POST /mint files rows under a subject vault42 never authenticated. An
//     operator reads an alert in a terminal, and a terminal acts on what it is
//     sent, so every caller-influenced field is neutralised and length-bounded
//     here rather than in each sink. The source is a masked network, never an
//     address: the audit row already holds the whole one and docs/PRIVACY.md
//     inventories it as the place that does.
//
//   - An alert must not cost availability. The caller is the login path.
//     Nothing in this package returns an error, nothing blocks on a sink while
//     holding the counter lock, and a sink that panics is contained rather than
//     propagated, on the same principle that makes the metrics listener's bind
//     failure non-fatal.
package alert

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/metrics"
)

// Scope names which of an event's two correlatable identities a count was kept
// over. Both are kept, because the two shapes of the same attack are invisible
// to each other: a password-spraying run against one account never moves a
// per-source counter far, and a credential-stuffing run against ten thousand
// accounts never moves any per-subject counter at all.
const (
	// ScopeSubject counts events sharing one actor — a user id, or the subject a
	// mint caller asserted.
	ScopeSubject = "subject"
	// ScopeSource counts events sharing one masked source network.
	ScopeSource = "source"
)

// RuleSaturated is the rule name the detector raises under its own name when the
// bounded key space is full. It is not a detection about the product; it is the
// detector reporting that it has stopped being able to detect, which is the one
// thing a bounded counter must never do quietly.
const RuleSaturated = "detector-saturated"

// maxKeyLen bounds every caller-influenced string an alert carries.
//
// A user id is a 36-character UUID and an event type is a constant, so the bound
// only ever truncates a value someone chose. Two distinct oversized subjects
// then share a counter, which merges an attacker's own events and raises the
// alert sooner rather than later; the alternative is one log line per alert
// whose length the attacker picks.
const maxKeyLen = 96

// Alert is one raised detection. Every string field is already neutralised and
// length-bounded, so a sink may render it without sanitising it again.
type Alert struct {
	// Rule is the detection that fired, from Rule.Name, or RuleSaturated.
	Rule string
	// EventType is the audit event class the count was kept over.
	EventType string
	// Scope is ScopeSubject or ScopeSource.
	Scope string
	// Key is the subject or the masked source network the count was kept under.
	Key string
	// Count is how many events were observed in the window when the rule fired.
	// It is at least the threshold, and more when a cooldown was suppressing.
	Count int
	// Window is the interval the count was kept over.
	Window time.Duration
	// Severity is the event class's score on the internal/audit scale.
	Severity int
	// Breach marks a detection whose subject matter is unauthorised access to,
	// disclosure of, or destruction of personal data — the classes that would
	// start a GDPR Art. 33 assessment. It is a routing hint, not a legal
	// conclusion: whether a notifiable breach occurred is an assessment a
	// controller makes, and this flag exists so the assessment can start inside
	// 72 hours instead of whenever someone next reads the audit view.
	Breach bool
	// At is when the rule fired.
	At time.Time
}

// Rule is one detection: how many events of a class, over what window, before
// the operator hears about it, and how long they are spared hearing it again.
type Rule struct {
	// Name identifies the detection in the alert. It is a constant, never
	// derived from an event.
	Name string
	// Threshold is how many events inside Window raise the alert. A rule with a
	// threshold of one alerts on a single occurrence and is reserved for classes
	// where one occurrence is already exceptional.
	Threshold int
	// Window is how long a count accumulates before it decays. Without it a
	// threshold is a lifetime counter that eventually fires for every account
	// that has ever mistyped a password.
	Window time.Duration
	// Cooldown silences the same key after the rule fires. Without it a
	// credential-stuffing run raises one alert per attempt, which is
	// functionally the same as raising none.
	Cooldown time.Duration
	// Severity is the event class's score, carried through to the alert.
	Severity int
	// Breach marks the class as one that would start an Art. 33 clock. See
	// Alert.Breach.
	Breach bool
}

// valid reports whether a rule can raise anything sensible. A malformed rule is
// ignored rather than corrected: a threshold of zero would fire on every event,
// which is the amplifier this package exists to prevent, and silently rewriting
// it to one would hide the mistake behind exactly that behaviour.
func (r Rule) valid() bool {
	return r.Name != "" && r.Threshold > 0 && r.Window > 0
}

// Sink delivers a raised alert. Implementations must not block for long and must
// not return errors: the caller is a request path and there is nothing useful it
// could do with one.
type Sink interface {
	Deliver(ctx context.Context, a Alert)
}

// LogSink writes each alert as one structured process-log record.
//
// This is the delivery mechanism vault42 1.0.0 ships, and the argument for it is
// that it is the one an operator already has. The process log is the channel the
// repository already publishes routable severity on — config.Validate emits
// SECURITY WARNING for a degraded control and the deployment guide tells
// operators to route it — so an alert on the same channel needs no new
// configuration, no new outbound connection, and no chart change to be seen. A
// webhook shipped as the default would be a feature that cannot work on the
// shipped deployment: the chart's NetworkPolicy admits no 443 egress at all.
//
// It is also the mechanism with the fewest ways to hurt. It cannot be pointed at
// an internal address, it cannot exhaust sockets, it cannot mail anybody, and it
// cannot fail in a way that refuses a login. Sink exists so a webhook or a
// mailer is a wiring change rather than a rewrite, and the case for shipping one
// in 1.0.0 was not made.
type LogSink struct{}

// Deliver writes the alert as one line with a fixed, greppable prefix.
func (LogSink) Deliver(_ context.Context, a Alert) {
	// #nosec G706 -- every string field was neutralised and bounded by safeField
	// before the Alert was constructed; see the package comment.
	log.Printf("SECURITY ALERT: rule=%s event_type=%s %s=%s count=%d window=%s severity=%d breach=%t",
		a.Rule, a.EventType, a.Scope, a.Key, a.Count, a.Window, a.Severity, a.Breach)
}

// safeField neutralises and bounds a caller-influenced string.
//
// SafeLogValue is the tree's existing answer to a value that will be printed: it
// replaces every character that can end a record or drive a terminal. Space is
// replaced on top of that because an alert is read as key=value pairs and a
// value carrying a space forges a second pair.
func safeField(s string) string {
	s = httputil.SafeLogValue(s)
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > maxKeyLen {
		s = s[:maxKeyLen]
	}
	return s
}

// raiseSecurityAlert reports one alert to the process-wide counter.
//
// It is package level for the same reason the audit drop tallies are: the
// detector is built at startup beside the audit logger, before the metrics
// collector exists, and threading a collector through it for a figure that is
// process-wide anyway would buy nothing.
func raiseSecurityAlert() { metrics.RecordSecurityAlert() }
