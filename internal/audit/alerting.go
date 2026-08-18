package audit

import (
	"context"
	"time"

	"github.com/42-v/vault42/internal/alert"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
)

// Detection rules: which event classes are watched, how many of them inside how
// long before an operator hears about it, and which of those would start a
// GDPR Art. 33 assessment.
//
// The table is deliberately short. Every declared event class is scored, because
// a score is a review aid and costs nothing; only these classes are watched,
// because every rule is a page somebody carries and a rule nobody trusts is
// worse than no rule. An event class with no entry here is recorded, scored and
// filterable, and raises nothing.
//
// The thresholds are not a single constant. One threshold over a severity score
// would fire on every honeypot trigger and never on ten thousand failed logins,
// which is the amplifier and the blind spot in the same mechanism: what makes a
// run of failed logins an attack is the run, and what makes one trap credential
// use an attack is that it happened at all. So each class carries its own count.

const (
	// shortWindow is the interval for classes an attacker can drive at HTTP
	// speed. Five minutes is long enough that a slow run still accumulates and
	// short enough that a count decays before it collects unrelated traffic.
	shortWindow = 5 * time.Minute
	// longWindow is the interval for classes bounded by something slower than
	// the network: a mailed link, an operator's hands, a data export.
	longWindow = 15 * time.Minute
	// alertCooldown silences a key after its rule fires. It is the difference
	// between one alert per campaign and one alert per request, and a
	// credential-stuffing run is thousands of requests.
	alertCooldown = 30 * time.Minute
)

// alertRules maps an event class to the detection watching it.
//
// Breach marks the classes whose alert says personal data may have been
// accessed, disclosed or destroyed by somebody who should not have -- the
// classes that would start a GDPR Art. 33 assessment. A failed login is not one:
// a login that failed disclosed nothing. Marking everything would make the flag
// mean nothing, which is the failure mode of every "severity: high" field.
var alertRules = map[string]alert.Rule{
	// Credential stuffing and password spraying. The count is kept per subject
	// and per source network, so a run against one account and a run across ten
	// thousand accounts from one place both reach it.
	LoginFailure: {
		Name: "credential-stuffing", Threshold: 25, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeverityNotable,
	},
	// The admin plane has a far smaller legitimate population, so the same shape
	// of attack shows up at a much lower count.
	AdminLoginFailure: {
		Name: "admin-brute-force", Threshold: 5, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeverityElevated,
	},
	// An authenticated admin repeatedly refused a route their role does not
	// carry. The decision is enforced regardless; the run is the probe.
	AdminAuthzDenied: {
		Name: "privilege-probe", Threshold: 5, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious,
	},
	// Bearer tokens and sessions being replayed or guessed at the admin edge.
	AdminSessionRejected: {
		Name: "admin-session-probe", Threshold: 10, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious,
	},
	// A refresh cookie presented from a device other than the one it was issued
	// to. Three of them is not a browser upgrade.
	FingerprintAnomaly: {
		Name: "session-hijack", Threshold: 3, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// The same signal for a DPoP-bound family: the cookie arrived without proof
	// of the key it was bound to.
	DPoPBindingMismatch: {
		Name: "dpop-binding-probe", Threshold: 3, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// A trap credential has no legitimate user, so one use is the alert. The
	// cooldown is what keeps a login loop against the trap from becoming an
	// amplifier pointed at the operator.
	HoneypotTrigger: {
		Name: "trap-credential-used", Threshold: 1, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeverityCritical, Breach: true,
	},
	// The envelope-unwrap oracle. A burst is a caller walking key ids.
	KMSUnwrap: {
		Name: "key-release-burst", Threshold: 20, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// Tokens signed for subjects vault42 never authenticated. A burst is a
	// service credential in the wrong hands, and the mint event is the only
	// attribution there is.
	TokenMinted: {
		Name: "mint-burst", Threshold: 20, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// Personal data leaving under Art. 15 or Art. 20. Legitimate one at a time;
	// a run is somebody harvesting through stolen sessions.
	DataExport: {
		Name: "bulk-personal-data-export", Threshold: 5, Window: longWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// Service documents are service-authored personal data about a user, and the
	// read event is the record of who read whose.
	SvcDocGet: {
		Name: "service-document-sweep", Threshold: 100, Window: shortWindow,
		Cooldown: alertCooldown, Severity: SeverityElevated, Breach: true,
	},
	// Destruction of personal data is an Art. 33 outcome in its own right, and
	// erasure is irreversible.
	AccountErased: {
		Name: "mass-erasure", Threshold: 5, Window: longWindow,
		Cooldown: alertCooldown, Severity: SeveritySerious, Breach: true,
	},
	// A second factor enrolled repeatedly is how a session thief keeps an
	// account after the owner changes the password.
	TwoFASetup: {
		Name: "factor-enrollment-burst", Threshold: 5, Window: longWindow,
		Cooldown: alertCooldown, Severity: SeverityElevated,
	},
	// The classic first act after a takeover, and the classic shape of a
	// credential-rotation script gone wrong.
	PasswordChange: {
		Name: "credential-change-burst", Threshold: 10, Window: longWindow,
		Cooldown: alertCooldown, Severity: SeverityElevated,
	},
	// A stolen credential in use somewhere the account has never been seen.
	LoginNewCountry: {
		Name: "new-country-burst", Threshold: 3, Window: longWindow,
		Cooldown: alertCooldown, Severity: SeverityElevated,
	},
}

// AlertRule returns the detection watching an event class, if any. It is
// exported so tests/compliance can assert the register's claims about which
// classes are watched and which of them are breach-relevant, without this
// package exposing a mutable table.
func AlertRule(eventType string) (alert.Rule, bool) {
	r, ok := alertRules[eventType]
	return r, ok
}

// AlertedEventTypes returns every event class a rule watches.
func AlertedEventTypes() []string {
	out := make([]string, 0, len(alertRules))
	for e := range alertRules {
		out = append(out, e)
	}
	return out
}

// SetDetector installs the detector this logger raises alerts through.
//
// A setter rather than a constructor argument because NewLogger and
// NewLoggerWithBufferSize have a hundred callers across the tree and the
// detector is a startup wiring decision made in one of them. The pointer is held
// atomically because Log reads it from every request goroutine; a nil detector
// is inert, which is the state every unit test that builds a logger is in.
func (l *Logger) SetDetector(d *alert.Detector) {
	l.detector.Store(d)
}

// observe feeds one recorded event to the detector.
//
// Three properties, each of which is the reason a line here reads the way it
// does:
//
// It runs after the entry has been handled, from a defer on Log, so no branch
// can reach a return without it and none can be blocked by it. An alert that
// could fail an audit write would make a notification problem into an
// authentication problem, and the audit write is already the thing that must not
// be blocked.
//
// It runs on the dropped path too. An event that met a full buffer still
// happened, and a detector that went quiet under buffer pressure would hand an
// attacker the same trick isCriticalEvent already refuses them: flood the
// logger, then probe in silence.
//
// It passes the masked source network rather than the address. The audit row
// holds the whole one and docs/PRIVACY.md inventories it as the place that does;
// an alert is a process-log record, and the tree's rule for those is a masked
// network. The masking is also better correlation, not worse: a run from one /24
// aggregates into one counter instead of scattering across 256.
func (l *Logger) observe(ctx context.Context, entry *model.AuditEntry) {
	d := l.detector.Load()
	if d == nil {
		return
	}
	rule, watched := alertRules[entry.EventType]
	if !watched {
		return
	}
	var source string
	if entry.IP != "" {
		source = httputil.ObfuscatedIP(entry.IP)
	}
	d.Observe(ctx, entry.Timestamp, rule, entry.EventType, entry.UserID, source)
}
