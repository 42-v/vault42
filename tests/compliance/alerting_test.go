package compliance

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/alert"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// =============================================================================
// Detection and alerting.
//
// Until this file, twenty-two Accepted Risk rows included three that all said
// the same thing in three vocabularies: every security-relevant event reaches an
// append-only store and nothing raises an alert from any of them. AU-6 called it
// missing analysis, A09:2025 called it missing alerting, and GDPR Arts. 33/34
// called it a 72-hour clock that only starts when an operator happens to look.
// The register's own words were that risk_score was "a hardcoded per-event
// severity tag that nothing reads, AuditFilter cannot select on it, and no
// threshold raises an alert".
//
// Each row below names a test that asserts what that row specifically requires,
// rather than one test standing in for all three. The register's rule is that a
// Met row names a test which proves it, and fifty-two rows once resting on five
// umbrella tests is the finding that rule exists for.
// =============================================================================

// recordedAlerts is a sink that keeps what the detector raised.
type recordedAlerts struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (r *recordedAlerts) Deliver(_ context.Context, a alert.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
}

func (r *recordedAlerts) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.alerts)
}

func (r *recordedAlerts) list() []alert.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]alert.Alert, len(r.alerts))
	copy(out, r.alerts)
	return out
}

// discardingAuditRepo accepts every entry. The assertions here are about what
// was raised, not about what was stored, which the V16 rows already cover.
type discardingAuditRepo struct{}

func (discardingAuditRepo) Insert(context.Context, *model.AuditEntry) error        { return nil }
func (discardingAuditRepo) InsertBatch(context.Context, []*model.AuditEntry) error { return nil }
func (discardingAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (discardingAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (discardingAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (discardingAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

// alertingLogger builds a logger whose alerts land in the returned sink.
func alertingLogger(t *testing.T) (*audit.Logger, *recordedAlerts) {
	t.Helper()
	sink := &recordedAlerts{}
	l := audit.NewLogger(discardingAuditRepo{}, 0)
	l.SetDetector(alert.NewDetector(sink, alert.DefaultMaxKeys))
	t.Cleanup(func() { _ = l.Close(context.Background()) })
	return l, sink
}

// --- NIST SP 800-53 AU-6: audit record review, analysis and reporting -------

// AU-6's review half needs the severity signal to be selectable. Before this,
// repository.AuditFilter carried UserID, EventType, Since, Until, Limit and
// Offset, so no WHERE clause over risk_score was expressible: the one severity
// signal in the store could be read back per row and not queried at all.
func TestNIST80053_AU_6_TheSeveritySignalIsSelectable(t *testing.T) {
	filterSrc := readProductionSource(t, "internal/repository/repository.go")
	idx := strings.Index(filterSrc, "type AuditFilter struct")
	if idx < 0 {
		t.Fatal("AU-6: repository.AuditFilter has moved; re-derive this gate against the new query surface")
	}
	filter := filterSrc[idx:]
	if end := strings.Index(filter, "\n}"); end > 0 {
		filter = filter[:end]
	}
	if !strings.Contains(filter, "MinRiskScore") {
		t.Error("AU-6: repository.AuditFilter carries no risk-score field, so no review can select " +
			"on severity and the score is written and never queried")
	}

	// The field is only a predicate if the query builder emits one.
	repoSrc := readProductionSource(t, "internal/repository/postgres/audit.go")
	if !strings.Contains(repoSrc, "risk_score >= $") {
		t.Error("AU-6: the audit query builder emits no risk_score predicate, so MinRiskScore is a " +
			"struct field the store ignores")
	}

	// And only usable if an operator can ask for it.
	handlerSrc := readProductionSource(t, "internal/adminapi/handler.go")
	if !strings.Contains(handlerSrc, `q.Get("min_risk_score")`) {
		t.Error("AU-6: the admin audit view accepts no min_risk_score parameter, so the predicate " +
			"exists and nothing can reach it")
	}
}

// AU-6's other half is analysis, which is the word the requirement uses and the
// one the old row could not claim. The smallest honest version is a windowed
// count that says something no single event says. Both directions matter: a run
// under the threshold must raise nothing, because a notification per failed
// login is a mail bomb aimed at whoever receives it, and a run over it must
// raise exactly one, because ten thousand alerts and none are the same alert.
func TestNIST80053_AU_6_ACorrelatedRunRaisesOneAlertAndAQuietOneRaisesNone(t *testing.T) {
	rule, watched := audit.AlertRule(audit.LoginFailure)
	if !watched {
		t.Fatal("AU-6: login_failure is no longer watched, so the correlation this row rests on is gone")
	}

	t.Run("below the threshold", func(t *testing.T) {
		l, sink := alertingLogger(t)
		for i := 0; i < rule.Threshold-1; i++ {
			if err := l.Log(context.Background(), audit.LoginFailure, "victim", "", "", "ua", "", "",
				map[string]interface{}{"reason": "invalid_password"}); err != nil {
				t.Fatalf("AU-6: log: %v", err)
			}
		}
		if n := sink.count(); n != 0 {
			t.Errorf("AU-6: %d failures, one below the threshold of %d, raised %d alerts. An alert "+
				"per event is an amplifier pointed at the operator.", rule.Threshold-1, rule.Threshold, n)
		}
	})

	t.Run("above the threshold", func(t *testing.T) {
		l, sink := alertingLogger(t)
		for i := 0; i < rule.Threshold*40; i++ {
			if err := l.Log(context.Background(), audit.LoginFailure, "victim", "", "", "ua", "", "",
				map[string]interface{}{"reason": "invalid_password"}); err != nil {
				t.Fatalf("AU-6: log: %v", err)
			}
		}
		got := sink.list()
		if len(got) != 1 {
			t.Fatalf("AU-6: %d failures raised %d alerts, want exactly 1: %+v",
				rule.Threshold*40, len(got), got)
		}
		if got[0].Count < rule.Threshold {
			t.Errorf("AU-6: the alert reports %d events, below its own threshold of %d",
				got[0].Count, rule.Threshold)
		}
	})
}

// --- OWASP Top 10 A09:2025: security logging and ALERTING failures ---------

// The 2025 rename added "Alerting", and that rename is what moved vault42 off
// Met. The gap was never missing code: honeypot.Alerter existed, with a rate
// limit and an audit trail of its own, and cmd/vault/main.go built it only under
// config.ProfileHoneypot. On every other profile the only outbound alert channel
// in the tree was never constructed.
//
// This asserts the dispatcher is installed for a deployment that is not a
// honeypot, which is the specific claim the register row now makes.
func TestOWASP_A09_2025_TheAlertSinkIsInstalledOutsideTheHoneypotProfile(t *testing.T) {
	main := readProductionSource(t, "cmd/vault/main.go")

	idx := strings.Index(main, "SetDetector")
	if idx < 0 {
		t.Fatal("A09:2025: cmd/vault/main.go installs no alert detector, so nothing raises an " +
			"alert from the audit trail on any profile")
	}
	// The installation must not sit inside any branch. Reading the source text
	// for a profile name would be fooled by the comment beside the call, so the
	// question is asked of the syntax tree: is there a conditional between the
	// function body and this call.
	if guarded, found := detectorInstallIsGuarded(t, filepath.Join(repoRoot(t), "cmd", "vault", "main.go")); !found {
		t.Error("A09:2025: no SetDetector call was found in the syntax tree of cmd/vault/main.go")
	} else if guarded {
		t.Error("A09:2025: the alert detector is installed inside a conditional. honeypot.Alerter " +
			"was gated on config.ProfileHoneypot exactly this way, which is why a production " +
			"deployment had no alert channel at all.")
	}

	// A dispatcher wired to nothing is the same gap with a longer call graph.
	stmt := main[idx:]
	if end := strings.Index(stmt, "\n"); end > 0 {
		stmt = stmt[:end]
	}
	if !strings.Contains(stmt, "alert.LogSink") {
		t.Errorf("A09:2025: the detector is installed with %q rather than a sink that reaches an "+
			"operator", strings.TrimSpace(stmt))
	}

	// The honeypot profile is still built after this point, so the honeypot
	// deployment gets both. The claim is "every profile", not "not the honeypot".
	if !strings.Contains(main, "config.ProfileHoneypot") {
		t.Error("A09:2025: the honeypot profile has disappeared from main.go; this gate was written " +
			"against a tree where it is one profile among several")
	}
}

// This test replaces TestOWASP_A09_2025_RiskScoreIsStillWriteOnly, which was
// written to fail on closure and did.
//
// What it asserted was that repository.AuditFilter contained no field whose name
// mentioned risk, and it said in its own failure message: "CR-15 is closed: move
// the register row to Met and delete this test." Deleting it silently would have
// removed the only assertion in the suite about what risk_score is for, so the
// tripwire is replaced by the property it was waiting for rather than removed.
func TestOWASP_A09_2025_RiskScoreIsReadAndNotMerelyWritten(t *testing.T) {
	// Written by one table rather than by the call site. The old literals were
	// 100, 50, 45, 30, 20, 10 and 0, with login_failure alone carrying four of
	// them, so a threshold over the column meant a different thing per row.
	auditSrc := readProductionSource(t, "internal/audit/audit.go")
	if strings.Contains(auditSrc, "riskScore int)") {
		t.Error("A09:2025: audit.Logger.Log accepts a risk score again. Every call site passed a " +
			"literal, which is how one column came to hold seven incomparable scales.")
	}
	if !strings.Contains(auditSrc, "RiskScore:       Severity(eventType)") {
		t.Error("A09:2025: the audit entry no longer derives its score from the event class")
	}

	// Read on the query side.
	if !strings.Contains(readProductionSource(t, "internal/repository/postgres/audit.go"), "risk_score >= $") {
		t.Error("A09:2025: nothing selects on risk_score; it is write-only again")
	}

	// And read on the decision side: the score reaches the alert an operator
	// receives, which is the half the query predicate does not cover.
	events := audit.AlertedEventTypes()
	if len(events) == 0 {
		t.Fatal("A09:2025: no event class raises an alert at all")
	}
	for _, event := range events {
		rule, _ := audit.AlertRule(event)
		if rule.Severity != audit.Severity(event) {
			t.Errorf("A09:2025: the alert for %s carries severity %d and the table scores it %d",
				event, rule.Severity, audit.Severity(event))
		}
	}
}

// --- GDPR Arts. 33 and 34: notification of a personal data breach -----------

// Art. 33's clock runs from the moment the controller becomes aware, and Art.
// 33(2) makes a processor's duty "without undue delay after becoming aware".
// Neither Article is satisfied by code alone -- the assessment, the notification
// and the register of breaches are procedure -- but both are unachievable while
// nothing in the system distinguishes a breach-indicative event from an ordinary
// one, because then "becoming aware" is whenever somebody next reads the audit
// view.
//
// What this asserts is the part that is code: the event classes whose occurrence
// would start that assessment are in the alerting set and are marked as such.
func TestGDPR_Arts_33_34_BreachIndicativeEventClassesRaiseAlerts(t *testing.T) {
	// Unauthorized access, disclosure or destruction of personal data, in
	// vault42's own event vocabulary. Each is here for a reason a reader can
	// check against the class's doc comment in internal/audit/audit.go.
	breachClasses := map[string]string{
		// A trap credential has no legitimate user, so its use is somebody
		// inside the system who should not be.
		audit.HoneypotTrigger: "a trap credential was used",
		// A refresh cookie presented from a device other than the one it was
		// issued to, and one presented without the key it was bound to.
		audit.FingerprintAnomaly:  "a session is in use by something other than the browser it was issued to",
		audit.DPoPBindingMismatch: "a DPoP-bound family was presented without proof of possession",
		// Key release and subject assertion.
		audit.KMSUnwrap:   "the envelope-unwrap oracle released key material",
		audit.TokenMinted: "a token was signed for a subject vault42 never authenticated",
		// Personal data leaving, and personal data being read by a service.
		audit.DataExport: "personal data left in bulk",
		audit.SvcDocGet:  "service-authored personal data about a user was read",
		// Destruction is an Art. 33 outcome in its own right.
		audit.AccountErased: "personal data was destroyed",
	}

	for event, why := range breachClasses {
		rule, watched := audit.AlertRule(event)
		if !watched {
			t.Errorf("GDPR Art. 33: %s (%s) raises no alert. An Art. 33 clock that starts when "+
				"somebody next opens the audit view is not a 72-hour clock.", event, why)
			continue
		}
		if !rule.Breach {
			t.Errorf("GDPR Art. 33: the rule for %s (%s) is not marked breach-relevant, so the "+
				"alert does not tell an operator which one starts an assessment", event, why)
		}
	}

	// The flag has to mean something, which it stops doing the moment everything
	// carries it. A run of failed logins is an attack and discloses nothing.
	if rule, watched := audit.AlertRule(audit.LoginFailure); watched && rule.Breach {
		t.Error("GDPR Art. 33: login_failure is marked breach-relevant. A login that failed " +
			"disclosed nothing, and a flag every rule carries routes nothing.")
	}
}

// The alert an operator reads has to say which class fired and whether it starts
// a clock, or the classification above never leaves the source tree.
func TestGDPR_Arts_33_34_TheAlertSaysWhetherItStartsAClock(t *testing.T) {
	l, sink := alertingLogger(t)

	rule, watched := audit.AlertRule(audit.HoneypotTrigger)
	if !watched {
		t.Fatal("GDPR Art. 33: honeypot_trigger is unwatched")
	}
	for i := 0; i < rule.Threshold; i++ {
		if err := l.Log(context.Background(), audit.HoneypotTrigger, "", "", "203.0.113.9", "ua", "", "", nil); err != nil {
			t.Fatalf("GDPR Art. 33: log: %v", err)
		}
	}

	got := sink.list()
	if len(got) == 0 {
		t.Fatal("GDPR Art. 33: a trap credential was used and nothing was raised")
	}
	if !got[0].Breach {
		t.Error("GDPR Art. 33: the raised alert does not carry the breach flag, so an operator " +
			"cannot route the classes that start a 72-hour assessment differently from the rest")
	}
	if got[0].EventType != audit.HoneypotTrigger {
		t.Errorf("GDPR Art. 33: the alert names event class %q, want %q", got[0].EventType, audit.HoneypotTrigger)
	}
}

// detectorInstallIsGuarded reports whether a SetDetector call in the given file
// has any conditional statement between it and the enclosing function body.
func detectorInstallIsGuarded(t *testing.T, path string) (guarded, found bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var depth int
	var walk func(ast.Node) bool
	walk = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			depth++
			ast.Inspect(node.Body, walk)
			depth--
			return false
		case *ast.SwitchStmt:
			depth++
			ast.Inspect(node.Body, walk)
			depth--
			return false
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetDetector" {
				found = true
				if depth > 0 {
					guarded = true
				}
			}
		}
		return true
	}
	ast.Inspect(file, walk)
	return guarded, found
}
