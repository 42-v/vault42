package compliance

import (
	"context"
	"go/ast"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) 5.0.0
// V16: Security Logging and Error Handling
// https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0
//
// Also evidences NIST SP 800-53 Rev 5 (Release 5.2.0) AU-2, AU-3, AU-8, AU-9
// and SI-11, and OWASP Top 10:2025 A09 (Security Logging and Alerting Failures)
// and A10 (Mishandling of Exceptional Conditions).
//
// Before this file, the logging and error-handling chapter carried 34
// claimed-met requirements and zero executable assertions. The controls were
// not missing; nothing failed when they were removed.
// =============================================================================

// captureRepo is an in-memory AuditRepository. It lets the scrubbing contract
// be exercised through the exported Logger.Log path rather than through an
// unexported helper, so the assertion covers what production actually calls.
type captureRepo struct {
	mu      sync.Mutex
	entries []*model.AuditEntry
}

func (r *captureRepo) Insert(_ context.Context, entry *model.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry)
	return nil
}

func (r *captureRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entries...)
	return nil
}

func (r *captureRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (r *captureRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (r *captureRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (r *captureRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, false, nil
}

func (r *captureRepo) last(t *testing.T) *model.AuditEntry {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		t.Fatal("no audit entry was written")
	}
	return r.entries[len(r.entries)-1]
}

// logOne writes one entry through the real logger in immediate mode and returns
// what the repository received.
func logOne(t *testing.T, eventType string, metadata map[string]interface{}) *model.AuditEntry {
	t.Helper()
	repo := &captureRepo{}
	logger := audit.NewLogger(repo, 0)
	if err := logger.Log(context.Background(), eventType,
		"user-1", "client-1", "203.0.113.7", "curl/8", "fp-hash", "device-1", metadata, 50); err != nil {
		t.Fatalf("audit log: %v", err)
	}
	return repo.last(t)
}

// --- V16.2.5: sensitive data is not logged at its raw protection level ---

// "Verify that when logging sensitive data, the application enforces logging
// based on the data's protection level. For example, it may not be allowed to
// log certain data, such as credentials or payment details."
//
// Asserting that a scrub list contains "password" today proves nothing about
// the list a future change leaves behind. This drives the real logger with a
// metadata map carrying every sensitive key name in the vocabulary and requires
// each one to be gone from what the repository stored.
func TestASVS_V16_2_5_AuditMetadataScrubsCredentialKeys(t *testing.T) {
	sensitive := []string{
		"password", "secret", "token", "access_token", "refresh_token",
		"code", "totp_secret", "backup_code", "master_key", "client_secret", "api_key",
	}

	metadata := map[string]interface{}{"reason": "kept"}
	for _, k := range sensitive {
		metadata[k] = "SENSITIVE-CANARY"
	}
	// Nesting matters: a scrubber that only walks the top level leaves the same
	// value one map deeper, which is where structured metadata puts it.
	metadata["nested"] = map[string]interface{}{"password": "SENSITIVE-CANARY"}

	stored := logOne(t, audit.LoginSuccess, metadata)

	for _, k := range sensitive {
		if v, present := stored.Metadata[k]; present {
			t.Errorf("V16.2.5: metadata key %q reached storage with value %v", k, v)
		}
	}
	if nested, ok := stored.Metadata["nested"].(map[string]interface{}); ok {
		if _, present := nested["password"]; present {
			t.Error("V16.2.5: a nested password reached storage; the scrubber does not recurse")
		}
	}
	if stored.Metadata["reason"] != "kept" {
		t.Error("V16.2.5: a non-sensitive key was dropped; audit records would lose investigative value")
	}
}

// Blob reference names and labels are user-chosen and can themselves be PII.
// The objects store deliberately keeps only an HMAC of the name and the
// ciphertext of the label, and audit rows survive erasure under Art. 17(3)(b),
// so a plaintext name in an audit row would outlive the account it belongs to.
func TestASVS_V16_2_5_BlobEventsScrubUserChosenNames(t *testing.T) {
	stored := logOne(t, "blob_create", map[string]interface{}{
		"name": "medical-records", "blob_name": "medical-records",
		"ref_name": "medical-records", "label": "diagnosis", "blob_id": "kept",
	})

	for _, k := range []string{"name", "blob_name", "ref_name", "label"} {
		if _, present := stored.Metadata[k]; present {
			t.Errorf("V16.2.5: blob event retained user-chosen key %q, which can carry PII", k)
		}
	}
	if stored.Metadata["blob_id"] != "kept" {
		t.Error("V16.2.5: blob_id was dropped; the opaque identifier is what makes the record useful")
	}
}

// The wider blob key set must not leak into every other event class: an admin
// role or client event legitimately records a non-personal object name.
func TestASVS_V16_2_5_NonBlobEventsKeepTheirObjectNames(t *testing.T) {
	stored := logOne(t, audit.AdminAction, map[string]interface{}{"name": "operator"})
	if stored.Metadata["name"] != "operator" {
		t.Error("V16.2.5: the blob-scoped scrub list is being applied to non-blob events, which would blind admin auditing")
	}
}

// --- V16.2.1: log entries carry the metadata an investigation needs ---

// "Verify that each log entry includes necessary metadata (such as when, where,
// who, what) that would allow for a detailed investigation of the timeline when
// an event happens."
func TestASVS_V16_2_1_EntriesCarryWhenWhereWhoWhat(t *testing.T) {
	stored := logOne(t, audit.LoginSuccess, map[string]interface{}{"method": "password"})

	if stored.ID == "" {
		t.Error("V16.2.1: entry has no identifier")
	}
	if stored.Timestamp.IsZero() {
		t.Error("V16.2.1: entry has no timestamp (when)")
	}
	if stored.EventType != audit.LoginSuccess {
		t.Errorf("V16.2.1: entry event type is %q, want %q (what)", stored.EventType, audit.LoginSuccess)
	}
	if stored.UserID == "" {
		t.Error("V16.2.1: entry has no user id (who)")
	}
	if stored.IP == "" {
		t.Error("V16.2.1: entry has no source address (where)")
	}
	if stored.UserAgent == "" {
		t.Error("V16.2.1: entry has no user agent (where)")
	}
	if stored.ClientID == "" {
		t.Error("V16.2.1: entry has no client id; multi-tenant attribution would be impossible")
	}
}

// --- V16.2.2: timestamps use UTC or carry an explicit offset ---

// "Verify that time sources for all logging components are synchronized, and
// that timestamps in security event metadata use UTC or include an explicit
// time zone offset."
//
// Go's time.Time always carries a location, and the column is TIMESTAMPTZ, so
// the stored instant is unambiguous. A TIMESTAMP WITHOUT TIME ZONE column would
// make the offset unrecoverable, and that is the regression worth catching.
func TestASVS_V16_2_2_AuditTimestampCarriesAnOffset(t *testing.T) {
	if loc := logOne(t, audit.LoginSuccess, nil).Timestamp.Location(); loc == nil {
		t.Error("V16.2.2: the entry timestamp has no location, so its offset is unrecoverable")
	}

	schema := readProductionSource(t, "migrations/001_initial_schema.sql")
	idx := strings.Index(schema, "CREATE TABLE audit.audit_log")
	if idx < 0 {
		t.Fatal("V16.2.2: audit.audit_log is no longer created in 001_initial_schema.sql")
	}
	end := strings.Index(schema[idx:], ");")
	if end < 0 {
		t.Fatal("V16.2.2: could not delimit the audit.audit_log definition")
	}
	ddl := schema[idx : idx+end]

	if !strings.Contains(ddl, "TIMESTAMPTZ") {
		t.Error("V16.2.2: audit.audit_log does not use TIMESTAMPTZ; the recorded instant would lose its zone offset")
	}
	if regexp.MustCompile(`(?i)\btimestamp\s+TIMESTAMP\s`).MatchString(ddl) {
		t.Error("V16.2.2: the timestamp column is TIMESTAMP WITHOUT TIME ZONE")
	}
}

// --- V16.3.1 / V16.3.2: authentication and authorization outcomes are logged ---

// "Verify that all authentication operations are logged, including successful
// and unsuccessful attempts."
//
// The event vocabulary is the contract between the code and any detection rule
// written against it. A rename that silently orphans a rule is invisible to
// every behavioral test, so the values are asserted, not just the identifiers.
func TestASVS_V16_3_1_AuthenticationOutcomesHaveDistinctEventTypes(t *testing.T) {
	required := map[string]string{
		audit.LoginSuccess:  "successful authentication",
		audit.LoginFailure:  "failed authentication",
		audit.TokenRefresh:  "session extension",
		audit.TokenRevoke:   "credential revocation",
		audit.SessionRevoke: "session termination",
		audit.TwoFAVerify:   "second-factor verification",
	}

	seen := map[string]string{}
	for value, meaning := range required {
		if value == "" {
			t.Errorf("V16.3.1: the audit event constant for %s is empty", meaning)
			continue
		}
		if prior, dup := seen[value]; dup {
			t.Errorf("V16.3.1: event value %q is shared by %s and %s; the two outcomes are indistinguishable in the log", value, prior, meaning)
		}
		seen[value] = meaning
	}

	// A failed login must be recoverable as a failure without reading metadata,
	// or rate-of-failure detection has to parse free text.
	if audit.LoginSuccess == audit.LoginFailure {
		t.Fatal("V16.3.1: success and failure share one event type")
	}
}

// "Verify that failed authorization attempts are logged. For L3, this must
// include logging all authorization decisions."
//
// Scope note, recorded here because it is the honest half of this requirement:
// vault42 logs every failed *authentication* attempt on the admin plane, and
// logs the local-only killswitch trip, but RBACCheck answers 403 without
// writing an audit record. V16.3.2 is therefore carried in the register as an
// accepted risk (AR-16), not as Met. What this test pins is the part that does
// hold, so the accepted risk cannot quietly widen to cover authentication too.
func TestASVS_V16_3_2_AdminAuthenticationFailuresAreLogged(t *testing.T) {
	for _, value := range []string{audit.AdminLogin, audit.AdminLoginFailure, audit.AdminAction, audit.AdminLockout} {
		if value == "" {
			t.Error("V16.3.2: an admin-plane audit event constant is empty")
		}
	}

	authSrc := readProductionSource(t, "internal/adminapi/auth.go")
	for _, needle := range []string{"audit.AdminLoginFailure", "audit.AdminLockout"} {
		if !strings.Contains(authSrc, needle) {
			t.Errorf("V16.3.2: internal/adminapi/auth.go no longer writes %s; failed admin authentication would go unlogged", needle)
		}
	}

	// The killswitch trip is a security-control bypass attempt and must reach
	// the audit table even though it is raised from middleware.
	if !strings.Contains(readProductionSource(t, "internal/adminapi/middleware.go"), "auditRepo") {
		t.Error("V16.3.2: the admin gateway middleware no longer writes to the audit repository; the killswitch trip would go unlogged")
	}
}

// The gap named in AR-16, pinned so that closing it is detected. When
// RBACCheck starts writing an audit record, this test fails and the register
// row moves from Accepted Risk to Met.
func TestASVS_V16_3_2_RBACDenialsAreStillUnlogged(t *testing.T) {
	src := readProductionSource(t, "internal/adminapi/middleware.go")
	idx := strings.Index(src, "func RBACCheck(")
	if idx < 0 {
		t.Skip("V16.3.2: RBACCheck has moved; re-derive AR-16 against the new enforcement point")
	}
	body := src[idx:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	if strings.Contains(body, "audit") {
		t.Fatal("V16.3.2: RBACCheck now writes an audit record. AR-16 is closed: move the register row to Met and delete this test.")
	}
}

// --- V16.4.1: log data is encoded to prevent log injection ---

// "Verify that all logging components appropriately encode data to prevent log
// injection."
//
// The attack is a newline or carriage return in an attacker-controlled field
// that forges a second log line. SafeLogValue is the encoder; this pins the
// control characters it is documented to neutralize.
func TestASVS_V16_4_1_LogValuesCannotForgeNewRecords(t *testing.T) {
	cases := []struct{ name, input string }{
		{"newline", "user\nADMIN LOGIN SUCCEEDED"},
		{"carriage return", "user\rADMIN LOGIN SUCCEEDED"},
		{"crlf", "user\r\nADMIN LOGIN SUCCEEDED"},
		{"null byte", "user\x00truncated"},
		{"tab", "user\tfield-split"},
	}

	for _, tc := range cases {
		got := httputil.SafeLogValue(tc.input)
		for _, forbidden := range []string{"\n", "\r", "\x00", "\t"} {
			if strings.Contains(got, forbidden) {
				t.Errorf("V16.4.1: %s: SafeLogValue returned %q, which still carries a record-forging control character", tc.name, got)
			}
		}
	}
}

// Source addresses are pseudonymised before they reach a log line. This is both
// a log-hygiene control and the GDPR Art. 5(1)(c) minimisation position, so it
// is asserted rather than assumed.
func TestASVS_V16_4_1_LoggedAddressesArePseudonymised(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.42", "192.168.1.0"},
		{"203.0.113.201", "203.0.113.0"},
		{"not-an-ip", "invalid_ip"},
	}
	for _, tc := range cases {
		if got := httputil.ObfuscatedIP(tc.in); got != tc.want {
			t.Errorf("V16.4.1: ObfuscatedIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- V16.4.2: logs are protected from unauthorized access and modification ---

// "Verify that logs are protected from unauthorized access and cannot be
// modified."
//
// The control lives in the schema, not in Go, so the schema is what gets
// asserted. This runs without a database: the migration text is the artifact.
func TestASVS_V16_4_2_AuditLogIsAppendOnlyInTheSchema(t *testing.T) {
	schema := readProductionSource(t, "migrations/001_initial_schema.sql")

	for _, trigger := range []string{"audit_log_no_update", "audit_log_no_delete"} {
		if !strings.Contains(schema, trigger) {
			t.Errorf("V16.4.2: trigger %s is no longer created; the audit table would accept the operation it blocks", trigger)
		}
	}
	if !strings.Contains(schema, "append-only") {
		t.Error("V16.4.2: the append-only guard is gone from 001_initial_schema.sql")
	}

	// The trigger alone is not enough: a role holding UPDATE can disable it.
	// The grant model has to revoke the privilege as well.
	if !regexp.MustCompile(`(?i)REVOKE\s+UPDATE\s*,\s*DELETE\s+ON\s+audit\.audit_log\s+FROM\s+vault_app`).MatchString(schema) {
		t.Error("V16.4.2: UPDATE/DELETE on audit.audit_log is no longer revoked from vault_app")
	}
	if !regexp.MustCompile(`(?i)GRANT\s+SELECT\s*,\s*INSERT\s+ON\s+audit\.audit_log\s+TO\s+vault_app`).MatchString(schema) {
		t.Error("V16.4.2: vault_app no longer holds SELECT, INSERT on audit.audit_log")
	}
}

// The one sanctioned way to delete audit rows is the retention function, which
// disables the trigger under SECURITY DEFINER. That is a deliberate hole, so
// its guards are asserted: a pinned search_path (CVE-2018-1058), EXECUTE
// revoked from PUBLIC, and the trigger re-enabled before the function returns.
func TestASVS_V16_4_2_RetentionBypassIsHardened(t *testing.T) {
	fn := readProductionSource(t, "migrations/012_audit_function_hardening.sql")

	for _, c := range []struct{ needle, why string }{
		{"SECURITY DEFINER", "the retention function must run as owner, not as caller"},
		{"SET search_path", "an unpinned search_path lets a caller shadow the referenced objects (CVE-2018-1058)"},
		{"DISABLE TRIGGER audit_log_no_delete", "the sanctioned delete path must name the trigger it suspends"},
		{"ENABLE TRIGGER audit_log_no_delete", "the trigger must be restored before the function returns"},
		{"REVOKE ALL ON FUNCTION", "EXECUTE must not be reachable from PUBLIC"},
	} {
		if !strings.Contains(fn, c.needle) {
			t.Errorf("V16.4.2: 012_audit_function_hardening.sql no longer contains %q: %s", c.needle, c.why)
		}
	}
}

// --- V16.5.1: a generic message is returned on unexpected errors ---

// "Verify that a generic message is returned to the consumer when an unexpected
// or security-sensitive error occurs, ensuring no exposure of sensitive
// internal system data such as stack traces, queries, secret keys, and tokens."
//
// The failure this catches is a handler reaching for err.Error() on a 5xx path,
// which is how query text and file paths escape. The scan covers every
// WriteError call in the HTTP layer that answers a server-error status.
func TestASVS_V16_5_1_ServerErrorsCarryNoInternalDetail(t *testing.T) {
	inspected := 0
	for _, pf := range productionGoFiles(t) {
		if !strings.HasPrefix(pf.path, "internal/handler/") && !strings.HasPrefix(pf.path, "internal/adminapi/") {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 3 || callName(call) != "WriteError" {
				return true
			}
			if !isServerErrorStatus(call.Args[1]) {
				return true
			}
			inspected++
			switch msg := call.Args[2].(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				t.Errorf("V16.5.1: %s answers a server error with the variable %s; internal error text must not reach the client", pf.pos(call), msg.Name)
			case *ast.CallExpr:
				t.Errorf("V16.5.1: %s answers a server error with %s(...); only fixed message literals may be returned", pf.pos(call), callName(msg))
			default:
				t.Errorf("V16.5.1: %s answers a server error with a non-literal message", pf.pos(call))
			}
			return true
		})
	}

	if inspected == 0 {
		t.Fatal("V16.5.1: no server-error WriteError call was found in the HTTP layer; the scan is broken")
	}
	t.Logf("V16.5.1: %d server-error responses inspected, all carry fixed message literals", inspected)
}

func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

func isServerErrorStatus(e ast.Expr) bool {
	switch selectorName(e) {
	case "http.StatusInternalServerError", "http.StatusNotImplemented", "http.StatusBadGateway",
		"http.StatusServiceUnavailable", "http.StatusGatewayTimeout":
		return true
	}
	return false
}

// --- V16.5.3: the application fails gracefully and securely ---

// "Verify that the application fails gracefully and securely, including when an
// exception occurs, preventing fail-open conditions."
//
// A panic in a handler must not surface the stack to the caller. Both planes
// carry their own recovery middleware, and the admin copy is the one with the
// killswitch re-panic, so both are asserted.
func TestASVS_V16_5_3_PanicRecoveryReturnsAGenericResponse(t *testing.T) {
	for _, m := range []struct{ file, plane string }{
		{"internal/middleware/recovery.go", "the public API plane"},
		{"internal/adminapi/middleware.go", "the admin gateway plane"},
	} {
		src := readProductionSource(t, m.file)
		if !strings.Contains(src, "recover()") {
			t.Errorf("V16.5.3: %s has no recover(); a panic on %s would drop the connection mid-response", m.file, m.plane)
			continue
		}
		if !strings.Contains(src, "StatusInternalServerError") {
			t.Errorf("V16.5.3: %s recovers from panics but does not answer 500", m.file)
		}
		if strings.Contains(src, "debug.Stack()") && !strings.Contains(src, "log.Printf") {
			t.Errorf("V16.5.3: %s captures a stack trace with no log sink; confirm it is not written to the response", m.file)
		}
	}
}

// The audit logger drops buffered events under back-pressure rather than
// blocking the request path. That trade is only acceptable because critical
// events are exempt from the drop. If the exemption disappears, security
// records become losable under exactly the load an attacker can generate.
func TestASVS_V16_5_3_CriticalAuditEventsAreExemptFromBufferDrop(t *testing.T) {
	src := readProductionSource(t, "internal/audit/audit.go")
	if !strings.Contains(src, "audit buffer full") {
		t.Skip("V16.5.3: the buffered audit path has been restructured; re-derive this assertion")
	}
	if !strings.Contains(src, "isCriticalEvent") {
		t.Fatal("V16.5.3: the audit buffer drops events with no critical-event exemption; security records become losable under load")
	}
	if !strings.Contains(src, "DroppedTotal") {
		t.Error("V16.5.3: dropped audit events are no longer counted, so the loss would be silent")
	}
}
