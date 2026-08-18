package compliance

import (
	"context"
	"go/ast"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
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
		"user-1", "client-1", "203.0.113.7", "curl/8", "fp-hash", "device-1", metadata); err != nil {
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
// This pins the authentication half: vault42 logs every failed *authentication*
// attempt on the admin plane and logs the local-only killswitch trip. The
// authorization half — a failed RBAC decision — is pinned separately by
// TestASVS_V16_3_2_RBACDenialsAreAudited, so neither half can regress without a
// named test failing.
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

// The authorization half of V16.3.2, and the closure of what was CR-16. A failed
// RBAC decision on the admin plane must reach the append-only audit log, or a
// privilege-boundary probe leaves no trail. This drives a denied permission
// check through the real RBACCheck middleware and asserts the record the
// repository received: the event type, the admin it names, and the permission it
// was refused. When this passes the register row is Met, not an accepted risk.
func TestASVS_V16_3_2_RBACDenialsAreAudited(t *testing.T) {
	repo := &captureRepo{}
	logger := audit.NewLogger(repo, 0)

	// A viewer holds read verbs only, so config:write is denied.
	admin := &model.AdminUser{ID: "admin-1", Username: "viewer", Role: string(rbac.RoleViewer)}

	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	guarded := adminapi.RBACCheck(rbac.ConfigWrite, logger)(next)

	req := httptest.NewRequest(http.MethodPut, "/admin/config/some_key", nil)
	req = req.WithContext(adminapi.WithAdmin(req.Context(), admin))
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("V16.3.2: a denied RBAC check returned %d, want 403", rec.Code)
	}
	if reached {
		t.Fatal("V16.3.2: the guarded handler ran despite a permission denial")
	}

	entry := repo.last(t)
	if entry.EventType != audit.AdminAuthzDenied {
		t.Errorf("V16.3.2: denial wrote event %q, want %q", entry.EventType, audit.AdminAuthzDenied)
	}
	if entry.UserID != admin.ID {
		t.Errorf("V16.3.2: denial record names user %q, want %q", entry.UserID, admin.ID)
	}
	if got := entry.Metadata["permission"]; got != string(rbac.ConfigWrite) {
		t.Errorf("V16.3.2: denial record permission = %v, want %q", got, rbac.ConfigWrite)
	}
	if got := entry.Metadata["role"]; got != admin.Role {
		t.Errorf("V16.3.2: denial record role = %v, want %q", got, admin.Role)
	}
}

// The authentication half of V16.3.2 for the admin session gate. A rejected
// admin session token must reach the append-only audit log, or a session-token
// replay or a bogus-token probe leaves no trail while the RBAC denials and the
// killswitch trip beside it are all logged. This drives a bogus bearer token
// through the real SessionAuth middleware and asserts the record the repository
// received: the event type and the reason it names. The oversize token trips the
// token-validity check before any repository lookup, so no session or admin
// repository is needed.
func TestASVS_V16_3_2_AdminSessionRejectionsAreAudited(t *testing.T) {
	repo := &captureRepo{}
	logger := audit.NewLogger(repo, 0)

	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	guarded := adminapi.SessionAuth(nil, nil, logger)(next)

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 300))
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("V16.3.2: a rejected admin session returned %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("V16.3.2: the guarded handler ran despite a session rejection")
	}

	entry := repo.last(t)
	if entry.EventType != audit.AdminSessionRejected {
		t.Errorf("V16.3.2: rejection wrote event %q, want %q", entry.EventType, audit.AdminSessionRejected)
	}
	if got := entry.Metadata["reason"]; got != "invalid_token" {
		t.Errorf("V16.3.2: rejection record reason = %v, want %q", got, "invalid_token")
	}
}

// --- V16.4.1: log data is encoded to prevent log injection ---
//
// Both assertions in this section used to call the helper and stop there.
//
//	got := httputil.SafeLogValue(tc.input)   // no log line involved
//	got := httputil.ObfuscatedIP(tc.in)      // no log line involved
//
// A helper is not a control. The control is that no unencoded request value
// reaches a log call, and the helpers had 27 and 11 production call sites with
// no test between them observing one. Both tests would have passed with every
// call site stripped, which is the pinned-the-helper-never-a-call-site defect
// this repository already found once, recurring in the section it was found in.
//
// So the helpers are still pinned — a broken encoder is a real regression — but
// the pinning now happens inside a scan of the call sites, and the scan is what
// fails when a value goes to a log raw.

// logCalls are the calls that write a line to the process log. The vault, the
// bridge and the admin gateway all use the standard logger, so this is the whole
// surface; a new logging package would have to be added here, which is the point.
var logCalls = map[string]struct{}{
	"Printf": {}, "Print": {}, "Println": {},
	"Fatalf": {}, "Fatal": {}, "Fatalln": {},
	"Panicf": {}, "Panic": {}, "Panicln": {},
}

// isLogCall reports whether call writes a line to the process log.
//
// Fprintf and Fprintln count only when the destination is os.Stderr or
// os.Stdout — the shape a CLI subcommand uses instead of the logger. The same
// call writing into an http.ResponseWriter is answering a request, which is a
// different surface with a different control.
func isLogCall(call *ast.CallExpr) bool {
	name := callName(call)
	if _, direct := logCalls[name]; direct {
		return true
	}
	if name != "Fprintf" && name != "Fprintln" && name != "Fprint" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	switch selectorName(call.Args[0]) {
	case "os.Stderr", "os.Stdout":
		return true
	}
	return false
}

// logSanitisers are the two encoders. A value wrapped in either has been through
// the control; ObfuscatedIP additionally drops the host part of an address, so
// it satisfies the injection requirement as well.
var logSanitisers = map[string]struct{}{
	"SafeLogValue": {}, "ObfuscatedIP": {}, "obfuscatedIP": {}, "safeLogValue": {},
}

// requestDerived are the reads that return a value the caller of the HTTP
// request chose. Each is matched on the selector, not on the receiver name, so
// renaming r to req does not hide one.
//
// Method is not in the set: net/http rejects a request line whose method is not
// an RFC 9110 token before a handler ever runs, so there is no byte in it an
// encoder would change.
var requestDerived = map[string]string{
	"RemoteAddr": "the peer address, which is also the value ObfuscatedIP exists to mask",
	"RequestURI": "the raw request line",
	"UserAgent":  "a header the client writes",
	"Referer":    "a header the client writes",
}

// urlFields are the parts of a parsed request URL a client controls. They are
// matched only through a URL selector — r.URL.Path, not any field called Path —
// because "Path" on its own is the name of half the file handling in the tree
// and the gate has to survive being right.
var urlFields = map[string]string{
	"Path":     "the request path",
	"RawPath":  "the request path",
	"RawQuery": "the query string",
	"Fragment": "the URL fragment",
	"Host":     "the request host",
	"Opaque":   "the opaque part of the URL",
}

// urlFieldRead reports the request-URL field a selector reads, or "".
func urlFieldRead(sel *ast.SelectorExpr) string {
	why, isField := urlFields[sel.Sel.Name]
	if !isField {
		return ""
	}
	switch base := sel.X.(type) {
	case *ast.SelectorExpr:
		if base.Sel.Name == "URL" {
			return why
		}
	case *ast.Ident:
		if base.Name == "URL" || base.Name == "u" || base.Name == "url" {
			return why
		}
	}
	return ""
}

// requestHeaderRead is the shape r.Header.Get("X") takes: a Get whose receiver
// is itself a Header selector. Anything a client can set arrives this way.
func requestHeaderRead(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && (inner.Sel.Name == "Header" || inner.Sel.Name == "Trailer")
}

// rawRequestValue reports the request-derived read at n, or "" when n is not one.
func rawRequestValue(n ast.Node) string {
	switch node := n.(type) {
	case *ast.CallExpr:
		if requestHeaderRead(node) {
			return "a request header"
		}
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			if why, hit := requestDerived[sel.Sel.Name]; hit {
				return why
			}
		}
	case *ast.SelectorExpr:
		// A selector that is the Fun of a call is reported by the call case, so
		// only value reads reach here: r.RemoteAddr, r.URL.Path.
		if why, hit := requestDerived[node.Sel.Name]; hit {
			return why
		}
		if why := urlFieldRead(node); why != "" {
			return why
		}
	}
	return ""
}

// unsanitisedRequestReads walks a log argument and returns the request-derived
// reads that are not inside a call to an encoder.
//
// Nesting is what makes this structural rather than textual: the argument
// httputil.SafeLogValue(r.UserAgent()) contains a request read and is clean,
// while fmt.Sprintf("%s", r.UserAgent()) contains the same read and is not.
func unsanitisedRequestReads(arg ast.Expr) []string {
	var found []string
	var walk func(n ast.Node, sanitized bool)
	walk = func(n ast.Node, sanitized bool) {
		if n == nil {
			return
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if _, clean := logSanitisers[callName(call)]; clean {
				sanitized = true
			}
		}
		if !sanitized {
			if why := rawRequestValue(n); why != "" {
				found = append(found, why)
			}
		}
		for _, child := range astChildren(n) {
			walk(child, sanitized)
		}
	}
	walk(arg, false)
	return found
}

// astChildren returns a node's child expressions. ast.Inspect cannot be used
// here because the sanitized flag has to travel down one branch only.
func astChildren(n ast.Node) []ast.Node {
	var out []ast.Node
	ast.Inspect(n, func(c ast.Node) bool {
		if c == nil || c == n {
			return c == n
		}
		out = append(out, c)
		return false
	})
	return out
}

// TestASVS_V16_4_1_LogValuesCannotForgeNewRecords asserts the encoder at the
// call sites, not on its own.
//
// "Verify that all logging components appropriately encode data to prevent log
// injection."
//
// The attack is a newline or carriage return in an attacker-controlled field
// that forges a second log line. Encoding it is only a control if the encoder
// is on the path: the scan below fails when a production log call reads a value
// off the request and passes it through without one.
func TestASVS_V16_4_1_LogValuesCannotForgeNewRecords(t *testing.T) {
	// The encoder still has to work. This is the premise of the scan, not a
	// substitute for it, which is why it is a Fatal: a broken encoder makes
	// every call site below meaningless.
	for _, tc := range []struct{ name, input string }{
		{"newline", "user\nADMIN LOGIN SUCCEEDED"},
		{"carriage return", "user\rADMIN LOGIN SUCCEEDED"},
		{"crlf", "user\r\nADMIN LOGIN SUCCEEDED"},
		{"null byte", "user\x00truncated"},
		{"tab", "user\tfield-split"},
		{"line separator", "user\u2028ADMIN LOGIN SUCCEEDED"},
		{"escape", "user\x1b[2J"},
	} {
		got := httputil.SafeLogValue(tc.input)
		for _, forbidden := range []string{"\n", "\r", "\x00", "\t", "\u2028", "\x1b"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("V16.4.1: %s: SafeLogValue returned %q, which still carries a "+
					"record-forging control character", tc.name, got)
			}
		}
	}

	var sites int
	for _, pf := range productionGoFiles(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isLogCall(call) {
				return true
			}
			for _, arg := range call.Args {
				sites++
				for _, why := range unsanitisedRequestReads(arg) {
					t.Errorf("V16.4.1: %s writes a log line carrying %s with no encoder on it. "+
						"A CR, an LF or a U+2028 in that value forges a second record, and an "+
						"ESC drives the terminal of whoever tails the log. Wrap it in "+
						"httputil.SafeLogValue, or in httputil.ObfuscatedIP if it is an address.",
						pf.pos(call), why)
				}
			}
			return true
		})
	}

	if sites < 100 {
		t.Fatalf("V16.4.1: only %d log-call arguments were inspected across the production tree; "+
			"the scan has stopped seeing what it guards, and would report the same ok whether "+
			"every call site were encoded or none were", sites)
	}
	t.Logf("V16.4.1: %d log-call arguments inspected for unencoded request values", sites)
}

// TestASVS_V16_4_1_LoggedAddressesArePseudonymised asserts the masking at the
// call sites, not on its own.
//
// Source addresses are pseudonymised before they reach a log line. This is both
// a log-hygiene control and the GDPR Art. 5(1)(c) minimisation position, so what
// is asserted is the "before they reach a log line" half: no log call in the
// production tree may pass a whole peer address.
//
// docs/PRIVACY.md inventories the full address in exactly two stores, the audit
// record and the device record, each with a retention period. The operational
// log is not one of them, so a full address written there is processing the
// document does not describe.
func TestASVS_V16_4_1_LoggedAddressesArePseudonymised(t *testing.T) {
	// The mask still has to work, for the same reason as above.
	for _, tc := range []struct{ in, want string }{
		{"192.168.1.42", "192.168.1.0"},
		{"203.0.113.201", "203.0.113.0"},
		{"203.0.113.201:44321", "203.0.113.0"},
		{"not-an-ip", "invalid_ip"},
	} {
		if got := httputil.ObfuscatedIP(tc.in); got != tc.want {
			t.Fatalf("V16.4.1: ObfuscatedIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	files := productionGoFiles(t)
	identNames := addressIdentNames(files)
	if len(identNames) == 0 {
		t.Fatal("V16.4.1: no variable in the production tree is passed to a mask, so this scan " +
			"knows no address-shaped names and would pass over every raw one")
	}

	var sites int
	stillNeeded := map[string]struct{}{}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isLogCall(call) {
				return true
			}
			for _, arg := range call.Args {
				for _, addr := range unmaskedAddressReads(arg, identNames) {
					sites++
					key := pf.path + ":" + enclosingFunc(pf, call)
					if _, exempt := fullAddressByDesign[key]; exempt {
						stillNeeded[key] = struct{}{}
						continue
					}
					t.Errorf("V16.4.1: %s writes a log line carrying %s, a whole client address. "+
						"docs/PRIVACY.md inventories the full address in the audit store and the "+
						"device record only; the operational log is not one of its stores, and a "+
						"reader tailing it needs the network, not the host. Wrap it in "+
						"httputil.ObfuscatedIP, or add %q to fullAddressByDesign with the reason "+
						"this channel is the one that needs the host.", pf.pos(call), addr, key)
				}
			}
			return true
		})
	}

	// The ratchet. An exemption for a line that no longer logs an address is a
	// standing permission nobody has to justify again, and the next line added
	// to the same function would inherit it.
	for key, reason := range fullAddressByDesign {
		if reason == "" {
			t.Errorf("fullAddressByDesign[%q] carries no reason; an exemption without one is "+
				"indistinguishable from an oversight", key)
		}
		if _, needed := stillNeeded[key]; !needed {
			t.Errorf("fullAddressByDesign names %q, which no longer logs a whole client address. "+
				"Delete the entry: the list may only shrink.", key)
		}
	}
	t.Logf("V16.4.1: %d whole-address log arguments found, %d covered by a written exemption",
		sites, len(stillNeeded))
}

// fullAddressByDesign are the log lines that deliberately keep the whole client
// address, with the reason each is the channel that needs it.
//
// Keyed by file and enclosing function, never by line: an absolute line number
// goes stale on a correct refactor, which makes a gate that fails on the fix and
// passes on the defect. Adding an entry is a privacy decision — the question to
// answer is which store in docs/PRIVACY.md §3 the value now lives in, and for
// how long.
var fullAddressByDesign = map[string]string{
	"internal/honeypot/honeypot.go:LoggingMiddleware": "the honeypot log is the threat-analysis " +
		"channel itself, not an operational log with an audit store behind it: nothing else " +
		"records who probed the decoy vault, so masking to a /24 would delete the finding rather " +
		"than relocate it. The subjects are unauthenticated callers who reached a workload that " +
		"serves nobody legitimately, and the profile is off unless an operator turns it on",
}

// enclosingFunc names the function declaration a node sits inside, so an
// exemption can be keyed on something a refactor moves with the code.
func enclosingFunc(pf parsedFile, n ast.Node) string {
	pos := pf.fset.Position(n.Pos()).Line
	for _, decl := range pf.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if pos >= pf.fset.Position(fn.Pos()).Line && pos <= pf.fset.Position(fn.End()).Line {
			return fn.Name.Name
		}
	}
	return "(file scope)"
}

// addressReads are the expressions that resolve a whole client address.
var addressReads = map[string]struct{}{
	"RemoteAddr": {}, "ClientIP": {}, "ClientIPFromContext": {},
}

// maskers are the two implementations of the /24 mask. cmd/bridge carries its
// own because it is stdlib-only and cannot import internal/httputil.
var maskers = map[string]struct{}{"ObfuscatedIP": {}, "obfuscatedIP": {}}

// addressIdentNames returns the variable names this codebase itself treats as
// client addresses: every bare identifier that is passed to a masker anywhere in
// the production tree.
//
// This is deliberately derived rather than written down. A hand-kept list of
// address-shaped names is a guess, and it guesses wrong in both directions — it
// would have to include "ip" while excluding "addr", which is a listen address
// in internal/server. Taking the names from the call sites means the codebase
// says which variables hold an address, and the gate believes it: strip the mask
// from one of them and the name is still known from the others.
func addressIdentNames(files []parsedFile) map[string]struct{} {
	out := map[string]struct{}{}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, isMask := maskers[callName(call)]; !isMask {
				return true
			}
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok {
					out[id.Name] = struct{}{}
				}
			}
			return true
		})
	}
	return out
}

// unmaskedAddressReads walks a log argument and returns the address reads that
// are not inside a masking call.
func unmaskedAddressReads(arg ast.Expr, identNames map[string]struct{}) []string {
	var found []string
	var walk func(n ast.Node, masked bool)
	walk = func(n ast.Node, masked bool) {
		if n == nil {
			return
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if _, isMask := maskers[callName(call)]; isMask {
				masked = true
			}
		}
		if !masked {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if _, hit := addressReads[node.Sel.Name]; hit {
					found = append(found, node.Sel.Name)
				}
			case *ast.CallExpr:
				if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
					if _, hit := addressReads[sel.Sel.Name]; hit {
						found = append(found, sel.Sel.Name+"()")
					}
				}
				if id, ok := node.Fun.(*ast.Ident); ok {
					if _, hit := addressReads[id.Name]; hit {
						found = append(found, id.Name+"()")
					}
				}
			case *ast.Ident:
				if _, hit := identNames[node.Name]; hit {
					found = append(found, "the variable "+node.Name)
				}
			}
		}
		for _, child := range astChildren(n) {
			walk(child, masked)
		}
	}
	walk(arg, false)
	return found
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
		// The two assertions below are the control. A skip on a moved needle
		// retires them at the exact moment the audit buffer was restructured,
		// which is when they are most worth running.
		t.Fatalf("V16.5.3: internal/audit/audit.go no longer contains the buffer-full drop path " +
			"this requirement is evidenced against, so the critical-event exemption and the drop " +
			"counter below would go unasserted. Re-derive both against the restructured path.")
	}
	if !strings.Contains(src, "isCriticalEvent") {
		t.Fatal("V16.5.3: the audit buffer drops events with no critical-event exemption; security records become losable under load")
	}
	if !strings.Contains(src, "DroppedTotal") {
		t.Error("V16.5.3: dropped audit events are no longer counted, so the loss would be silent")
	}
}
