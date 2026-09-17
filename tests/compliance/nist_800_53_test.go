package compliance

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/rbac"
)

// =============================================================================
// NIST SP 800-53 Rev 5, Release 5.2.0 (2025-08-27)
// "Security and Privacy Controls for Information Systems and Organizations"
// https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
//
// Control titles below are quoted from the OSCAL catalog published at
// github.com/usnistgov/oscal-content (NIST_SP-800-53_rev5_catalog.json,
// metadata version 5.2.0).
//
// Until this file, docs/COMPLIANCE.md claimed 23 SP 800-53 requirements and a
// grep for any control identifier across tests/ and internal/ returned zero
// hits. An entire standard was claimed with no requirement-level traceability
// of any kind, which made "name the test for AU-2" an unanswerable question.
// Test names carry the control identifier so that question now has an answer.
// =============================================================================

// --- AC-3 "Access Enforcement" ---

// Enforcement means the decision function refuses by default. A permission
// vocabulary that answers "yes" for an unknown role is not an access control.
func TestNIST80053_AC_3_AccessEnforcementDeniesUnknownPrincipals(t *testing.T) {
	everything := rbac.PermissionsForRole(rbac.RoleSuperAdmin)
	if len(everything) == 0 {
		t.Fatal("AC-3: the permission vocabulary is empty; the role model did not load")
	}
	for _, role := range []rbac.Role{"", "admin", "root", "*", "SUPER_ADMIN"} {
		for _, p := range everything {
			if rbac.HasPermission(role, p) {
				t.Errorf("AC-3: unrecognized role %q was granted %q", role, p)
			}
		}
	}
}

// --- AC-6 "Least Privilege" ---

func TestNIST80053_AC_6_LeastPrivilegeHoldsAcrossTheRoleLattice(t *testing.T) {
	viewer := rbac.PermissionsForRole(rbac.RoleViewer)
	if len(viewer) == 0 {
		t.Fatal("AC-6: the read-only role resolved to no permissions; the role model did not load")
	}
	for _, p := range viewer {
		verb := string(p)
		if i := strings.LastIndex(verb, ":"); i >= 0 {
			verb = verb[i+1:]
		}
		if verb != "read" && verb != "list" {
			t.Errorf("AC-6: the read-only role holds %q, which changes state", p)
		}
	}
}

// --- AC-7 "Unsuccessful Logon Attempts" ---

// AC-7 requires a limit on consecutive invalid logon attempts and an action
// taken when the limit is exceeded.
//
// This gate used to be three substring searches: "lockoutThreshold" and
// "FailedLoginCount" somewhere in internal/service/auth.go, and
// "CheckAccountLockout" somewhere in internal/middleware/ratelimit.go. The third
// was the instructive one. CheckAccountLockout was a helper with no callers in
// the binary; the string was present, the gate was green, and the function it
// named had nothing to do with whether a failed logon was bounded. Rename a
// constant in a correct refactor and the gate goes red for no reason; delete the
// enforcement and leave the names behind and it stays green. That teaches people
// to edit the gate rather than the code, which is how the repository acquired
// three tripwires that could never trip.
//
// So AC-7 is now measured, not grepped. Every number below is discovered by
// attempting logins against a real AuthService until the answer changes.
func TestNIST80053_AC_7_UnsuccessfulLogonAttemptsAreBounded(t *testing.T) {
	// "A limit on consecutive invalid attempts." Measured on the login path
	// three times, because there are three limits and only together do they
	// bound an attacker: one address against one account, one account across
	// every address, and one address across every account.
	perSource := perSourceAttemptLimit(t, perSourceSearchCeiling)
	account := accountWideAttemptLimit(t, nistConsecutiveFailureCeiling)
	address := sourceAddressAttemptLimit(t, 2*nistConsecutiveFailureCeiling)
	for _, m := range []struct {
		name string
		n    int
	}{
		{"per (account, source address)", perSource},
		{"per account across all addresses", account},
		{"per source address across all accounts", address},
	} {
		if m.n < 1 {
			t.Fatalf("AC-7: the limit %s measured %d; a limit below one is not a control, it is an outage",
				m.name, m.n)
		}
	}
	if account > nistConsecutiveFailureCeiling {
		t.Errorf("AC-7: an account absorbs %d consecutive failures from rotating addresses before it "+
			"locks, over the %d that NIST SP 800-63B 5.2.2 allows a throttling verifier",
			account, nistConsecutiveFailureCeiling)
	}
	// The third limit bounds the attacker who never lets any one account reach
	// its own limit — the spray. Without it the other two are a budget per
	// account, multiplied by every address the attacker can guess.
	if address <= perSource {
		t.Errorf("AC-7: one address may fail %d logins across all accounts but %d against a single "+
			"account. A per-address limit at or below the per-account one leaves password spraying "+
			"bounded only by how many accounts the attacker knows about.", address, perSource)
	}
	t.Logf("AC-7 measured limits: %d failures per (account, source address), %d per account across "+
		"all addresses, %d per address across all accounts", perSource, account, address)

	// "An action taken when the limit is exceeded." The action is that the
	// correct password stops working, which is what the two measurements above
	// each observed to terminate; assert it explicitly so the action cannot be
	// reduced to a log line.
	const (
		email      = "ac7-target@example.com"
		attackerIP = "198.51.100.7"
	)
	f := newLockoutFixture(t)
	f.account(email)
	for i := 0; i < perSource; i++ {
		f.fail(email, attackerIP)
	}
	if f.probe(t, email, attackerIP) == loginAccepted {
		t.Errorf("AC-7: after %d consecutive invalid attempts the correct password was still accepted "+
			"from %s; the limit is counted but nothing acts on it", perSource, attackerIP)
	}

	// The counter lives in the cache, so a cache outage would otherwise lift the
	// limit entirely. The durable failed_login_count column is what keeps AC-7
	// enforced when the fast path cannot answer — asserted here by breaking the
	// cache and driving the same attack, rather than by finding the column's
	// name in the file.
	down := newLockoutFixtureWithCache(t, unreadableCache{cache.NewMemoryCache()})
	down.account(email)
	if down.probe(t, email, attackerIP) != loginAccepted {
		t.Fatalf("AC-7: an untouched account could not log in with the cache unavailable; the fallback " +
			"is failing closed on every login, not enforcing a limit")
	}
	for i := 0; i < perSource; i++ {
		down.fail(email, attackerIP)
	}
	if down.probe(t, email, attackerIP) == loginAccepted {
		t.Errorf("AC-7: with the lockout cache unreadable, %d consecutive invalid attempts left the "+
			"account open. A cache outage would remove the attempt limit, and a cache outage is when "+
			"an attacker would most like it removed.", perSource)
	}
}

// --- AC-12 "Session Termination" ---

// The control requires termination on a defined trigger. Explicit termination
// is implemented and asserted here.
//
// The other half of AC-12, an inactivity trigger, does not exist: no
// last-activity timestamp is recorded on a refresh-token family and no auth
// decision consults one. That is carried in the register as an accepted risk
// rather than asserted away. This test pins the half that holds so the accepted
// risk cannot widen to cover explicit revocation as well.
func TestNIST80053_AC_12_ExplicitTerminationRevokesEveryFamily(t *testing.T) {
	src := readProductionSource(t, "internal/repository/postgres/refresh_token.go")
	for _, fn := range []string{"RevokeAllForUser", "RevokeFamily"} {
		if !strings.Contains(src, fn) {
			t.Errorf("AC-12: %s is gone from the refresh-token repository; termination would not reach existing sessions", fn)
		}
	}

	// Every state change that invalidates the credential a session rests on
	// must revoke globally, not just end the current request's session.
	for _, site := range []struct{ file, why string }{
		{"internal/handler/password.go", "a completed password reset"},
		{"internal/handler/webauthn.go", "a WebAuthn credential change"},
		{"internal/handler/user.go", "a user-initiated revoke-all"},
	} {
		if !strings.Contains(readProductionSource(t, site.file), "RevokeAll") {
			t.Errorf("AC-12: %s no longer revokes all sessions on %s", site.file, site.why)
		}
	}
}

// --- AU-2 "Event Logging" / AU-3 "Content of Audit Records" ---

// AU-3 enumerates what a record must establish: what happened, when, where,
// the source, and the identity associated with the outcome. The audit entry
// shape is asserted through the real logger in asvs_logging_test.go; here the
// control identifier is bound to that evidence and the event catalog is
// checked for the categories AU-2 requires an organization to select.
func TestNIST80053_AU_2_TheEventCatalogueCoversTheSelectedCategories(t *testing.T) {
	src := readProductionSource(t, "internal/audit/audit.go")
	categories := map[string]string{
		"LoginSuccess":   "successful logon",
		"LoginFailure":   "unsuccessful logon",
		"PasswordChange": "credential change",
		"PasswordReset":  "credential reset",
		"TokenRevoke":    "credential revocation",
		"AdminAction":    "privileged function execution",
		"AccountErased":  "account lifecycle",
		"DataExport":     "information export",
		"KMSUnwrap":      "key release",
	}
	for constant, category := range categories {
		if !strings.Contains(src, constant+" =") {
			t.Errorf("AU-2: no audit event constant for the %s category (%s)", category, constant)
		}
	}
}

// --- AU-9 "Protection of Audit Information" ---

// The control requires audit information to be protected from unauthorized
// modification and deletion. vault42 enforces this in the database rather than
// in the application, which is the stronger placement: it survives a
// compromised application process.
//
// What is not implemented is cryptographic chaining, which would additionally
// resist an adversary holding database write access. That is carried in the
// register as an accepted risk with a stated threat model.
func TestNIST80053_AU_9_ModificationIsRevokedAtTheDatabase(t *testing.T) {
	schema := readProductionSource(t, "migrations/001_initial_schema.sql")
	if !strings.Contains(schema, "REVOKE UPDATE, DELETE ON audit.audit_log FROM vault_app") {
		t.Error("AU-9: the application role can once again UPDATE or DELETE audit records")
	}
	if !strings.Contains(schema, "audit_log_no_update") || !strings.Contains(schema, "audit_log_no_delete") {
		t.Error("AU-9: the append-only triggers are gone")
	}

	// A privileged role that can read every audit row is its own exposure, so
	// the later migration that narrows vault_admin must still be present.
	if !strings.Contains(readProductionSource(t, "migrations/002_revoke_vault_app_admin_select.sql"), "REVOKE") {
		t.Error("AU-9: migration 002 no longer narrows the audit read surface")
	}
}

// --- AU-11 "Audit Record Retention" ---

// Retention is an operator decision, and the control is satisfied by the
// mechanism plus the documented default, not by a particular horizon. The
// default is off, because silently deleting security logs is not a safe
// default; that choice is what this pins.
func TestNIST80053_AU_11_RetentionIsMechanisedAndOffByDefault(t *testing.T) {
	src := readProductionSource(t, "internal/audit/retention.go")
	if !strings.Contains(src, "func (r *Retention) Sweep") {
		t.Error("AU-11: the retention sweeper is gone")
	}
	if !strings.Contains(src, "SweepInterval") {
		t.Error("AU-11: the sweep interval constant is gone")
	}

	cfg := readProductionSource(t, "internal/config/config.go")
	if !strings.Contains(cfg, `envInt("VAULT_AUDIT_RETENTION_DAYS", 0)`) {
		t.Error("AU-11: the audit retention horizon no longer defaults to 0 (disabled); deleting security logs must stay an explicit operator choice")
	}
}

// --- IA-2 "Identification and Authentication (Organizational Users)" ---
// --- IA-5 "Authenticator Management" ---

// IA-5 requires authenticator content to be protected. Every stored
// authenticator must therefore be a hash or a ciphertext, never the value
// presented at authentication time.
func TestNIST80053_IA_5_StoredAuthenticatorsAreNeverPlaintext(t *testing.T) {
	schema := readProductionSource(t, "migrations/001_initial_schema.sql")

	for _, column := range []string{"password_hash", "token_hash"} {
		if !strings.Contains(schema, column) {
			t.Errorf("IA-5: column %s is gone from the initial schema", column)
		}
	}
	// A column literally named for the secret it holds is the regression this
	// guards against.
	for _, forbidden := range []string{"password TEXT", "password VARCHAR", "refresh_token TEXT"} {
		if strings.Contains(schema, forbidden) {
			t.Errorf("IA-5: the schema declares %q, which would store an authenticator in the clear", forbidden)
		}
	}

	// The TOTP seed is a shared secret and cannot be hashed, so it must be
	// encrypted at rest instead.
	if !strings.Contains(readProductionSource(t, "internal/handler/totp.go"), "Encrypt(") {
		t.Error("IA-5: the TOTP seed is no longer encrypted before storage")
	}
}

// --- IA-6 "Authentication Feedback" ---

// The control requires authentication feedback to be obscured. In an API that
// means the failure response must not reveal which factor failed or whether the
// account exists. The generic-credentials sentinel is the mechanism.
func TestNIST80053_IA_6_AuthenticationFailureFeedbackIsGeneric(t *testing.T) {
	src := readProductionSource(t, "internal/service/auth.go")
	if !strings.Contains(src, "ErrInvalidCredentials") {
		t.Fatal("IA-6: the generic credential-failure sentinel is gone")
	}
	// A dummy hash on the not-found path is what keeps the timing of a missing
	// account indistinguishable from a wrong password.
	if !strings.Contains(src, "dummy") && !strings.Contains(src, "Dummy") {
		t.Error("IA-6: the dummy-hash path is gone; a missing account would be distinguishable by response time")
	}
}

// --- IA-11 "Re-authentication" ---

// The control requires re-authentication when a defined circumstance occurs.
// vault42 re-authenticates before changes to authentication-affecting
// attributes, via a recent password confirmation.
func TestNIST80053_IA_11_SensitiveChangesRequireRecentConfirmation(t *testing.T) {
	routes := serverRoutes(t)
	needConfirmation := []string{
		"POST /auth/2fa/totp/setup",
		"DELETE /auth/2fa/totp",
		"POST /auth/2fa/backup-codes",
	}
	for _, route := range needConfirmation {
		wiring, ok := routes[route]
		if !ok {
			t.Errorf("IA-11: route %q is no longer registered; re-derive this assertion", route)
			continue
		}
		// confirmedWrite is confirmed plus the erased-account guard; it composes
		// the same confirmMw, so it satisfies IA-11 exactly as confirmed does.
		// Matching only "confirmed(" would not match it, because the name
		// continues into "Write".
		if !strings.Contains(wiring, "confirmed(") && !strings.Contains(wiring, "confirmedWrite(") {
			t.Errorf("IA-11: %s changes an authentication factor without requiring recent re-authentication; it is wired as %s", route, wiring)
		}
	}
}

// --- SC-8 "Transmission Confidentiality and Integrity" ---

// Bound to the structural TLS assertions in asvs_communication_test.go, which
// cover every tls.Config in the tree rather than the one this process opens.
func TestNIST80053_SC_8_TransmissionProtectionCoversEveryConfiguredEndpoint(t *testing.T) {
	configs := compositeLiteralsOfType(productionGoFiles(t), "tls.Config")
	if len(configs) < 3 {
		t.Fatalf("SC-8: only %d tls.Config literals found; the API listener, the admin gateway and the cache client each need one", len(configs))
	}
	for _, c := range configs {
		value, ok := litField(c.Lit, "MinVersion")
		if !ok {
			t.Errorf("SC-8: %s configures TLS with no minimum version", c.pos(c.Lit))
			continue
		}
		if tlsVersionRank[selectorName(value)] < tlsVersionRank["tls.VersionTLS12"] {
			t.Errorf("SC-8: %s permits a TLS version below 1.2", c.pos(c.Lit))
		}
	}
}

// --- SC-13 "Cryptographic Protection" ---

// The control requires the cryptography in use to be identified and to be a
// type the organization has approved. The approved set is asserted by name so
// that a substitution has to be a deliberate edit to this list.
func TestNIST80053_SC_13_OnlyApprovedPrimitivesAreConfigured(t *testing.T) {
	aes := readProductionSource(t, "internal/crypto/aes.go")
	if !strings.Contains(aes, "cipher.NewGCM") {
		t.Error("SC-13: AES-GCM is no longer the authenticated-encryption mode")
	}
	if strings.Contains(aes, "NewCBCEncrypter") || strings.Contains(aes, "NewECB") {
		t.Error("SC-13: an unauthenticated block mode has appeared in the encryption helper")
	}

	jwt := readProductionSource(t, "internal/crypto/jwt.go")
	if !strings.Contains(jwt, `AllowedAlgorithm = "RS256"`) {
		t.Error("SC-13: the JWT signing algorithm is no longer pinned to RS256")
	}

	if !strings.Contains(readProductionSource(t, "internal/crypto/argon2.go"), "argon2.IDKey") {
		t.Error("SC-13: Argon2id is no longer the password key-derivation function")
	}
}

// --- SC-28 "Protection of Information at Rest" ---

func TestNIST80053_SC_28_IdentityDataIsEncryptedAtRest(t *testing.T) {
	src := readProductionSource(t, "internal/service/identity.go")
	if !strings.Contains(src, "vaultcrypto.Encrypt(") {
		t.Fatal("SC-28: identity data is no longer encrypted before storage")
	}
	// The ciphertext is bound to its owner through the additional authenticated
	// data, so a row moved between users fails to decrypt rather than
	// decrypting into the wrong account.
	if !strings.Contains(src, "[]byte(pseudo)") {
		t.Error("SC-28: identity ciphertext is no longer bound to the owner pseudonym as additional authenticated data")
	}

	// The private signing keys are the highest-value data at rest.
	if !strings.Contains(readProductionSource(t, "internal/keystore/keystore.go"), "vaultcrypto.Encrypt(privPEM") {
		t.Error("SC-28: signing keys are no longer encrypted at rest under the master key")
	}
}

// --- SI-10 "Information Input Validation" ---

func TestNIST80053_SI_10_InputIsValidatedBeforeUse(t *testing.T) {
	src := readProductionSource(t, "internal/sanitize/sanitize.go")
	for _, fn := range []string{"func String(", "func Locale(", "func RedirectPath(", "func AvatarURL(", "func Email("} {
		if !strings.Contains(src, fn) {
			t.Errorf("SI-10: internal/sanitize no longer exports %s", strings.TrimSuffix(strings.TrimPrefix(fn, "func "), "("))
		}
	}

	// Unbounded request bodies are an input-validation failure with a
	// denial-of-service outcome, so the cap is asserted with its exemption list.
	server := readProductionSource(t, "internal/server/server.go")
	if !strings.Contains(server, "MaxBodyWithExemptions(") {
		t.Error("SI-10: the request body cap is no longer installed")
	}
}

// --- SI-11 "Error Handling" ---

// Bound to TestASVS_V16_5_1_ServerErrorsCarryNoInternalDetail, which scans
// every server-error response in the HTTP layer.
func TestNIST80053_SI_11_ErrorsRevealNoInternalState(t *testing.T) {
	if !strings.Contains(readProductionSource(t, "internal/httputil/response.go"), "func WriteError(") {
		t.Fatal("SI-11: the central error writer is gone; error shape would no longer be centrally controlled")
	}
	for _, plane := range []string{"internal/middleware/recovery.go", "internal/adminapi/middleware.go"} {
		if !strings.Contains(readProductionSource(t, plane), "recover()") {
			t.Errorf("SI-11: %s no longer recovers from panics", plane)
		}
	}
}
