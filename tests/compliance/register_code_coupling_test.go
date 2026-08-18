package compliance

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// Coupling gates: the register's status must match what the code does.
//
// Every gap this register has published came from the same shape — a sentence
// about the code that stopped being true and nothing noticed. A test that
// asserts only the code's current behaviour does not catch it: the code was
// never wrong, the document was.
//
// So these read both sides. Each one derives a fact from source and then
// asserts the register row that describes it carries the matching status. They
// fail in either direction: if the control lands, an Accepted Risk row that
// still says it is missing fails; if the control is removed, a Met row fails.
// Neither the fix nor the regression can land without the register moving in
// the same change.
// =============================================================================

// registerRowStatus returns the status of one row, and fails if the row is
// gone: a coupling gate that silently passes because its subject vanished is
// worse than no gate.
func registerRowStatus(t *testing.T, standard, requirementID string) (status, acceptedRisk string) {
	t.Helper()
	reg := loadRegister(t)
	for _, r := range reg.Requirements {
		if r.Standard == standard && r.RequirementID == requirementID {
			return r.Status, r.AcceptedRisk
		}
	}
	t.Fatalf("register row %s %s no longer exists; this gate has no subject", standard, requirementID)
	return "", ""
}

// --- ASVS V3.4.3 — the CSP minimum directives ---

// Verbatim, the requirement's operative clause: "As a minimum, a global policy
// must be used which includes the directives object-src 'none' and base-uri
// 'none'".
//
// default-src does not cover base-uri. A <base> injection re-points every
// relative URL in the document and is unaffected by default-src 'self', which
// is exactly why the requirement names it separately.
func TestASVS_V3_4_3_TheCSPMatchesWhatTheRegisterClaims(t *testing.T) {
	src := readCodeOnly(t, "internal/middleware/security_headers.go")

	// Both policies have to carry them: the API policy and the frontend policy
	// are chosen per request path, so a directive on one of the two is a
	// directive on some of the responses.
	policies := regexp.MustCompile(`(?m)^\s*(apiCSP|frontendCSP)\s*:?=\s*"([^"]*)"`).FindAllStringSubmatch(src, -1)
	if len(policies) != 2 {
		t.Fatalf("V3.4.3: expected two Content-Security-Policy strings in security_headers.go, found %d; "+
			"the gate cannot tell what is served", len(policies))
	}

	complete := true
	for _, p := range policies {
		name, policy := p[1], p[2]
		for _, directive := range []string{"object-src 'none'", "base-uri 'none'"} {
			if !strings.Contains(policy, directive) {
				t.Logf("V3.4.3: %s does not declare %s", name, directive)
				complete = false
			}
		}
	}

	status, ar := registerRowStatus(t, "OWASP ASVS", "V3.4.3")

	if complete && status != statusMet {
		t.Errorf("V3.4.3: both policies now declare object-src 'none' and base-uri 'none', but the "+
			"register still carries the row as %q (%s). The gap closed: move the row to Met, name "+
			"this test, and retire the accepted risk.", status, ar)
	}
	if !complete && status == statusMet {
		t.Error("V3.4.3: the register marks this Met, but at least one served policy is missing " +
			"object-src 'none' or base-uri 'none'. These are the two directives the requirement " +
			"names by number, and default-src covers neither.")
	}
	if !complete && status == statusNA {
		t.Error("V3.4.3: the register marks this Not Applicable. It applies: the server emits a " +
			"Content-Security-Policy on every response, and the requirement is about that header.")
	}
	if !complete {
		t.Logf("V3.4.3: carried as %s (%s) — matches the code", status, ar)
	}
}

// --- ASVS V3.5.3 — sensitive functionality must not use safe methods ---

// GET /auth/verify-email mutates state: it marks an address verified. The
// requirement allows either a non-safe method or strict Sec-Fetch-* validation,
// and vault42 does neither. What it has instead is a single-use token consumed
// atomically, which bounds the damage without satisfying the requirement.
func TestASVS_V3_5_3_StateChangingGETMatchesWhatTheRegisterClaims(t *testing.T) {
	routes := readCodeOnly(t, "internal/server/server.go")
	mutatingGET := strings.Contains(routes, `"GET /auth/verify-email"`)

	// The alternative the requirement offers.
	var secFetch bool
	for _, pf := range productionGoFiles(t) {
		if strings.Contains(readCodeOnly(t, pf.path), "Sec-Fetch-") {
			secFetch = true
			break
		}
	}

	status, ar := registerRowStatus(t, "OWASP ASVS", "V3.5.3")
	satisfied := !mutatingGET || secFetch

	switch {
	case satisfied && status != statusMet:
		t.Errorf("V3.5.3: either the state-changing GET is gone or Sec-Fetch-* validation has "+
			"landed, but the register still carries the row as %q (%s). Move it to Met.", status, ar)
	case !satisfied && status == statusMet:
		t.Error("V3.5.3: the register marks this Met, but GET /auth/verify-email still mutates " +
			"state and no Sec-Fetch-* validation exists anywhere in the tree.")
	case !satisfied && status == statusNA:
		t.Error("V3.5.3: the register marks this Not Applicable. It applies: a route the server " +
			"mounts under GET changes state.")
	default:
		t.Logf("V3.5.3: carried as %s (%s) — matches the code", status, ar)
	}
}

// --- ASVS V3.2.1 and V5.4.1 — Content-Disposition on the download paths ---

// V3.2.1 names "the attachment disposition type in the Content-Disposition
// header field" as one of its example controls; V5.4.1 requires the header
// outright. Neither blob download path sets it. Both rows point at the same
// one-line absence, so one gate covers both.
func TestASVS_V3_2_1_And_V5_4_1_ContentDispositionMatchesWhatTheRegisterClaims(t *testing.T) {
	src := readCodeOnly(t, "internal/handler/blob.go")
	present := strings.Contains(src, "Content-Disposition")

	for _, id := range []string{"V3.2.1", "V5.4.1"} {
		status, ar := registerRowStatus(t, "OWASP ASVS", id)
		switch {
		case present && status != statusMet:
			t.Errorf("%s: the blob download paths now set Content-Disposition, but the register "+
				"carries the row as %q (%s). Move it to Met and retire the accepted risk.", id, status, ar)
		case !present && status == statusMet:
			t.Errorf("%s: the register marks this Met, but no download path sets "+
				"Content-Disposition", id)
		case !present && status == statusNA:
			t.Errorf("%s: the register marks this Not Applicable. It applies: the server serves "+
				"stored bytes back to a browser over GET.", id)
		default:
			t.Logf("%s: carried as %s (%s) — matches the code", id, status, ar)
		}
	}
}

// --- NIST SP 800-63B-4 §3.1.1.2 — the password length floor ---

// The claim that failed hardest in the previous report was this one: three
// documents said vault42 "has enforced" a 15-character minimum since 0.4. It
// has not. 15 is the shipped *default*; the enforced floor, the number below
// which a non-dev deployment refuses to start, is a separate constant.
//
// A document that types a number the code owns will drift. This reads both
// numbers out of internal/config/config.go and asserts the documents state
// those numbers, so the prose cannot outlive the constant.
func TestNIST63B4_3_1_1_2_TheEnforcedPasswordFloorIsWhatTheDocsSay(t *testing.T) {
	src := readCodeOnly(t, "internal/config/config.go")

	floorMatch := regexp.MustCompile(`passwordMinLengthFloor\s*=\s*(\d+)`).FindStringSubmatch(src)
	if floorMatch == nil {
		t.Fatal("3.1.1.2: passwordMinLengthFloor is gone. It is the only value that bounds what a " +
			"deployment may set VAULT_PASSWORD_MIN_LENGTH to; without it the documented minimum " +
			"is advisory.")
	}
	floor, err := strconv.Atoi(floorMatch[1])
	if err != nil {
		t.Fatalf("3.1.1.2: passwordMinLengthFloor is not a number: %q", floorMatch[1])
	}

	defaultMatch := regexp.MustCompile(`envInt\("VAULT_PASSWORD_MIN_LENGTH",\s*(\d+)\)`).FindStringSubmatch(src)
	if defaultMatch == nil {
		t.Fatal("3.1.1.2: the VAULT_PASSWORD_MIN_LENGTH default is gone")
	}
	shipped, err := strconv.Atoi(defaultMatch[1])
	if err != nil {
		t.Fatalf("3.1.1.2: the VAULT_PASSWORD_MIN_LENGTH default is not a number: %q", defaultMatch[1])
	}

	if shipped < floor {
		t.Errorf("3.1.1.2: the shipped default (%d) is below the enforced floor (%d), so the "+
			"package default would be refused by its own validator", shipped, floor)
	}

	// The floor is only a floor outside dev. That exemption is deliberate and
	// documented, and it is part of what the docs have to say.
	if !strings.Contains(src, "c.Profile != ProfileDev && c.PasswordMinLength < passwordMinLengthFloor") {
		t.Error("3.1.1.2: the floor check no longer has the shape the register describes " +
			"(non-dev profiles only). If the dev exemption is gone that is an improvement, but " +
			"the register row says otherwise and must be updated.")
	}

	// Now the documents. Each has to state the enforced floor, not just the
	// default, because the difference between them is the whole finding.
	docs := map[string]string{
		"docs/COMPLIANCE.md": readProductionSource(t, "docs/COMPLIANCE.md"),
		"README.md":          readProductionSource(t, "README.md"),
	}
	for path, body := range docs {
		if !strings.Contains(body, strconv.Itoa(floor)) {
			t.Errorf("3.1.1.2: %s never states the enforced floor of %d characters. The previous "+
				"report said 15 was 'the minimum vault42 has enforced since 0.4' while the "+
				"enforced floor was 8, which is the exact overclaim this gate exists to stop.",
				path, floor)
		}
		if !strings.Contains(body, strconv.Itoa(shipped)) {
			t.Errorf("3.1.1.2: %s never states the shipped default of %d characters", path, shipped)
		}
	}

	// And the register row: its notes must carry both numbers too.
	reg := loadRegister(t)
	var found bool
	for _, r := range reg.Requirements {
		if r.Standard != "NIST SP 800-63B-4" || r.RequirementID != "3.1.1.2" {
			continue
		}
		found = true
		if !strings.Contains(r.Notes, strconv.Itoa(floor)) {
			t.Errorf("3.1.1.2: the register row does not state the enforced floor of %d", floor)
		}
		if floor >= 15 && r.Status != statusMet {
			t.Errorf("3.1.1.2: the enforced floor is now %d, which meets the Rev 4 single-factor "+
				"SHALL of 15. The row is %q: move it to Met.", floor, r.Status)
		}
		if floor < 15 && r.Status == statusMet {
			t.Errorf("3.1.1.2: the row is Met, but the enforced floor is %d and Rev 4 §3.1.1.2 "+
				"requires 15 for single-factor use. A production deployment may legally set "+
				"VAULT_PASSWORD_MIN_LENGTH=%d.", floor, floor)
		}
	}
	if !found {
		t.Fatal("3.1.1.2: the NIST SP 800-63B-4 3.1.1.2 row is gone from the register")
	}

	t.Logf("3.1.1.2: shipped default %d, enforced floor %d (dev exempt)", shipped, floor)
}

// --- ASVS V1.3.7 — template injection ---

// The old reason was "Templates are compiled from files in the binary. No
// template is built from input." The second sentence is false: compileOverride
// parses an admin-supplied subject line and HTML body with
// template.New(...).Parse(...), on the preview route and on every send that has
// a stored override.
//
// The requirement's second clause is therefore the operative one: "any
// untrusted input being included dynamically during template creation must be
// sanitized or strictly validated". Three things hold it. The source is
// validated before storage and before preview; the route needs a super_admin
// permission; and the package is html/template, whose contextual auto-escaping
// leaves no OS or reflection escape hatch, so the worst a holder of that
// permission achieves is structural, in an email body, which they could already
// rewrite wholesale.
func TestASVS_V1_3_7_AdminTemplateOverridesAreValidatedBeforeCompilation(t *testing.T) {
	mailer := readCodeOnly(t, "internal/email/mailer.go")
	if !strings.Contains(mailer, "template.New") || !strings.Contains(mailer, ".Parse(") {
		t.Fatal("V1.3.7: internal/email/mailer.go no longer compiles a template from a string. " +
			"If overrides are gone this requirement's applicability changed; update the register " +
			"row rather than deleting this test.")
	}

	// html/template, not text/template. This is the difference between a
	// structural injection and an unescaped one.
	for _, rel := range []string{"internal/email/mailer.go", "internal/email/templates.go"} {
		src := readProductionSource(t, rel)
		if !strings.Contains(src, `"html/template"`) {
			t.Errorf("V1.3.7: %s no longer imports html/template", rel)
		}
		if strings.Contains(src, `"text/template"`) {
			t.Errorf("V1.3.7: %s imports text/template, which does not escape by context. "+
				"Interpolated data becomes markup and the row's whole argument collapses.", rel)
		}
	}

	// Validated on both paths that reach compileOverride: storage and preview.
	if !strings.Contains(readCodeOnly(t, "internal/adminapi/email.go"), "email.ValidateTemplateContent(req.Subject, req.HTMLContent)") {
		t.Error("V1.3.7: the storage path no longer validates template content before writing it. " +
			"A stored override is compiled on every send, so an unvalidated one is compiled " +
			"forever rather than once.")
	}
	if !strings.Contains(readCodeOnly(t, "internal/email/preview.go"), "ValidateTemplateContent(subject, htmlContent)") {
		t.Error("V1.3.7: the preview path no longer validates template content before compiling it")
	}

	// And the route is gated by a permission the lower roles do not hold.
	router := readCodeOnly(t, "internal/adminapi/router.go")
	for _, route := range []string{
		`mux.Handle("PUT /admin/email-templates/{app}/{name}", withPerm(sessionAuth, rbac.EmailWrite`,
		`mux.Handle("POST /admin/email-templates/preview", withPerm(sessionAuth, rbac.EmailWrite`,
	} {
		if !strings.Contains(router, route) {
			t.Errorf("V1.3.7: the template route is no longer gated by rbac.EmailWrite: %s", route)
		}
	}
}
