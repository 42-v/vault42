package compliance

import (
	"fmt"
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
// asserts only the code's current behavior does not catch it: the code was
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
//
// The gate used to read only the apiCSP and frontendCSP literals out of
// internal/middleware/security_headers.go, and the register said "both" policies
// carried the directives. There were four. The two it could not see were the
// admin gateway's, which conformed, and web/nginx.conf's, which shipped
// base-uri 'self' into the frontend image the chart deploys — the one policy a
// browser receives from a container rather than from the Go binary, and the only
// one that failed the requirement this row is Met on. A gate scoped to one file
// reports on that file, not on the claim.
//
// So every policy the repository serves is enumerated here, from every file that
// emits one, and cspPolicySources is a floor: adding a fifth policy somewhere new
// without adding it to this list fails the count check rather than passing
// silently.
var cspPolicySources = []struct {
	file  string
	want  int
	goSrc bool
}{
	// apiCSP and frontendCSP, chosen per request path, so a directive on one of
	// the two is a directive on some of the responses.
	{file: "internal/middleware/security_headers.go", want: 2, goSrc: true},
	// The admin gateway's own middleware, a separate binary and a separate policy.
	{file: "internal/adminapi/middleware.go", want: 1, goSrc: true},
	// The optional standalone frontend image. Off by default, but
	// charts/vault/templates/frontend.yaml deploys it when it is on, and then it
	// is the policy a browser actually receives.
	{file: "web/nginx.conf", want: 1, goSrc: false},
}

// cspLiteralRe matches a Go string literal holding a policy. Read against
// comment-stripped source, so the prose explaining the directives cannot be
// mistaken for a policy that declares them.
var cspLiteralRe = regexp.MustCompile(`"([^"\n]*default-src [^"\n]*)"`)

// nginxCSPRe matches the add_header form.
var nginxCSPRe = regexp.MustCompile(`add_header\s+Content-Security-Policy\s+"([^"]*)"`)

func TestASVS_V3_4_3_TheCSPMatchesWhatTheRegisterClaims(t *testing.T) {
	type policy struct{ where, value string }
	var policies []policy

	for _, src := range cspPolicySources {
		var body string
		re := nginxCSPRe
		if src.goSrc {
			body, re = readCodeOnly(t, src.file), cspLiteralRe
		} else {
			body = readProductionSource(t, src.file)
		}
		found := re.FindAllStringSubmatch(body, -1)
		if len(found) != src.want {
			t.Fatalf("V3.4.3: expected %d Content-Security-Policy string(s) in %s, found %d; "+
				"the gate cannot tell what is served", src.want, src.file, len(found))
		}
		for i, m := range found {
			policies = append(policies, policy{where: fmt.Sprintf("%s[%d]", src.file, i+1), value: m[1]})
		}
	}

	// A floor over the whole corpus, on top of the per-file counts above. Each
	// per-file check reads its expected count out of the table, so emptying the
	// table satisfies every one of them vacuously; this does not.
	if len(policies) < 4 {
		t.Fatalf("V3.4.3: only %d Content-Security-Policy strings were collected. The repository "+
			"serves four, and a gate cannot report on a policy it did not read.", len(policies))
	}

	complete := true
	for _, p := range policies {
		for _, directive := range []string{"object-src 'none'", "base-uri 'none'"} {
			if !strings.Contains(p.value, directive) {
				t.Logf("V3.4.3: %s does not declare %s", p.where, directive)
				complete = false
			}
		}
	}

	status, ar := registerRowStatus(t, "OWASP ASVS", "V3.4.3")

	if complete && status != statusMet {
		t.Errorf("V3.4.3: all %d served policies now declare object-src 'none' and base-uri 'none', but "+
			"the register still carries the row as %q (%s). The gap closed: move the row to Met, name "+
			"this test, and retire the accepted risk.", len(policies), status, ar)
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
	if files := productionGoFiles(t); len(files) < 100 {
		t.Fatalf("V3.5.3: only %d production files parsed; the Sec-Fetch sweep below would pass vacuously", len(files))
	}

	routes := readCodeOnly(t, "internal/server/server.go")
	mutatingGET := strings.Contains(routes, `"GET /auth/verify-email"`)

	// The alternative the requirement offers, looked for only where it would
	// count. cmd/bridge validates Sec-Fetch-* and is declared out of scope in
	// the register: it is a separate binary, a non-default deployment mode, and
	// nothing it does protects a route on the vault server. Scanning the whole
	// tree found it and concluded the remedy had landed, which would have moved
	// this row to Met on the strength of a control that is not in front of the
	// endpoint. A gate that reads the right token in the wrong binary is a
	// false pass, and a false pass on a coupling gate retires a real risk.
	var secFetch bool
	for _, pf := range productionGoFiles(t) {
		if strings.HasPrefix(pf.path, "cmd/bridge/") {
			continue
		}
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

	// Every profile has a floor; dev's is merely lower. That distinction is the
	// one the register row turns on, so it is asserted rather than assumed: the
	// original defect was a dev profile with no floor at all, which accepted a
	// four-character password.
	if !strings.Contains(src, "if floor := passwordFloorFor(c.Profile); c.PasswordMinLength < floor") {
		t.Error("3.1.1.2: the floor check no longer resolves a per-profile floor through " +
			"passwordFloorFor. If the shape changed, read what it does now and update the register " +
			"row to match; the row's claim is that no profile is exempt from having a floor.")
	}
	devMatch := regexp.MustCompile(`devPasswordMinLengthFloor\s*=\s*(\d+)`).FindStringSubmatch(src)
	if devMatch == nil {
		t.Error("3.1.1.2: devPasswordMinLengthFloor is gone. Either dev now shares the published " +
			"floor, which is stricter and the row should say so, or dev has no floor at all, which " +
			"is the defect this constant replaced.")
	} else {
		dev, convErr := strconv.Atoi(devMatch[1])
		if convErr != nil || dev < 8 {
			t.Errorf("3.1.1.2: the dev floor is %q. Section 3.1.1.1 requires a verifier to accept "+
				"memorized secrets of at least 8 characters, so a build below that is not "+
				"exercising the password path the deployment profiles run.", devMatch[1])
		}
		if dev > floor {
			t.Errorf("3.1.1.2: the dev floor (%d) is above the published floor (%d), which inverts "+
				"the relationship the register describes", dev, floor)
		}
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

	t.Logf("3.1.1.2: shipped default %d, enforced floor %d, dev floor %s", shipped, floor, devFloorLabel(devMatch))
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
	// The parse moved out of internal/email/mailer.go and into
	// email.CompileOverride, and it got stronger on the way: validation used to
	// run on the admin write path, so a row that reached the table by any other
	// route was compiled unvalidated on every send. It now runs wherever a
	// stored override is loaded.
	branding := readCodeOnly(t, "internal/email/branding.go")
	if !strings.Contains(branding, "func CompileOverride(ov TemplateOverride)") {
		t.Fatal("V1.3.7: email.CompileOverride is gone. It is the only constructor for a " +
			"CompiledOverride, which is what makes possession of one proof that the content was " +
			"validated. If overrides are gone this requirement's applicability changed; update the " +
			"register row rather than deleting this test.")
	}
	if !strings.Contains(branding, "template.New") || !strings.Contains(branding, ".Parse(") {
		t.Fatal("V1.3.7: nothing parses an admin-supplied string into a template any more")
	}

	// Validation before the parse, not after it and not somewhere else. The
	// order is the requirement: "any untrusted input being included dynamically
	// during template creation must be sanitized or strictly validated".
	validateAt := strings.Index(branding, "validateTemplate([]byte(ov.HTMLContent))")
	parseAt := strings.Index(branding, `template.New("subject")`)
	if validateAt < 0 {
		t.Error("V1.3.7: CompileOverride no longer validates the HTML body before compiling it")
	}
	if !strings.Contains(branding, "validateTemplate([]byte(ov.Subject))") {
		t.Error("V1.3.7: CompileOverride no longer validates the subject line, which is compiled as " +
			"a template of its own")
	}
	if validateAt >= 0 && parseAt >= 0 && validateAt > parseAt {
		t.Error("V1.3.7: validation now runs after the parse. An unvalidated admin-supplied string " +
			"reaching html/template is the thing this row claims cannot happen.")
	}

	// html/template, not text/template. This is the difference between a
	// structural injection and an unescaped one.
	for _, rel := range []string{"internal/email/branding.go", "internal/email/templates.go"} {
		src := readProductionSource(t, rel)
		if !strings.Contains(src, `"html/template"`) {
			t.Errorf("V1.3.7: %s no longer imports html/template", rel)
		}
		if strings.Contains(src, `"text/template"`) {
			t.Errorf("V1.3.7: %s imports text/template, which does not escape by context. "+
				"Interpolated data becomes markup and the row's whole argument collapses.", rel)
		}
	}

	// Both paths that can produce a compiled override reach it through the
	// validating constructor: the load path and the admin write path.
	if !strings.Contains(readCodeOnly(t, "internal/service/email_overrides.go"), "vaultemail.CompileOverride(") {
		t.Error("V1.3.7: the override load path no longer compiles through CompileOverride, so a " +
			"stored template that never passed the admin write path is compiled unvalidated on " +
			"every send")
	}
	if !strings.Contains(readCodeOnly(t, "internal/adminapi/email.go"), "email.ValidateTemplateContent(req.Subject, req.HTMLContent)") {
		t.Error("V1.3.7: the admin write path no longer validates before storing. The load path " +
			"catches it now, but rejecting at the boundary is what gives the operator an error " +
			"instead of a silently dead template.")
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

// --- ASVS V2.3.4 — the capped insert has to cover every path ---

// The concurrent-session cap was Met on the strength of CreateWithinCap, the
// advisory-locked insert. Three paths create a refresh family, and one of them,
// the social-login callback, did not use it: it called CheckSessionLimit, a
// count-only pre-check, and then inserted through the plain Create. Two
// reviewers found that independently. No test did.
//
// The fix for one path does not stop the fourth path arriving, so this asserts
// the property rather than the instance: every insert that creates a family
// either goes through the capped insert, or the register row names the file it
// is in. A path the register does not name fails the build.
func TestASVS_V2_3_4_EveryFamilyCreatingPathIsNamedByTheRegister(t *testing.T) {
	repo := readCodeOnly(t, "internal/repository/postgres/refresh_token.go")
	if !strings.Contains(repo, "func (r *RefreshTokenRepo) CreateWithinCap(") {
		t.Fatal("V2.3.4: CreateWithinCap is gone. It is the advisory-locked insert the whole row " +
			"rests on; without it the cap is a count followed by a race.")
	}
	if !strings.Contains(repo, "pg_advisory_xact_lock") && !strings.Contains(repo, "advisory") {
		t.Error("V2.3.4: CreateWithinCap no longer takes a per-user advisory lock, so two logins can " +
			"each count the same free slot and both insert")
	}

	// Every file that builds a model.RefreshToken inserts one. Rotation
	// legitimately uses the plain Create, because it extends a family that
	// already exists rather than creating one, so the discriminator is not the
	// call but the file: a file that inserts refresh tokens and never reaches
	// CreateWithinCap at all has no capped path, and whatever it inserts is a
	// new family by construction.
	//
	// That is a heuristic, and it is stated as one. It is the heuristic that
	// would have caught internal/handler/oauth.go, which is the path two
	// reviewers found and no test did.
	type site struct{ file, call string }
	var uncapped []site

	for _, pf := range productionGoFiles(t) {
		code := readCodeOnly(t, pf.path)
		if !strings.Contains(code, "model.RefreshToken{") {
			continue
		}
		if strings.Contains(code, "CreateWithinCap(") {
			continue
		}
		for _, call := range []string{"tokens.Create(", "refreshRepo.Create(", "h.tokens.Create("} {
			if strings.Contains(code, call) {
				uncapped = append(uncapped, site{pf.path, call})
			}
		}
	}

	notes := registerRowNotes(t, "OWASP ASVS", "V2.3.4")
	for _, s := range uncapped {
		if !strings.Contains(notes, s.file) {
			t.Errorf("V2.3.4: %s inserts a refresh-token family through %s rather than "+
				"CreateWithinCap, and the register row does not name it. The row claims the cap is "+
				"enforced as one unit of work; a path outside the advisory lock is a path where two "+
				"logins can each pass the pre-check and both insert. Name it in the row or move it "+
				"onto the capped insert.", s.file, s.call)
		}
	}
	if len(uncapped) == 0 {
		t.Logf("V2.3.4: every family-creating insert goes through CreateWithinCap")
	} else {
		t.Logf("V2.3.4: %d uncapped family-creating insert(s), each named by the register row", len(uncapped))
	}
}

// registerRowNotes returns one row's notes, failing if the row is gone.
func registerRowNotes(t *testing.T, standard, requirementID string) string {
	t.Helper()
	reg := loadRegister(t)
	for _, r := range reg.Requirements {
		if r.Standard == standard && r.RequirementID == requirementID {
			return r.Notes
		}
	}
	t.Fatalf("register row %s %s no longer exists; this gate has no subject", standard, requirementID)
	return ""
}

// devFloorLabel renders the dev floor for the log line, or says it is absent.
func devFloorLabel(m []string) string {
	if m == nil {
		return "absent"
	}
	return m[1]
}

// TestASVS_V7_6_1_FederatedSessionLifetimeMatchesWhatTheRegisterClaims is the
// coupling gate this row did not have.
//
// V7.6.1 asks that session lifetime and termination between a relying party and
// an identity provider behave as documented. CR-22 carries it as an accepted
// risk on the grounds that vault42 records neither the provider's authentication
// instant nor its session identifier, and nothing held that argument to the
// code: the row named TestASVS_V10_2_1_StateIsIntegrityProtectedAndSessionBound,
// which asserts the OAuth state parameter is HMAC-signed and session-bound. That
// is a cross-site-request-forgery gate. It would pass unchanged whether or not
// auth_time were read, so the row could have drifted in either direction without
// anything failing.
//
// The requirement has two halves and they moved apart. The authentication
// instant is now taken from the provider's auth_time claim, so a federated token
// no longer dates a login to the moment the callback ran. Termination is still
// unhandled in both directions: no back-channel logout endpoint exists, and
// AuthService.Logout revokes only vault42's own tokens. The row stays accepted
// for the second half, and this gate fails if either half changes without the
// register changing with it.
func TestASVS_V7_6_1_FederatedSessionLifetimeMatchesWhatTheRegisterClaims(t *testing.T) {
	callback := readCodeOnly(t, "internal/handler/oauth.go")
	verifier := readCodeOnly(t, "internal/oauth2/oidc_idtoken.go")

	// Half one: the instant. Reading the claim and passing it on are separate
	// steps and a gate that checked only the first would pass over a value that
	// is parsed and dropped.
	readsAuthTime := strings.Contains(verifier, `claims["auth_time"]`)
	usesAuthTime := strings.Contains(callback, "authTime := userInfo.AuthTime") &&
		strings.Contains(callback, "service.NewAuthContext(authTime,")

	if readsAuthTime != usesAuthTime {
		t.Errorf("V7.6.1: the ID token verifier %s auth_time and the callback %s it. Reading the "+
			"claim without passing it on leaves the token dating the login to the callback; "+
			"passing on a claim nobody reads cannot compile. One of the two moved without the "+
			"other.",
			map[bool]string{true: "reads", false: "does not read"}[readsAuthTime],
			map[bool]string{true: "uses", false: "does not use"}[usesAuthTime])
	}

	// Half two: termination. A back-channel logout endpoint is what closes it,
	// and it would be the thing that moves this row to Met.
	backchannel := strings.Contains(readCodeOnly(t, "internal/server/server.go"), "backchannel-logout") ||
		strings.Contains(verifier, "logout_token")

	status, ar := registerRowStatus(t, "OWASP ASVS", "V7.6.1")

	switch {
	case backchannel && status != statusMet:
		t.Errorf("V7.6.1: a back-channel logout path has landed and the register still carries "+
			"the row as %q (%s). Upstream termination was the half holding it open.", status, ar)
	case !backchannel && status == statusMet:
		t.Error("V7.6.1: the register marks this Met, and termination is still unhandled: no " +
			"back-channel logout endpoint exists, so an IdP session ending upstream does not end " +
			"the vault42 session.")
	case !readsAuthTime && status != statusMet:
		t.Error("V7.6.1: the register's argument rests on the authentication instant being read " +
			"from the provider, and internal/oauth2 no longer reads auth_time. Either the claim " +
			"handling was removed, in which case the row is weaker than it says, or this gate is " +
			"looking in the wrong place.")
	default:
		t.Logf("V7.6.1: carried as %s (%s); auth_time read=%v, back-channel logout=%v",
			status, ar, readsAuthTime, backchannel)
	}
}
