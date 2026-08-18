package compliance

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// OWASP Top 10:2025
// https://owasp.org/Top10/2025/
//
// Categories verified against owasp.org on 2026-08-10:
//   A01 Broken Access Control
//   A02 Security Misconfiguration
//   A03 Software Supply Chain Failures
//   A04 Cryptographic Failures
//   A05 Injection
//   A06 Insecure Design
//   A07 Authentication Failures
//   A08 Software or Data Integrity Failures
//   A09 Security Logging and Alerting Failures
//   A10 Mishandling of Exceptional Conditions
//
// Until this file, the Top 10 section of docs/COMPLIANCE.md carried 48 claimed
// requirements and no test anywhere in the tree named a Top 10 category. The
// counter to "we align with the Top 10" was one question long: name the test.
// =============================================================================

// --- A01:2025 Broken Access Control ---

// serverRoutes parses internal/server/server.go and returns, for each route
// pattern, the source text of the handler expression it is wired to. Reading
// the wiring is the point: the rbac and middleware unit tests both pass while a
// route is registered without its guard, because neither of them can see the
// route table.
func serverRoutes(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "internal", "server", "server.go")
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	routes := make(map[string]string)
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		pattern, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pattern.Kind != token.STRING {
			return true
		}

		var sb strings.Builder
		if err := printer.Fprint(&sb, fset, call.Args[1]); err != nil {
			t.Fatalf("render handler expression: %v", err)
		}
		routes[strings.Trim(pattern.Value, `"`)] = sb.String()
		return true
	})
	return routes
}

// publicRoutePrefixes is the declared unauthenticated surface. It is an
// allowlist rather than a denylist on purpose: a new route is authenticated by
// default and has to be argued into this list, instead of being exposed by
// forgetting a wrapper.
var publicRoutePrefixes = []string{
	"/healthz", "/readyz", "/metrics",
	"/.well-known/",
	"/auth/capabilities",
	"/auth/register", "/auth/login", "/auth/refresh",
	"/auth/verify-email", "/auth/resend-verification",
	"/auth/password/reset",
	"/auth/oauth2/",
	"/client/token",
	// The catch-all serves the static single-page frontend, which carries no
	// data of its own. Everything it then calls is one of the API routes below.
	"/",
}

// authGuards are the wrapper names that establish a caller identity before the
// handler runs. They differ in which credential they accept, not in whether
// they require one: authMw and confirmed take an access token, authedChallenge
// takes an MFA challenge token issued only after a first factor succeeded, and
// docRead/docWrite compose authMw with a required scope.
//
// Adding a name here is the deliberate cost of introducing a new guard: the
// reviewer has to confirm the closure really authenticates before the route
// scan will accept it. TestOWASP_A01_2025_GuardClosuresReallyAuthenticate keeps
// that confirmation executable rather than trusting this list.
var authGuards = []string{"authed(", "authMw(", "authedChallenge(", "confirmed(", "docRead(", "docWrite("}

// guardComposes names, per guard, the authentication middleware that guard is
// entitled to compose — and only that one.
//
// This map replaces a check that accepted "authMw(" or "challengeMw("
// interchangeably. The two are not interchangeable. challengeMw additionally
// accepts the 2fa_challenge token, minted after the password succeeds and before
// the second factor, so repointing authed at it hands twenty-one routes to a
// caller holding the victim's password alone — including decrypted identity and
// the full GDPR export. That mutation is one identifier wide and it passed here,
// because a check that accepts either is not a check.
//
// The deployed guard sets are pinned route by route in
// tests/spec/chain_wiring_test.go and driven with real tokens in
// internal/server/chain_probe_test.go. This gate is the register's own copy: the
// A01 row cites it, so it has to be able to fail.
var guardComposes = map[string]string{
	"authed":          "authMw(",
	"confirmed":       "authMw(",
	"authedChallenge": "challengeMw(",
	"docRead":         "authMw(",
	"docWrite":        "authMw(",
}

func isDeclaredPublic(path string) bool {
	for _, prefix := range publicRoutePrefixes {
		if prefix == "/" {
			if path == "/" {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func hasAuthGuard(wiring string) bool {
	for _, guard := range authGuards {
		if strings.Contains(wiring, guard) {
			return true
		}
	}
	return false
}

// "Broken access control" at the route layer means a handler that runs without
// the middleware that establishes who is calling. Every route outside the
// declared public surface must pass through authed(...) or authMw(...).
func TestOWASP_A01_2025_EveryNonPublicRouteIsAuthenticated(t *testing.T) {
	routes := serverRoutes(t)
	if len(routes) < 40 {
		t.Fatalf("A01:2025: only %d routes parsed out of server.go; the parse is broken", len(routes))
	}

	checked := 0
	for route, wiring := range routes {
		_, path, found := strings.Cut(route, " ")
		if !found {
			path = route
		}
		if isDeclaredPublic(path) {
			continue
		}
		checked++
		if !hasAuthGuard(wiring) {
			t.Errorf("A01:2025: %s is neither on the declared public surface nor wrapped in one of %v; it is wired as %s", route, authGuards, wiring)
		}
	}

	if checked == 0 {
		t.Fatal("A01:2025: every parsed route matched the public allowlist; the allowlist has swallowed the check")
	}
	t.Logf("A01:2025: %d of %d routes are non-public, all authenticated", checked, len(routes))
}

// A name in authGuards is only as good as the closure behind it. This resolves
// each guard back to its definition in server.go and requires it to compose the
// authentication middleware, so a future guard that merely rate-limits cannot be
// added to the list and silently expose every route it wraps.
func TestOWASP_A01_2025_GuardClosuresReallyAuthenticate(t *testing.T) {
	src := readProductionSource(t, "internal/server/server.go")
	for _, guard := range authGuards {
		name := strings.TrimSuffix(guard, "(")
		if name == "authMw" {
			continue // the middleware itself, not a closure over it
		}
		idx := strings.Index(src, name+" := func(")
		if idx < 0 {
			t.Errorf("A01:2025: guard %q is in authGuards but is not defined as a closure in server.go", name)
			continue
		}
		body := src[idx:]
		if end := strings.Index(body, "\n\t}"); end > 0 {
			body = body[:end]
		}
		want, declared := guardComposes[name]
		if !declared {
			t.Errorf("A01:2025: guard %q is in authGuards but guardComposes does not say which "+
				"authentication middleware it is entitled to compose. Name it, so the reviewer "+
				"decides which credential this guard accepts rather than inheriting whichever one "+
				"the closure happens to reach.", name)
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("A01:2025: guard %q no longer composes %s; it is defined as %s", name, want, body)
		}
		for _, mw := range []string{"authMw(", "challengeMw("} {
			if mw == want || !strings.Contains(body, mw) {
				continue
			}
			t.Errorf("A01:2025: guard %q composes %s where the register entitles it to %s. The two "+
				"authentication middleware accept different credentials — challengeMw also accepts "+
				"the 2fa_challenge token minted between the first and second factor — so a guard "+
				"reaching the wrong one hands every route it wraps to the wrong credential. It is "+
				"defined as %s", name, mw, want, body)
		}
	}
}

// The routes that mutate or read another principal's data must additionally
// bind the caller's device fingerprint, not merely a valid bearer token.
func TestOWASP_A01_2025_SensitiveRoutesBindTheFingerprint(t *testing.T) {
	mustBind := []string{
		"DELETE /user/account",
		"POST /user/password",
		"POST /auth/confirm",
	}
	routes := serverRoutes(t)

	for _, route := range mustBind {
		wiring, ok := routes[route]
		if !ok {
			t.Errorf("A01:2025: route %q is no longer registered; re-derive this assertion", route)
			continue
		}
		if !strings.Contains(wiring, "fingerprintMw(") {
			t.Errorf("A01:2025: %s does not bind the device fingerprint; a stolen access token alone would suffice", route)
		}
	}
}

// --- A05:2025 Injection ---

// sqlEntryPoints are the pgx call names that take SQL as their second argument
// (the first being a context).
var sqlEntryPoints = map[string]bool{"Query": true, "QueryRow": true, "Exec": true}

// sqlKeyword recognizes a string literal that is actually SQL rather than, say,
// a log message that happens to be concatenated.
var sqlKeyword = regexp.MustCompile(`(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|ORDER\s+BY|LIMIT|OFFSET|RETURNING)\b`)

// "SQL injection is impossible here" is the single most load-bearing claim in
// the compliance report and, until this test, the only one with no executable
// backing. internal/sanitize has unit tests; none of them can see a repository
// method that builds its WHERE clause with a +.
//
// The rule enforced is structural: every operand of a SQL string expression
// must be a literal, a package-level constant, or a parameter whose every
// in-package call site passes a literal. A value that came from a request
// cannot satisfy any of those.
func TestOWASP_A05_2025_NoRequestDataIsConcatenatedIntoSQL(t *testing.T) {
	byPackage := map[string][]parsedFile{}
	for _, pf := range productionGoFiles(t) {
		dir := filepath.ToSlash(filepath.Dir(pf.path))
		byPackage[dir] = append(byPackage[dir], pf)
	}

	inspected, flagged := 0, 0
	for dir, pkg := range byPackage {
		if !strings.Contains(dir, "repository") {
			continue
		}
		safe := newSQLTaint(pkg)

		for _, pf := range pkg {
			ast.Inspect(pf.file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !sqlEntryPoints[sel.Sel.Name] {
					return true
				}
				inspected++
				if reason := safe.explain(call.Args[1]); reason != "" {
					flagged++
					t.Errorf("A05:2025: %s builds its query from %s; a query may only be assembled from literals, package constants and placeholder-only formatting", pf.pos(call), reason)
				}
				return true
			})
		}
	}

	if inspected == 0 {
		t.Fatal("A05:2025: no SQL entry point was found in the repository layer; the scan is broken")
	}
	t.Logf("A05:2025: %d SQL call sites inspected across the repository layer, %d flagged", inspected, flagged)
}

// A detector that has never fired is indistinguishable from a detector that
// cannot fire, and the repository layer is clean, so the scan above always
// passes. This runs the same analysis over a synthetic package containing the
// four shapes the control exists to catch, and fails if any of them slips
// through. Without it, deleting the body of explain() would break nothing.
func TestOWASP_A05_2025_TheInjectionDetectorFiresOnKnownBadPatterns(t *testing.T) {
	const bad = `package postgres

const cols = "id, name"

func (r *Repo) Direct(ctx C, name string) {
	r.db.Pool.Query(ctx, "SELECT "+cols+" FROM t WHERE name = '"+name+"'")
}

func (r *Repo) ViaSprintf(ctx C, order string) {
	r.db.Pool.Query(ctx, fmt.Sprintf("SELECT id FROM t ORDER BY %s", order))
}

func (r *Repo) ViaLocal(ctx C, filter string) {
	q := "SELECT id FROM t"
	q += " WHERE " + filter
	r.db.Pool.Query(ctx, q)
}

func (r *Repo) ViaHelper(ctx C, where string) {
	r.helper(ctx, "SELECT id FROM t "+where)
}

func (r *Repo) helper(ctx C, query string) {
	r.db.Pool.Exec(ctx, query)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", bad, 0)
	if err != nil {
		t.Fatalf("parse synthetic package: %v", err)
	}
	pkg := []parsedFile{{path: "synthetic.go", fset: fset, file: parsed}}
	taint := newSQLTaint(pkg)

	// Four SQL entry points: three direct, plus helper's Exec, whose `query`
	// parameter is tainted by the concatenation ViaHelper passes it.
	const wantFlagged = 4
	flagged := 0
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !sqlEntryPoints[sel.Sel.Name] {
			return true
		}
		if reason := taint.explain(call.Args[1]); reason != "" {
			flagged++
			t.Logf("A05:2025: detector correctly flagged %s: %s", fset.Position(call.Pos()), reason)
		} else {
			t.Errorf("A05:2025: the detector passed a query at %s that splices a parameter into SQL", fset.Position(call.Pos()))
		}
		return true
	})

	if flagged != wantFlagged {
		t.Errorf("A05:2025: detector flagged %d of %d known-bad queries", flagged, wantFlagged)
	}
}

// sqlTaint answers whether a string expression can only ever hold text the
// repository authored. A value is authored when every leaf that flows into it
// is a string literal, a package-level constant, a placeholder-only Sprintf, or
// another authored value. Anything reaching a query from outside that closure
// is a finding, and no request value can enter the closure.
//
// The analysis is name-based and package-scoped rather than type-resolved, so
// two same-named locals in one package are merged. That errs toward reporting,
// which is the correct direction for a control.
type sqlTaint struct {
	consts  map[string]bool
	contrib map[string][]ast.Expr // candidate name -> every expression that flows into it
	tainted map[string]bool
}

// valueVerb matches a fmt verb that interpolates a value. "$%d" emits a
// placeholder index and carries nothing from the caller into the SQL text;
// "%s" splices the argument itself, which is the injection.
var valueVerb = regexp.MustCompile(`%[-+# 0-9.*]*[svqxXeEfgGtcUp]`)

func newSQLTaint(pkg []parsedFile) *sqlTaint {
	s := &sqlTaint{
		consts:  packageStringConsts(pkg),
		contrib: map[string][]ast.Expr{},
		tainted: map[string]bool{},
	}

	// Every assignment to a local, every append into a slice, and every
	// argument passed to an in-package function parameter is a way for text to
	// reach a query. All three are collected as contributions.
	params := functionStringParams(pkg)
	for _, pf := range pkg {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok || i >= len(node.Rhs) {
						continue
					}
					s.contrib[ident.Name] = append(s.contrib[ident.Name], node.Rhs[i])
				}
			case *ast.CallExpr:
				name := callName(node)
				if name == "append" && len(node.Args) >= 2 {
					if ident, ok := node.Args[0].(*ast.Ident); ok {
						s.contrib[ident.Name] = append(s.contrib[ident.Name], node.Args[1:]...)
					}
					return true
				}
				for _, p := range params[name] {
					if p.index < len(node.Args) {
						s.contrib[p.name] = append(s.contrib[p.name], node.Args[p.index])
					}
				}
			}
			return true
		})
	}

	// Fixpoint: a candidate is tainted as soon as any contribution is, so the
	// taint set only grows and the loop terminates.
	for changed := true; changed; {
		changed = false
		for name, exprs := range s.contrib {
			if s.tainted[name] {
				continue
			}
			for _, e := range exprs {
				if s.explain(e) != "" {
					s.tainted[name] = true
					changed = true
					break
				}
			}
		}
	}
	return s
}

// explain returns "" when the expression is authored, and otherwise a short
// description of the first leaf that is not.
func (s *sqlTaint) explain(e ast.Expr) string {
	for _, leaf := range flattenConcat(e) {
		switch v := leaf.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "a non-string literal"
			}
		case *ast.Ident:
			if s.consts[v.Name] {
				continue
			}
			if _, known := s.contrib[v.Name]; known && !s.tainted[v.Name] {
				continue
			}
			return "the identifier " + v.Name
		case *ast.CallExpr:
			if reason := s.explainCall(v); reason != "" {
				return reason
			}
		case *ast.ParenExpr:
			if reason := s.explain(v.X); reason != "" {
				return reason
			}
		default:
			return "a non-literal expression"
		}
	}
	return ""
}

func (s *sqlTaint) explainCall(call *ast.CallExpr) string {
	switch callName(call) {
	case "Sprintf":
		format, ok := call.Args[0].(*ast.BasicLit)
		if !ok || format.Kind != token.STRING {
			return "a Sprintf with a non-literal format"
		}
		if match := valueVerb.FindString(format.Value); match != "" {
			return "a Sprintf whose format interpolates a value with " + match
		}
		return ""
	case "Join":
		// strings.Join over authored fragments is itself authored.
		if len(call.Args) != 2 {
			return "a Join with an unexpected shape"
		}
		if reason := s.explain(call.Args[0]); reason != "" {
			return reason
		}
		return s.explain(call.Args[1])
	case "append":
		// A slice of authored fragments stays authored. The first argument is
		// the slice being extended and is covered by its own contributions.
		for _, arg := range call.Args[1:] {
			if reason := s.explain(arg); reason != "" {
				return reason
			}
		}
		return ""
	case "Repeat", "TrimSuffix", "TrimRight":
		for _, arg := range call.Args {
			if reason := s.explain(arg); reason != "" {
				return reason
			}
		}
		return ""
	}
	return "the result of " + callName(call) + "(...)"
}

// stringParam records one string-typed parameter of an in-package function.
type stringParam struct {
	name  string
	index int
}

func functionStringParams(pkg []parsedFile) map[string][]stringParam {
	out := map[string][]stringParam{}
	for _, pf := range pkg {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}
			index := 0
			for _, field := range fn.Type.Params.List {
				ident, isIdent := field.Type.(*ast.Ident)
				isString := isIdent && ident.Name == "string"
				if len(field.Names) == 0 {
					index++
					continue
				}
				for _, name := range field.Names {
					if isString {
						out[fn.Name.Name] = append(out[fn.Name.Name], stringParam{name: name.Name, index: index})
					}
					index++
				}
			}
		}
	}
	return out
}

// The other injection shape is fmt.Sprintf. Building "WHERE x = $%d" is safe
// because the result is a placeholder; building "WHERE x = %s" is the bug. The
// distinction is the verb, so the verb is what gets checked.
func TestOWASP_A05_2025_SprintfIntoSQLEmitsPlaceholdersOnly(t *testing.T) {
	inspected, scanned := 0, 0
	for _, pf := range productionGoFiles(t) {
		if !strings.Contains(pf.path, "repository") {
			continue
		}
		scanned++
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || callName(call) != "Sprintf" {
				return true
			}
			format, ok := call.Args[0].(*ast.BasicLit)
			if !ok || format.Kind != token.STRING || !sqlKeyword.MatchString(format.Value) {
				return true
			}
			inspected++
			if match := valueVerb.FindString(format.Value); match != "" {
				t.Errorf("A05:2025: %s formats SQL with the value verb %q; only placeholder indices (%%d) may be interpolated into a query", pf.pos(call), match)
			}
			return true
		})
	}

	// Zero Sprintf-built fragments is a legitimate and better state, so it is
	// not a failure. Zero *files* is not: it means the path filter stopped
	// matching the repository layer, and then the scan above asserted nothing
	// while reporting the same green.
	if scanned == 0 {
		t.Fatalf("A05:2025: no production file matched the repository layer, so this scan " +
			"inspected nothing and would report success whatever the queries do")
	}
	t.Logf("A05:2025: %d repository files scanned, %d Sprintf-built SQL fragments inspected, all placeholder-only", scanned, inspected)
}

// packageStringConsts returns the names of package-level constants declared in
// the given files.
func packageStringConsts(pkg []parsedFile) map[string]bool {
	out := map[string]bool{}
	for _, pf := range pkg {
		for _, decl := range pf.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range value.Names {
					out[name.Name] = true
				}
			}
		}
	}
	return out
}

// flattenConcat expands a chain of string concatenations into its leaves.
func flattenConcat(e ast.Expr) []ast.Expr {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return []ast.Expr{e}
	}
	return append(flattenConcat(bin.X), flattenConcat(bin.Y)...)
}

// --- A02:2025 Security Misconfiguration ---

// A shipped default that is insecure is the whole category. vault42's answer is
// that the non-dev profile refuses to start when a control is off, so the
// assertion is that each refusal is still wired into Config.Validate.
func TestOWASP_A02_2025_ProductionProfileRefusesInsecureDefaults(t *testing.T) {
	src := readProductionSource(t, "internal/config/config.go")
	idx := strings.Index(src, "func (c *Config) Validate() error")
	if idx < 0 {
		t.Fatal("A02:2025: Config.Validate is gone; the startup security gate no longer exists")
	}
	validate := src[idx:]
	if end := strings.Index(validate, "\nfunc "); end > 0 {
		validate = validate[:end]
	}

	for _, c := range []struct{ needle, control string }{
		{"HMACSecret", "HMAC secret length"},
		{"Pepper", "password pepper length"},
		{"RateLimitEnabled", "rate limiting cannot be silently disabled"},
		{"TLSEnabled", "TLS cannot be silently disabled"},
		{"Origin", "a CORS origin must be declared"},
	} {
		if !strings.Contains(validate, c.needle) {
			t.Errorf("A02:2025: Config.Validate no longer checks %s (%s)", c.needle, c.control)
		}
	}

	// The default profile must be the strict one. A deployment that forgets to
	// set VAULT_PROFILE has to land in production, not in dev.
	if !strings.Contains(src, `envOr("VAULT_PROFILE", "production")`) {
		t.Error(`A02:2025: the default profile is no longer "production"; an unset VAULT_PROFILE would relax every gate`)
	}
	if !strings.Contains(validate, "ProfileDev") {
		t.Error("A02:2025: Config.Validate no longer distinguishes the dev profile; verify the bypass is still scoped")
	}
}

func TestOWASP_A02_2025_SecurityHeadersAreSetOnEveryResponse(t *testing.T) {
	src := readProductionSource(t, "internal/middleware/security_headers.go")
	required := map[string]string{
		"Strict-Transport-Security":    "transport downgrade",
		"X-Content-Type-Options":       "MIME sniffing",
		"X-Frame-Options":              "clickjacking",
		"Referrer-Policy":              "referrer leakage",
		"Cache-Control":                "sensitive-response caching",
		"Content-Security-Policy":      "script injection",
		"Cross-Origin-Opener-Policy":   "cross-origin window access",
		"Cross-Origin-Resource-Policy": "cross-origin resource inclusion",
		"Permissions-Policy":           "ambient device access",
	}
	for header, risk := range required {
		if !strings.Contains(src, header) {
			t.Errorf("A02:2025: %s is no longer set; %s is unmitigated", header, risk)
		}
	}

	// A header middleware that is defined but never installed is not a control.
	if !strings.Contains(readProductionSource(t, "internal/server/server.go"), "SecurityHeaders") {
		t.Error("A02:2025: the security-headers middleware is no longer installed in the server chain")
	}
}

// --- A03:2025 Software Supply Chain Failures ---

// A03 is new in the 2025 edition and is the category vault42 is best placed to
// evidence, because the release pipeline already produces an SBOM, build
// provenance and cosign signatures. The evidence was simply never cited where
// it counts, and nothing failed if it were removed.
//
// The workflow files are read, never written: the CI definitions belong to
// another owner.
func TestOWASP_A03_2025_ReleasePipelineProducesSignedProvenance(t *testing.T) {
	release := workflowSource(t, "release.yml")
	if release == "" {
		// Fatal, not skip, and matching the three tests in
		// audit_supplychain_test.go that answer the identical condition the same
		// way. The register cites this test as the evidence that the release
		// pipeline signs what it publishes; without the workflow there is no
		// evidence, and a skip leaves the row Met with nothing behind it.
		t.Fatalf("A03:2025: .github/workflows/release.yml is unreadable, so every provenance and " +
			"signing assertion below would be skipped and the register row would stay Met with " +
			"nothing behind it")
	}

	for _, c := range []struct{ needle, artifact string }{
		{"sbom: true", "a software bill of materials"},
		{"provenance: true", "SLSA build provenance"},
		{"cosign-installer", "the cosign toolchain"},
		{"cosign sign", "a signature over the published digest"},
		{"id-token: write", "the OIDC identity that makes keyless signing verifiable"},
	} {
		if !strings.Contains(release, c.needle) {
			t.Errorf("A03:2025: release.yml no longer produces %s (looked for %q)", c.artifact, c.needle)
		}
	}
}

// An unpinned action is a supply-chain hole that no dependency scanner sees:
// a moved tag re-points at new code with the same reference. Every third-party
// action must be pinned to a commit SHA.
func TestOWASP_A03_2025_WorkflowActionsArePinnedToCommitSHAs(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("A03:2025: .github/workflows is unreadable (%v), so no action reference is "+
			"checked for SHA pinning and this gate would report the same green as a clean scan", err)
	}

	uses := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*([^\s#]+)`)
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	checked := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, m := range uses.FindAllStringSubmatch(string(raw), -1) {
			ref := m[1]
			// Local composite actions and reusable workflows in this repo are
			// pinned by being in this repo.
			if strings.HasPrefix(ref, "./") {
				continue
			}
			checked++
			_, version, found := strings.Cut(ref, "@")
			if !found || !sha.MatchString(version) {
				t.Errorf("A03:2025: %s uses %q, which is not pinned to a 40-character commit SHA", entry.Name(), ref)
			}
		}
	}

	// Every workflow in this repository uses third-party actions. Zero means
	// the `uses:` pattern stopped matching, not that the supply chain shrank,
	// and a skip would hide an unpinned action rather than report one.
	if checked == 0 {
		t.Fatalf("A03:2025: no third-party action reference matched in %d workflow files, so "+
			"nothing was checked for SHA pinning", len(entries))
	}
	t.Logf("A03:2025: %d third-party action references inspected, all SHA-pinned", checked)
}

func workflowSource(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", name))
	if err != nil {
		return ""
	}
	return string(raw)
}

// --- A06:2025 Insecure Design ---

// A rate limiter that fails open under cache loss is a design choice, not a
// bug, but it must not be the choice on the credential endpoints: those are
// exactly where an attacker would induce the outage. The property asserted is
// that the authentication-critical limiters are constructed fail-closed.
func TestOWASP_A06_2025_CredentialEndpointsRateLimitFailClosed(t *testing.T) {
	src := readProductionSource(t, "internal/server/server.go")
	if !strings.Contains(src, "FailClosed") {
		t.Fatal("A06:2025: no rate limiter in the server chain is constructed fail-closed")
	}

	// Count is the assertion: the credential surface is login, register,
	// password reset, TOTP, account delete and the KMS unwrap oracle.
	got := strings.Count(src, "FailClosed")
	if got < 6 {
		t.Errorf("A06:2025: only %d rate limiters are fail-closed; the credential and key-release surface needs at least 6", got)
	}
}

// --- A08:2025 Software or Data Integrity Failures ---

// The lockfile is the integrity boundary for the JavaScript surface, and the
// package manager itself is integrity-pinned. Both are asserted because losing
// either silently reintroduces resolution-time substitution.
func TestOWASP_A08_2025_DependencyResolutionIsIntegrityPinned(t *testing.T) {
	manifest := readProductionSource(t, "package.json")
	if !strings.Contains(manifest, `"packageManager"`) || !strings.Contains(manifest, "+sha512.") {
		t.Error("A08:2025: package.json no longer pins the package manager by hash")
	}

	if ci := workflowSource(t, "ci.yml"); ci != "" && !strings.Contains(ci, "--frozen-lockfile") {
		t.Error("A08:2025: CI no longer installs with --frozen-lockfile; the lockfile would stop being binding")
	}

	if !strings.Contains(readProductionSource(t, "go.mod"), "toolchain go") {
		t.Error("A08:2025: go.mod no longer pins a toolchain; builds would float across Go releases")
	}
}

// --- A09:2025 Security Logging and Alerting Failures ---

// A09 was renamed in the 2025 edition to add "Alerting", and that rename is what
// moved vault42 off Met: every security event reached an append-only store and
// nothing raised anything from any of them.
//
// The tripwire that used to live here, TestOWASP_A09_2025_RiskScoreIsStillWriteOnly,
// asserted that repository.AuditFilter contained no field mentioning risk, and
// said in its own failure message that closing CR-15 meant moving the row and
// deleting it. It has fired. It is replaced rather than deleted, because it was
// the suite's only assertion about what risk_score is for, and the replacement
// is in tests/compliance/alerting_test.go:
//
//   - TestOWASP_A09_2025_RiskScoreIsReadAndNotMerelyWritten
//   - TestOWASP_A09_2025_TheAlertSinkIsInstalledOutsideTheHoneypotProfile
//
// The logging half of A09 is unchanged and is pinned below.

// The logging half of A09 is genuinely strong and is what the register cites.
func TestOWASP_A09_2025_SecurityEventsReachAnAppendOnlyStore(t *testing.T) {
	src := readProductionSource(t, "internal/audit/audit.go")
	for _, needle := range []string{"func (l *Logger) Log(", "scrubEventMetadata", "isCriticalEvent"} {
		if !strings.Contains(src, needle) {
			t.Errorf("A09:2025: internal/audit/audit.go no longer contains %s", needle)
		}
	}
	if !strings.Contains(readProductionSource(t, "migrations/001_initial_schema.sql"), "audit_log_no_delete") {
		t.Error("A09:2025: the audit store is no longer append-only")
	}
}
