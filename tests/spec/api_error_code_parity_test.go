// Error-code parity between the handlers and the published API reference.
//
// docs/api.md gives each endpoint a "| Status | Error | Description |" table,
// and a client integrator codes their error handling against it. Nothing
// checked those tables. A sweep of the 1.0.3 tree found 49 rows missing across
// 17 endpoints -- every 403 the OAuth callback can answer, the whole shared
// refusal set the four 2FA verify endpoints inherit from the MFA completion
// path, the 409 a raced backup code returns, the two 500s that mean the
// password was already changed -- and the omissions all ran the same way: the
// document described a narrower, tidier failure surface than the code has, so a
// client that handled every documented code still met undocumented ones in
// production.
//
// The gate is deliberately one-directional and literal. It asserts that a
// WriteError with a literal status and a literal code, written inside a
// function that says which route it serves, has a row in that route's table. It
// does not assert the converse: a documented code with no literal in the
// handler is usually correct, because middleware answers many of them
// (missing_authorization, insufficient_scope, rate_limit_exceeded) through
// WriteBearerError and other helpers this parser does not read. Twenty rows
// looked like phantoms under a naive reverse check and all twenty were real,
// which is why that direction is left to a reader.
//
// Handlers are mapped to routes through their own doc comments -- "// Verify
// handles POST /auth/2fa/totp/verify." -- rather than by resolving the mux
// registration back to a receiver type. The convention already held for every
// handler in the package, and TestEveryRouteAnnotatedHandlerHasADocSection
// keeps it holding: a handler whose comment stops naming a real route fails
// rather than dropping silently out of the gate's view, which is the failure
// mode that lets a gate pass while seeing nothing.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// handlerPkg holds every HTTP handler for the main binary.
const handlerPkg = "internal/handler"

// apiReference is the document whose error tables this gate holds.
var apiReference = filepath.Join("docs", "api.md")

// routeComment matches the convention every handler in internal/handler follows:
// the doc comment's first sentence names the method and path it serves. The
// trailing text after the path is free-form -- several handlers carry a
// paragraph of rationale -- so only the leading triple is captured.
var routeComment = regexp.MustCompile(`^(\w+) handles ([A-Z]+) (/\S*)`)

// errorRow matches one row of a "| Status | Error | Description |" table.
var errorRow = regexp.MustCompile("^\\|\\s*(\\d{3})\\s*\\|\\s*`([a-z0-9_]+)`\\s*\\|")

// sectionHeading matches the "#### METHOD /path" endpoint headings that open
// each reference section. route_drift_test.go already asserts every one of
// these names a registered route, so this gate can trust them as keys.
var sectionHeading = regexp.MustCompile(`^#### ([A-Z]+) (\S+)\s*$`)

// inlinedHelpers are package-local functions whose failures reach the caller
// unchanged, so their codes belong in the caller's table.
//
// completeMFAIfChallenge is the shared tail of all four 2FA verify endpoints. It
// writes the response and reports that it did, so every code it can emit is a
// code those four routes can return, and documenting them once per endpoint is
// the only way a client sees them.
//
// The list is deliberately short and hand-picked. Expanding it to every helper
// that calls WriteError over-reports badly: ServiceDocumentHandler.writeError is
// one error mapper shared by four routes, and inlining it would demand that
// DELETE document a 413 document_too_large it cannot produce, which would make
// the document worse rather than better.
var inlinedHelpers = map[string]bool{
	"completeMFAIfChallenge": true,
}

// statusNames maps the net/http status constants to their codes. Only the ones
// the handlers actually use are listed; an unlisted constant fails loudly in
// emittedCodes rather than being skipped, so a handler that starts answering a
// new status cannot slip past.
var statusNames = map[string]int{
	"StatusBadRequest": 400, "StatusUnauthorized": 401, "StatusForbidden": 403,
	"StatusNotFound": 404, "StatusMethodNotAllowed": 405, "StatusNotAcceptable": 406,
	"StatusConflict": 409, "StatusGone": 410, "StatusPreconditionFailed": 412,
	"StatusRequestEntityTooLarge": 413, "StatusUnsupportedMediaType": 415,
	"StatusUnprocessableEntity": 422, "StatusTooManyRequests": 429,
	"StatusInternalServerError": 500, "StatusNotImplemented": 501,
	"StatusBadGateway": 502, "StatusServiceUnavailable": 503,
}

// errCode is one (status, error code) pair an endpoint can answer with.
type errCode struct {
	status int
	code   string
}

// handlerFunc is one parsed handler: the route it says it serves, the codes it
// writes itself, and the helpers it delegates to.
type handlerFunc struct {
	name   string
	route  string // "METHOD /path", empty when the function serves no route
	codes  map[errCode]string
	callee map[string]bool
	pos    string
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEveryEmittedErrorCodeIsDocumented is the gate.
func TestEveryEmittedErrorCodeIsDocumented(t *testing.T) {
	root := repoRoot(t)
	handlers, helpers := parseHandlers(t, root)
	tables := errorTables(t, filepath.Join(root, apiReference))

	// Floors first. A parser that recognizes nothing reports no violations,
	// which is indistinguishable from a document that is correct.
	routed := 0
	for _, h := range handlers {
		if h.route != "" {
			routed++
		}
	}
	if routed < 40 {
		t.Fatalf("only %d route-annotated handlers parsed out of %s; the doc-comment convention "+
			"changed and this gate has stopped seeing what it guards", routed, handlerPkg)
	}
	if len(tables) < 40 {
		t.Fatalf("only %d endpoint sections parsed out of %s; the heading convention changed",
			len(tables), apiReference)
	}

	var checked int
	for _, h := range handlers {
		if h.route == "" {
			continue
		}
		documented, ok := tables[h.route]
		if !ok {
			continue // reported by TestEveryRouteAnnotatedHandlerHasADocSection
		}
		emitted := resolveCodes(h, helpers)
		for _, c := range sortedCodes(emitted) {
			checked++
			if documented[c] {
				continue
			}
			t.Errorf("%s answers %d %q at %s, and %s has no row for it in the %s table.\n"+
				"A client that handles every documented code still meets this one. Add the row, "+
				"or stop emitting the code.",
				h.route, c.status, c.code, emitted[c], apiReference, h.route)
		}
	}
	if checked == 0 {
		t.Fatal("zero (status, code) pairs were extracted; the WriteError call shape changed and " +
			"this gate is asserting nothing")
	}
	t.Logf("%d route-annotated handlers, %d documented endpoint sections, %d emitted codes checked",
		routed, len(tables), checked)
}

// TestEveryRouteAnnotatedHandlerHasADocSection keeps the mapping honest. A
// handler that names a route the reference does not document would otherwise be
// skipped by the gate above without anybody noticing, which is exactly how a
// gate comes to guard nothing.
func TestEveryRouteAnnotatedHandlerHasADocSection(t *testing.T) {
	root := repoRoot(t)
	handlers, _ := parseHandlers(t, root)
	tables := errorTables(t, filepath.Join(root, apiReference))

	for _, h := range handlers {
		if h.route == "" {
			continue
		}
		if _, ok := tables[h.route]; !ok {
			t.Errorf("%s (%s) says it handles %q, which has no '#### %s' section in %s.\n"+
				"Either the comment names a route that does not exist, or the endpoint is "+
				"undocumented; both are drift this gate exists to catch.",
				h.name, h.pos, h.route, h.route, apiReference)
		}
	}
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

// parseHandlers reads every non-test file in internal/handler and returns every
// function declaration once, plus a lookup of the package-local helpers an
// inlined caller needs to resolve.
func parseHandlers(t *testing.T, root string) ([]*handlerFunc, map[string]*handlerFunc) {
	t.Helper()
	dir := filepath.Join(root, handlerPkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", handlerPkg, err)
	}

	var all []*handlerFunc
	helpers := map[string]*handlerFunc{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			h := &handlerFunc{
				name:   fn.Name.Name,
				codes:  map[errCode]string{},
				callee: map[string]bool{},
				pos:    e.Name() + ":" + strconv.Itoa(fset.Position(fn.Pos()).Line),
			}
			if fn.Doc != nil {
				if m := routeComment.FindStringSubmatch(strings.TrimSpace(fn.Doc.Text())); m != nil {
					// A path is written with the sentence's punctuation attached
					// ("...totp/verify.") and one comment carries an illustrative
					// query string; neither is part of the route key.
					p := strings.TrimRight(strings.SplitN(m[3], "?", 2)[0], ".,")
					h.route = m[2] + " " + p
				}
			}
			collect(t, fn.Body, h, e.Name(), fset)
			all = append(all, h)
			// Same-named methods on different receivers (four Delete, three
			// Verify) make the bare name ambiguous, so only the unambiguous
			// names are offered for helper resolution. Every entry in
			// inlinedHelpers is checked against this map by
			// TestInlinedHelpersResolve, so an ambiguous or renamed helper
			// fails rather than resolving to nothing.
			if prev, clash := helpers[fn.Name.Name]; clash {
				if prev != nil {
					helpers[fn.Name.Name] = nil // ambiguous: refuse to guess
				}
				continue
			}
			helpers[fn.Name.Name] = h
		}
	}
	return all, helpers
}

// collect walks a function body recording the codes it writes and the local
// functions it calls.
func collect(t *testing.T, body *ast.BlockStmt, h *handlerFunc, file string, fset *token.FileSet) {
	t.Helper()
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			h.callee[fn.Name] = true
			if fn.Name == "WriteError" {
				if c, ok := writeErrorArgs(t, call, file, fset); ok {
					h.codes[c] = file + ":" + strconv.Itoa(fset.Position(call.Lparen).Line)
				}
			}
		case *ast.SelectorExpr:
			// h.writeError(...) and httputil.WriteError(...) both land here.
			h.callee[fn.Sel.Name] = true
		}
		return true
	})
}

// writeErrorArgs pulls the literal status and code out of a WriteError call.
// A call whose status is not a recognized http.Status constant is a hard
// failure: silently skipping it is how a gate stops covering new code.
func writeErrorArgs(t *testing.T, call *ast.CallExpr, file string, fset *token.FileSet) (errCode, bool) {
	t.Helper()
	if len(call.Args) < 3 {
		return errCode{}, false
	}
	sel, ok := call.Args[1].(*ast.SelectorExpr)
	if !ok {
		return errCode{}, false // a computed status, e.g. the mint refusal mapper
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return errCode{}, false
	}
	status, known := statusNames[sel.Sel.Name]
	if !known {
		t.Errorf("%s:%d writes http.%s, which this gate does not know. Add it to statusNames; "+
			"an unknown status must not be skipped silently.",
			file, fset.Position(call.Lparen).Line, sel.Sel.Name)
		return errCode{}, false
	}
	lit, ok := call.Args[2].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return errCode{}, false // a named constant, e.g. handler.unwrapFailed
	}
	return errCode{status: status, code: strings.Trim(lit.Value, `"`)}, true
}

// resolveCodes returns the codes a handler answers with: its own, plus those of
// any inlined helper it calls.
func resolveCodes(h *handlerFunc, helpers map[string]*handlerFunc) map[errCode]string {
	out := map[errCode]string{}
	for c, pos := range h.codes {
		out[c] = pos
	}
	for name := range h.callee {
		if !inlinedHelpers[name] {
			continue
		}
		helper := helpers[name]
		if helper == nil {
			continue // reported by TestInlinedHelpersResolve
		}
		for c, pos := range helper.codes {
			if _, seen := out[c]; !seen {
				out[c] = pos + " (via " + name + ")"
			}
		}
	}
	return out
}

// errorTables reads docs/api.md and returns, per "METHOD /path" section, the set
// of (status, code) pairs its error table publishes.
func errorTables(t *testing.T, path string) map[string]map[errCode]bool {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]map[errCode]bool{}
	var current string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") {
			// Any heading closes the previous section. Without this, a non-route
			// heading such as "#### Errors shared by every 2FA verify endpoint"
			// would let its own table be counted as the previous endpoint's, and
			// rows the reader can see would silently satisfy a different route.
			current = ""
			if m := sectionHeading.FindStringSubmatch(line); m != nil {
				current = m[1] + " " + m[2]
				if _, seen := out[current]; !seen {
					out[current] = map[errCode]bool{}
				}
			}
			continue
		}
		if current == "" {
			continue
		}
		if m := errorRow.FindStringSubmatch(line); m != nil {
			out[current][errCode{status: mustAtoi(m[1]), code: m[2]}] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// sortedCodes orders the pairs so a failing run reads the same every time.
func sortedCodes(m map[errCode]string) []errCode {
	out := make([]errCode, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].status != out[j].status {
			return out[i].status < out[j].status
		}
		return out[i].code < out[j].code
	})
	return out
}

// mustAtoi converts a status captured by errorRow, which the regexp already
// constrained to three digits.
func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// TestInlinedHelpersResolve holds the one hand-maintained list in this file. An
// entry that no longer names exactly one function in internal/handler resolves
// to nothing, and resolveCodes would then quietly stop contributing that
// helper's codes -- the four 2FA verify tables would lose six rows each and the
// gate would still pass. Renaming completeMFAIfChallenge must break this test,
// not weaken the other one.
func TestInlinedHelpersResolve(t *testing.T) {
	_, helpers := parseHandlers(t, repoRoot(t))
	for name := range inlinedHelpers {
		h, ok := helpers[name]
		if !ok {
			t.Errorf("inlinedHelpers names %q, which no function in %s declares", name, handlerPkg)
			continue
		}
		if h == nil {
			t.Errorf("inlinedHelpers names %q, which is declared more than once in %s; "+
				"the bare name cannot be resolved unambiguously", name, handlerPkg)
			continue
		}
		if len(h.codes) == 0 {
			t.Errorf("inlinedHelpers names %q (%s), which writes no literal error code; "+
				"it contributes nothing and the entry is misleading", name, h.pos)
		}
	}
}
