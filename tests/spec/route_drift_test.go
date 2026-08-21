// Package spec_test holds the anti-staleness gate for the published API
// specification.
//
// docs/spec.md and docs/api.md are hand-written, and before 1.0.0 they drifted:
// 41 implemented routes were missing from the spec, 15 were documented nowhere,
// and 3 were documented at a path that returns 404. Nothing in scripts/ checked
// either document, so the drift was invisible until someone read both files
// side by side.
//
// These tests close that hole. They parse the real route registrations out of
// internal/server/server.go and internal/adminapi/router.go with go/ast, not
// with a regex over the source text, which would go stale the moment the
// registration style changes, and compare that set against the route
// inventories published in the docs. Drift fails the build in both directions:
// a route in the source that no document lists, and a route a document lists
// that the source does not register.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
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

// routeSources are the files that register every HTTP route in the product.
// A third mux would have to be added here by hand, which is the point: adding a
// new routing surface is a deliberate act, not something that slips in.
var routeSources = []string{
	filepath.Join("internal", "server", "server.go"),
	filepath.Join("internal", "adminapi", "router.go"),
}

// frontendIdent is the identifier through which every non-API route is served:
// the embedded SPA catch-all in server.go and the admin gateway's HTML pages and
// static assets in router.go. Classifying by handler identifier rather than by a
// hardcoded path list means a new HTML page is recognized as non-API without
// anyone remembering to update this test.
const frontendIdent = "frontend"

// nonAPIPrefixes bounds what the frontendIdent rule is allowed to exclude. A
// route served through the frontend handler but living outside these prefixes is
// a misclassification, not an HTML page, and must fail rather than silently
// vanish from the documented surface.
var nonAPIPrefixes = []string{"/", "/admin/", "/admin/login", "/admin/ui/", "/admin/static/"}

// docInventories are the machine-checked route tables. Each is delimited by HTML
// comment sentinels so the surrounding prose can be rewritten freely without
// disturbing the gate.
var docInventories = []struct {
	file  string
	begin string
	end   string
}{
	{filepath.Join("docs", "spec.md"), "<!-- BEGIN ROUTE INVENTORY -->", "<!-- END ROUTE INVENTORY -->"},
	{filepath.Join("docs", "api.md"), "<!-- BEGIN ENDPOINT SUMMARY -->", "<!-- END ENDPOINT SUMMARY -->"},
}

// httpMethods is the set of method tokens net/http.ServeMux patterns may carry.
var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true,
}

// route is one documented or registered endpoint.
type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

// where records the source position a route was registered at, for error
// messages that point at the line rather than at the file.
type where map[route]string

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRouteDriftAgainstDocs is the gate. Every route the binaries register must
// appear in every published inventory, and every inventory row must correspond
// to a registered route.
func TestRouteDriftAgainstDocs(t *testing.T) {
	root := repoRoot(t)
	impl, pos := implementedRoutes(t, root)
	if len(impl) == 0 {
		t.Fatal("parsed zero routes from the source tree: the AST extractor is broken, not the docs")
	}

	for _, inv := range docInventories {
		t.Run(filepath.Base(inv.file), func(t *testing.T) {
			documented := tableRoutes(t, filepath.Join(root, inv.file), inv.begin, inv.end)
			if len(documented) == 0 {
				t.Fatalf("%s: no rows found between %s and %s", inv.file, inv.begin, inv.end)
			}

			for _, r := range sorted(impl) {
				if !documented[r] {
					t.Errorf("undocumented route: %s is registered at %s but has no row in %s.\n"+
						"Add it between %s and %s, or remove the registration.",
						r, pos[r], inv.file, inv.begin, inv.end)
				}
			}
			for _, r := range sorted(documented) {
				if !impl[r] {
					t.Errorf("phantom route: %s has a row in %s but no binary registers it.\n"+
						"A doc that gives a wrong path is worse than no doc: the operator gets a 404 "+
						"and cannot tell whether the feature is missing or the document is.", r, inv.file)
				}
			}
		})
	}
}

// TestAPIReferenceSectionsExist checks the prose half of docs/api.md. Every
// "#### METHOD /path" section heading must name a route that exists. This is the
// check that catches a documented-but-wrong path such as the pre-1.0.0
// POST /admin/clients/{id}/rotate-secret, which never existed under that name.
//
// The converse is deliberately not asserted: the admin gateway's operational
// detail lives in docs/admin-gateway.md, so not every route owes api.md a prose
// section. Coverage of the full surface is enforced by the summary table above.
func TestAPIReferenceSectionsExist(t *testing.T) {
	root := repoRoot(t)
	impl, _ := implementedRoutes(t, root)

	path := filepath.Join(root, "docs", "api.md")
	body, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var found int
	for i, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 3 || fields[0] != "####" || !httpMethods[fields[1]] {
			continue
		}
		found++
		r := route{method: fields[1], path: fields[2]}
		if !impl[r] {
			t.Errorf("docs/api.md:%d documents %s, which no binary registers", i+1, r)
		}
	}
	if found == 0 {
		t.Fatal("docs/api.md: no '#### METHOD /path' endpoint sections found; the heading convention changed")
	}
}

// TestNonAPIRoutesStayOutsideTheAPISurface guards the classifier itself. Routes
// excluded from the documented surface because they are served by the frontend
// handler must live under a known HTML or asset prefix. Without this, wiring an
// API route through a variable that happens to be called "frontend" would delete
// it from the contract silently.
func TestNonAPIRoutesStayOutsideTheAPISurface(t *testing.T) {
	root := repoRoot(t)
	_, nonAPI, pos := parseAllRoutes(t, root)
	if len(nonAPI) == 0 {
		t.Fatal("expected at least the SPA catch-all and the admin HTML pages to be classified non-API")
	}
	for _, r := range sorted(nonAPI) {
		var ok bool
		for _, p := range nonAPIPrefixes {
			// "/" is the SPA catch-all and matches only itself; every other entry
			// is a prefix, so that a new console page under /admin/ui/ is covered
			// without editing this list.
			if r.path == p || (p != "/" && strings.HasPrefix(r.path, p)) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s (%s) is served through the %q handler but sits outside the known HTML/asset prefixes %v; "+
				"if it is an API route it must be documented, not excluded", r, pos[r], frontendIdent, nonAPIPrefixes)
		}
	}
}

// ---------------------------------------------------------------------------
// DPoP wiring
// ---------------------------------------------------------------------------

// serverSource is the mux that mounts the authenticated API surface. The admin
// gateway is a separate binary behind mutual TLS on loopback and issues no
// sender-constrained tokens, so it is not in scope for the check below.
var serverSource = filepath.Join("internal", "server", "server.go")

// TestEveryAuthenticatedRouteCarriesTheDPoPWrapper is the ratchet that keeps
// sender-constraining from decaying back into decoration.
//
// DPoP binds an access token to a key the client proves possession of. The
// middleware can only enforce that on a route it is mounted on, and it was
// mounted on five: the two token endpoints, the 2FA verify wrapper, POST
// /kms/unwrap and POST /mint. Every other authenticated route — the whole of
// /user — took a bound token as an ordinary bearer token, so a stolen token was
// replayed there instead and the constraint bought nothing. One unwrapped route
// is enough to make the whole control decorative.
//
// internal/server/dpop_routes_test.go drives six routes and proves the
// enforcement works on them. It cannot see the seventh. That is the failure mode
// this fix was written to end, recurring in the fix's own test.
//
// The check derives its vocabulary from the source instead of hardcoding
// identifier names. It finds the variables built from middleware.Auth* and from
// middleware.DPoP, then closes over the wrappers that use them, so renaming
// authMw or dpopWrap moves the gate with the code rather than blinding it. A
// route registered through a new wrapper is classified by what that wrapper is
// made of.
func TestEveryAuthenticatedRouteCarriesTheDPoPWrapper(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, serverSource)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverSource, err)
	}

	authIdents := identsBuiltFrom(file, "middleware", func(name string) bool {
		return strings.HasPrefix(name, "Auth")
	})
	dpopIdents := identsBuiltFrom(file, "middleware", func(name string) bool {
		return name == "DPoP"
	})

	if len(authIdents) == 0 {
		t.Fatal("no authentication middleware is built from middleware.Auth* in server.go; the " +
			"construction style changed and this gate has stopped seeing what it guards")
	}
	if len(dpopIdents) == 0 {
		t.Fatal("no DPoP middleware is built from middleware.DPoP in server.go; the construction " +
			"style changed and this gate has stopped seeing what it guards")
	}

	// Close over the local wrappers. authed := func(h) { return authMw(...) }
	// makes authed an authentication wrapper, and it carries DPoP only if its
	// own body reaches something that does.
	closeOverAssignments(file, authIdents)
	closeOverAssignments(file, dpopIdents)

	var authenticated, wrapped int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pattern, _, ok := muxRegistration(call)
		if !ok {
			return true
		}
		handler := call.Args[1]
		if !mentionsAnyIdent(handler, authIdents) {
			return true
		}
		authenticated++
		if mentionsAnyIdent(handler, dpopIdents) {
			wrapped++
			return true
		}
		t.Errorf("%s:%d mounts %q behind authentication with no DPoP wrapper on it. A "+
			"sender-constrained token presented here is accepted as an ordinary bearer token, so a "+
			"stolen one is simply replayed at this route instead — and one such route makes the "+
			"binding decorative everywhere. Wrap the handler the way the authenticated routes "+
			"around it are wrapped, or, if this route must be reachable without a proof, say so "+
			"here in a way the next reader can weigh.",
			serverSource, fset.Position(call.Lparen).Line, pattern)
		return true
	})

	// The floor. A classifier that recognizes nothing reports no violations,
	// which is the same "ok" as a correctly wired mux.
	if authenticated < 20 {
		t.Fatalf("only %d authenticated route registrations were classified in %s; the vault mounts "+
			"far more than that, so the classifier has stopped seeing them and this gate would pass "+
			"over an unwrapped route", authenticated, serverSource)
	}
	t.Logf("%d authenticated route registrations, %d carrying a DPoP wrapper", authenticated, wrapped)
}

// identsBuiltFrom returns the variable names assigned, anywhere in the file,
// from a call to pkg.<Name> where match reports on the name.
//
// Both branches of an if/else count: server.go picks middleware.AuthDynamic or
// middleware.Auth depending on whether a keystore is wired, and a gate that saw
// only one of them would classify half the routes.
func identsBuiltFrom(file *ast.File, pkg string, match func(string) bool) map[string]struct{} {
	out := map[string]struct{}{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			ast.Inspect(as.Rhs[i], func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				base, ok := sel.X.(*ast.Ident)
				if !ok || base.Name != pkg || !match(sel.Sel.Name) {
					return true
				}
				out[ident.Name] = struct{}{}
				return true
			})
		}
		return true
	})
	return out
}

// closeOverAssignments grows a set of identifiers to a fixpoint: a variable
// assigned an expression that mentions a member of the set joins the set.
//
// This is what makes the check survive a refactor. authed, authedChallenge,
// confirmed, docWrite and docRead are all local closures over authMw, and a new
// one added tomorrow is classified by what it is built from rather than by
// somebody remembering to list its name here.
func closeOverAssignments(file *ast.File, set map[string]struct{}) {
	for changed := true; changed; {
		changed = false
		ast.Inspect(file, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range as.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || i >= len(as.Rhs) {
					continue
				}
				if _, already := set[ident.Name]; already {
					continue
				}
				if mentionsAnyIdent(as.Rhs[i], set) {
					set[ident.Name] = struct{}{}
					changed = true
				}
			}
			return true
		})
	}
}

// mentionsAnyIdent reports whether expr contains any of the named identifiers.
func mentionsAnyIdent(expr ast.Expr, names map[string]struct{}) bool {
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if _, hit := names[id.Name]; hit {
				found = true
			}
		}
		return !found
	})
	return found
}

// ---------------------------------------------------------------------------
// Source side: go/ast
// ---------------------------------------------------------------------------

// implementedRoutes returns the API surface: every route the binaries register,
// minus the HTML and static-asset routes.
func implementedRoutes(t *testing.T, root string) (map[route]bool, where) {
	t.Helper()
	api, _, pos := parseAllRoutes(t, root)
	return api, pos
}

// parseAllRoutes parses every routing source with go/ast and splits the
// registrations into the documented API surface and the non-API surface.
func parseAllRoutes(t *testing.T, root string) (api, nonAPI map[route]bool, pos where) {
	t.Helper()
	api, nonAPI, pos = map[route]bool{}, map[route]bool{}, where{}

	for _, rel := range routeSources {
		full := filepath.Join(root, rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, full, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pattern, isFrontend, ok := muxRegistration(call)
			if !ok {
				return true
			}
			r, ok := splitPattern(pattern)
			if !ok || isFrontend {
				// A pattern with no method token is a prefix mount, never a
				// documented endpoint; so is anything the frontend serves.
				if !ok {
					r = route{method: "", path: pattern}
				}
				nonAPI[r] = true
			} else {
				api[r] = true
			}
			p := fset.Position(call.Lparen)
			pos[r] = fmt.Sprintf("%s:%d", rel, p.Line)
			return true
		})
	}
	return api, nonAPI, pos
}

// muxRegistration reports whether call is a mux.Handle/mux.HandleFunc with a
// string-literal pattern, returning the pattern and whether the handler argument
// is served through the frontend identifier.
func muxRegistration(call *ast.CallExpr) (pattern string, isFrontend, ok bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false, false
	}
	if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
		return "", false, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != "mux" {
		return "", false, false
	}
	if len(call.Args) < 2 {
		return "", false, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false, false
	}
	pattern, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false, false
	}
	return pattern, mentionsIdent(call.Args[1], frontendIdent), true
}

// mentionsIdent reports whether expr contains the identifier name anywhere,
// which catches frontend.Handler(), frontend.Dashboard and the wrapped
// http.HandlerFunc(frontend.ServeStatic) alike.
func mentionsIdent(expr ast.Expr, name string) bool {
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// splitPattern splits a Go 1.22+ ServeMux pattern into method and path. Patterns
// without a method token are prefix mounts and are rejected.
func splitPattern(pattern string) (route, bool) {
	method, path, found := strings.Cut(pattern, " ")
	if !found || !httpMethods[method] {
		return route{}, false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return route{}, false
	}
	return route{method: method, path: path}, true
}

// ---------------------------------------------------------------------------
// Doc side
// ---------------------------------------------------------------------------

// tableRoutes extracts routes from the markdown tables between begin and end.
// A row contributes a route when its first cell is an HTTP method and its second
// cell is a path; header and separator rows fall out on their own.
func tableRoutes(t *testing.T, path, begin, end string) map[route]bool {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	out := map[route]bool{}
	var inside bool
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case begin:
			inside = true
			continue
		case end:
			inside = false
			continue
		}
		if !inside || !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 2 {
			continue
		}
		method := cleanCell(cells[0])
		if !httpMethods[method] {
			continue
		}
		p := cleanCell(cells[1])
		if !strings.HasPrefix(p, "/") {
			continue
		}
		out[route{method: method, path: p}] = true
	}
	if inside {
		t.Fatalf("%s: %s has no matching %s", path, begin, end)
	}
	return out
}

// cleanCell strips markdown decoration from a table cell.
func cleanCell(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, `\`, "")
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test working directory")
		}
		dir = parent
	}
}

// sorted returns the routes in a stable order so failures read the same on every
// run and diff cleanly in CI logs.
func sorted(set map[route]bool) []route {
	out := make([]route, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].method < out[j].method
	})
	return out
}

// routeCountInProse matches the sentence in docs/COMPLIANCE.md that quotes the
// size of the documented route surface.
var routeCountInProse = regexp.MustCompile(`all (\d+) mounted routes must appear`)

// TestRouteInventoryCountInProseIsCurrent keeps the one prose claim about the
// size of the API surface honest.
//
// The route inventories themselves are gated in both directions by the tests
// above, so they cannot drift. The sentence in docs/COMPLIANCE.md that tells a
// reader how many routes those gates cover was not gated by anything, and it
// was wrong: it said 51 from 1.0.0 until 1.0.3, over an inventory that held 105
// routes on the day the sentence was written. Nobody counted, because the
// paragraph is next to a description of a mechanism that counts for itself.
//
// A number in prose beside a machine-checked artifact is the worst place for a
// number to be. It reads as the artifact's own output and is maintained by
// hand.
func TestRouteInventoryCountInProseIsCurrent(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)

	inventory, err := os.ReadFile(filepath.Join(root, "docs", "api.md"))
	if err != nil {
		t.Fatalf("read docs/api.md: %v", err)
	}
	rows := countInventoryRows(t, string(inventory),
		"<!-- BEGIN ENDPOINT SUMMARY -->", "<!-- END ENDPOINT SUMMARY -->")
	if rows == 0 {
		t.Fatal("no endpoint rows found in docs/api.md; the scan is broken and the comparison " +
			"below would be against zero")
	}

	doc, err := os.ReadFile(filepath.Join(root, "docs", "COMPLIANCE.md"))
	if err != nil {
		t.Fatalf("read docs/COMPLIANCE.md: %v", err)
	}
	m := routeCountInProse.FindSubmatch(doc)
	if m == nil {
		t.Fatal("docs/COMPLIANCE.md no longer states how many mounted routes the API9 gate " +
			"covers. Either restore the sentence or delete this test; leaving the sentence out " +
			"is fine, leaving it in unchecked is what produced the wrong number.")
	}
	claimed, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse the route count out of docs/COMPLIANCE.md: %v", err)
	}

	if claimed != rows {
		t.Errorf("docs/COMPLIANCE.md says %d mounted routes and docs/api.md lists %d. The "+
			"inventory is machine-checked in both directions; this sentence is not, which is why "+
			"it is the half that was wrong.", claimed, rows)
	}
}

// countInventoryRows counts the endpoint rows between two sentinels. A row is a
// table line whose first cell is a code span, which skips the header and the
// alignment marker without depending on their exact text.
func countInventoryRows(t *testing.T, doc, begin, end string) int {
	t.Helper()

	from := strings.Index(doc, begin)
	to := strings.Index(doc, end)
	if from < 0 || to < 0 || to < from {
		t.Fatalf("sentinels %q / %q not found in order", begin, end)
	}

	count := 0
	for _, line := range strings.Split(doc[from:to], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| `") {
			count++
		}
	}
	return count
}

// inventoryHeadline is the sentence both inventories open with: a total and the
// split between the two binaries.
var inventoryHeadline = regexp.MustCompile(
	`\*\*(\d+) API routes: (\d+) on the main binary, (\d+) on the admin gateway\.\*\*`)

// docsWithRouteInventoryHeadline are the files that publish that sentence.
var docsWithRouteInventoryHeadline = []string{"docs/api.md", "docs/spec.md"}

// readmeRouteClaim is the README's own count, which is written as a table cell
// rather than as the headline sentence and so was checked by nothing.
//
// It read "80 endpoints ... 62 on the main server, 18 on the admin gateway"
// while the table held 105 split 62 and 43 -- the main-binary figure right and
// the admin one short by 25. The front page is where most readers meet that
// number, so it is the worst of the three places to have it wrong.
var readmeRouteClaim = regexp.MustCompile(
	`(\d+) endpoints[^|]*?(\d+) on the main server, (\d+) on the admin gateway`)

// TestRouteInventoryHeadlineMatchesTheTable checks the three numbers in the
// sentence, which nothing did.
//
// TestRouteInventoryCountInProseIsCurrent covers the count in docs/COMPLIANCE.md
// by comparing it against the number of endpoint rows in docs/api.md. It passed
// while the sentence directly above that same table read "103 API routes: 62 on
// the main binary, 41 on the admin gateway" and the table held 105 rows split
// 62 and 43. Two gates, one table, and the sentence between them belonged to
// neither.
//
// The split is checked and not just the total, because a total alone stays
// correct when a route moves from one binary to the other, and which binary
// serves a route is the more consequential half of the claim: the admin gateway
// is a separate deployment behind mTLS.
func TestRouteInventoryHeadlineMatchesTheTable(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	rows := apiDocEndpointRows(t, root)
	if len(rows) < 50 {
		t.Fatalf("only %d endpoint row(s) parsed out of docs/api.md; the scan is broken and "+
			"every comparison below would be against a number nobody computed", len(rows))
	}

	var admin, main int
	for _, path := range rows {
		if strings.HasPrefix(path, "/admin") {
			admin++
			continue
		}
		main++
	}

	var checked int
	for _, rel := range docsWithRouteInventoryHeadline {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		m := inventoryHeadline.FindStringSubmatch(string(body))
		if m == nil {
			t.Errorf("%s no longer opens its route inventory with the count sentence. Either the "+
				"inventory moved or the sentence was reworded; in both cases the numbers it "+
				"carried are no longer checked by anything.", rel)
			continue
		}
		checked++

		for _, want := range []struct {
			label  string
			stated string
			actual int
		}{
			{"total", m[1], len(rows)},
			{"main binary", m[2], main},
			{"admin gateway", m[3], admin},
		} {
			stated, err := strconv.Atoi(want.stated)
			if err != nil {
				t.Errorf("%s: %s count %q is not a number", rel, want.label, want.stated)
				continue
			}
			if stated != want.actual {
				t.Errorf("%s says %d routes on the %s and docs/api.md lists %d. The table is "+
					"generated against the router by TestRouteDrift, so the table is right and "+
					"the sentence is stale.", rel, stated, want.label, want.actual)
			}
		}
	}

	if checked != len(docsWithRouteInventoryHeadline) {
		t.Errorf("the headline was found in %d of %d inventories", checked,
			len(docsWithRouteInventoryHeadline))
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	m := readmeRouteClaim.FindStringSubmatch(string(readme))
	if m == nil {
		t.Error("README.md no longer states how many endpoints the API reference documents. " +
			"It is the count most readers see first, so it is checked here rather than left " +
			"to drift the way it did at 80/62/18 against a table of 105/62/43.")
		return
	}
	for _, want := range []struct {
		label  string
		stated string
		actual int
	}{
		{"total", m[1], len(rows)},
		{"main binary", m[2], main},
		{"admin gateway", m[3], admin},
	} {
		stated, convErr := strconv.Atoi(want.stated)
		if convErr != nil {
			t.Errorf("README.md: %s count %q is not a number", want.label, want.stated)
			continue
		}
		if stated != want.actual {
			t.Errorf("README.md says %d routes on the %s and docs/api.md lists %d",
				stated, want.label, want.actual)
		}
	}
}

// apiDocEndpointRows returns the path from every endpoint row of the docs/api.md
// route table.
func apiDocEndpointRows(t *testing.T, root string) []string {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(root, "docs", "api.md"))
	if err != nil {
		t.Fatalf("read docs/api.md: %v", err)
	}
	row := regexp.MustCompile("(?m)^\\|\\s*`(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)`\\s*\\|\\s*`([^`]+)`")
	matches := row.FindAllStringSubmatch(string(body), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}
