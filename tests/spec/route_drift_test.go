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
// hardcoded path list means a new HTML page is recognised as non-API without
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
		switch {
		case trimmed == begin:
			inside = true
			continue
		case trimmed == end:
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
