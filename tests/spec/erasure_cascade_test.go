// Erasure-cascade wiring gate.
//
// ErasureService reaches the service-document store only when SetServiceDocs
// has been called. The setter is optional at compile time and mandatory in
// fact: documents other services filed about a user are personal data under
// GDPR Art. 4(1) whoever authored them, so an erasure that skips them is an
// Art. 17 failure.
//
// It was skipped. internal/server/server.go wired it; cmd/admin-gateway did
// not, so DELETE /admin/users/{id}, the path an Art. 17 request is normally
// actioned through, returned success and wrote an AccountErased audit row while
// every service document survived. Nothing failed, because nothing was checked:
// an optional setter that must always be called is invisible to the compiler
// and to every test that exercises only the wired path.
//
// This closes that with the same instrument route_drift_test.go uses. It parses
// real call sites with go/ast rather than grepping, so a change in construction
// style is caught rather than silently passing.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cascadeConstructor is the function whose result must be completed by a setter
// call before it is used.
const cascadeConstructor = "NewErasureService"

// cascadeSetters are the calls that must accompany every construction. Adding a
// store to the erasure cascade means adding its setter here, which is the point:
// the list is the specification, and forgetting to extend it is a review-visible
// omission rather than a silent data-retention bug.
//
// SetLoginCountries joined the list when migration 030 gave the cascade a way to
// reach auth.login_countries. That store has no "disabled" deployment — the table
// is unconditional — so an ErasureService built without it retains a user's
// login-country history on every path that construction serves.
var cascadeSetters = []string{"SetServiceDocs", "SetLoginCountries"}

// goFilesUnder returns every non-test .go file beneath root, skipping the
// directories that are not ours to assert on.
func goFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dist", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

// TestEveryErasureServiceGetsTheFullCascade fails when a production call site
// builds an ErasureService without completing its cascade.
//
// The check is per enclosing function rather than per file: construction and
// wiring belong together, and a setter called in some other function on a value
// this one cannot see is not the same guarantee.
func TestEveryErasureServiceGetsTheFullCascade(t *testing.T) {
	root := repoRoot(t)

	var sites int
	for _, dir := range []string{"cmd", "internal"} {
		for _, path := range goFilesUnder(t, filepath.Join(root, dir)) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}

				var constructedAt token.Pos
				seen := map[string]bool{}
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case cascadeConstructor:
						constructedAt = call.Pos()
					default:
						seen[sel.Sel.Name] = true
					}
					return true
				})

				if !constructedAt.IsValid() {
					return true
				}
				sites++

				rel, err := filepath.Rel(root, path)
				if err != nil {
					rel = path
				}
				for _, setter := range cascadeSetters {
					if !seen[setter] {
						t.Errorf("%s:%d %s builds an ErasureService but never calls %s. "+
							"That store is not reached by the cascade, so an erasure through this "+
							"path reports success while retaining personal data.",
							rel, fset.Position(constructedAt).Line, fn.Name.Name, setter)
					}
				}
				return true
			})
		}
	}

	// A gate that silently matches nothing is worse than no gate: if the
	// constructor is renamed, every call site vanishes from this check at once.
	if sites < 2 {
		t.Fatalf("found %d ErasureService construction site(s); expected at least 2 "+
			"(internal/server and cmd/admin-gateway). Either %s was renamed or this "+
			"gate has stopped seeing the code it guards.", sites, cascadeConstructor)
	}
}
