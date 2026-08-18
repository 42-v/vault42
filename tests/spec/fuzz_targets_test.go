// Every fuzz target has to reach shipped code.
//
// tests/fuzz/fuzz_email_test.go fuzzed an isValidEmail defined in the same file,
// under a comment reading "same logic as service/auth.go". Nothing enforced the
// equivalence, and it was not true: auth.go has never had an isValidEmail and
// has always called internal/sanitize.Email. The target's only assertion was
// that the local copy did not panic, so it ran green forever over code that
// ships nowhere while the real sanitiser went unfuzzed.
//
// The fix landed as a second target, FuzzSanitizeEmail, and left the dummy
// running. Adding a correct target does not make an incorrect one correct; both
// were counted by the fuzz job and only one of them tested the product.
//
// So this is the rule rather than the instance. A target that imports no vault42
// package cannot be fuzzing vault42, and a target that imports one and never
// calls through it is fuzzing its own helpers. Both fail here, by name, with the
// package they would have to reach.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const vaultModule = "github.com/42-v/vault42/"

func TestEveryFuzzTargetReachesShippedCode(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "tests", "fuzz")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tests/fuzz: %v", err)
	}

	targets, offenders := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse tests/fuzz/%s: %v", entry.Name(), err)
		}

		// The local names under which shipped packages are reachable in this
		// file: the alias where one is given, the last path element otherwise.
		shipped := map[string]string{}
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !strings.HasPrefix(p, vaultModule) {
				continue
			}
			name := p[strings.LastIndexByte(p, '/')+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			shipped[name] = p
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "Fuzz") || fn.Body == nil {
				continue
			}
			targets++

			if len(shipped) == 0 {
				t.Errorf("tests/fuzz/%s: %s imports no %s package, so whatever it fuzzes is "+
					"defined in the test tree and ships nowhere. Point it at the production "+
					"function, or delete it: a target over a local copy is a green tick with "+
					"no subject.", entry.Name(), fn.Name.Name, vaultModule)
				offenders++
				continue
			}

			var reached string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if imported, ok := shipped[pkg.Name]; ok {
					reached = imported + "." + sel.Sel.Name
					return false
				}
				return true
			})
			if reached == "" {
				names := make([]string, 0, len(shipped))
				for _, p := range shipped {
					names = append(names, p)
				}
				t.Errorf("tests/fuzz/%s: %s imports %s and never calls through it, so the "+
					"import satisfies a reader and the body fuzzes something else. Call the "+
					"production function the target is named for.",
					entry.Name(), fn.Name.Name, strings.Join(names, ", "))
				offenders++
			}
		}
	}

	// A floor. The suite has carried more than ten targets since 1.0.0, so a
	// count near zero means the directory moved or the parse stopped finding
	// them, and every assertion above passed by running on nothing.
	if targets < 10 {
		t.Fatalf("only %d fuzz targets were parsed under tests/fuzz. The suite has more; "+
			"this gate is reading the wrong directory or the wrong function shape, and it "+
			"would report a clean suite either way.", targets)
	}
	t.Logf("%d fuzz targets checked, %d do not reach shipped code", targets, offenders)
}
