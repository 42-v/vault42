package compliance

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Shared source-scanning helpers for the property-based compliance suites.
//
// The compliance suites in this package assert *properties* of the tree rather
// than the behaviour of one function. A statement-coverage number cannot see
// the failures these catch: a new tls.Config that forgets MinVersion, a new
// repository method that builds SQL by concatenation, a new admin route wired
// to the wrong permission. Each of those is invisible to a unit test of the
// code that already exists, because the defect arrives with code that does not
// exist yet. Scanning the tree is the only assertion shape that survives it.
// =============================================================================

// productionRoots are the directories that ship in the binary. Anything outside
// them (tests/, web/, packages/) is excluded from the structural scans: test
// helpers legitimately do things production code must not.
var productionRoots = []string{"internal", "cmd"}

// parsedFile pairs a parsed AST with the fileset needed to resolve positions.
type parsedFile struct {
	path string // repo-relative, slash-separated
	fset *token.FileSet
	file *ast.File
}

// pos renders a node's position as "path:line", the form used throughout the
// compliance register.
func (p parsedFile) pos(n ast.Node) string {
	return p.path + ":" + itoa(p.fset.Position(n.Pos()).Line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// productionGoFiles parses every non-test .go file under the production roots.
// Test files are excluded by suffix, not by build tag, so a _test.go helper
// cannot smuggle a violation past the scan by being compiled into a package
// the scan otherwise reads.
func productionGoFiles(t *testing.T) []parsedFile {
	t.Helper()
	root := repoRoot(t)

	var out []parsedFile
	for _, sub := range productionRoots {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "mocks" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			out = append(out, parsedFile{path: filepath.ToSlash(rel), fset: fset, file: parsed})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	// A broken walk that finds nothing would turn every structural test into a
	// vacuous pass. That is the failure mode these tests exist to prevent, so
	// the floor is asserted rather than assumed.
	if len(out) < 100 {
		t.Fatalf("production scan parsed only %d files under %v; the walk is broken", len(out), productionRoots)
	}
	return out
}

// compositeLiteralsOfType returns every composite literal in the production
// tree whose type name matches, e.g. "tls.Config" or "http.Cookie".
func compositeLiteralsOfType(files []parsedFile, qualified string) []struct {
	parsedFile
	Lit *ast.CompositeLit
} {
	pkg, name, _ := strings.Cut(qualified, ".")
	var out []struct {
		parsedFile
		Lit *ast.CompositeLit
	}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != pkg || sel.Sel.Name != name {
				return true
			}
			out = append(out, struct {
				parsedFile
				Lit *ast.CompositeLit
			}{pf, lit})
			return true
		})
	}
	return out
}

// litField returns the value expression for a named field of a composite
// literal, and whether it was present.
func litField(lit *ast.CompositeLit, field string) (ast.Expr, bool) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		return kv.Value, true
	}
	return nil, false
}

// selectorName renders an expression as "pkg.Name" when it is a qualified
// identifier, and "" otherwise.
func selectorName(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + sel.Sel.Name
}

// readProductionSource returns the raw bytes of a repo-relative file.
func readProductionSource(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

// readCodeOnly returns a Go file's source with every comment removed. Searching
// raw source for a forbidden token otherwise trips on the comment that explains
// why the token is forbidden, which is the wrong way round.
func readCodeOnly(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(rel))
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, parsed); err != nil {
		t.Fatalf("render %s: %v", rel, err)
	}
	return sb.String()
}
