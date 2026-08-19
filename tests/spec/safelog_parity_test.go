package spec_test

// The log sanitiser must exist once, and any copy of it must be identical.
//
// httputil.SafeLogValue is the vault's. cmd/bridge used to carry a private copy,
// because that binary is deliberately stdlib-only and imports nothing under
// internal/ (cmd/bridge/main.go says so). Two copies of a security control are
// tolerable only while something keeps them the same, and nothing did: commit
// 27b1735 widened the vault's set to neutralize U+2028 and U+2029 -- a log
// shipper splits records on those as readily as on a newline -- and the bridge
// copy, written later, still mapped only the C0/C1 ranges and DEL. Bridge log
// lines stayed forgeable by a value an attacker controls, which is the CWE-117
// gap the original fix closed, reopened under a second name.
//
// The copy is gone now. It had no caller: every client-chosen value reaching a
// bridge log line goes through obfuscatedIP, which returns a masked network or
// the constant "invalid_ip", or through a %q verb, which escapes exactly the
// characters the sanitiser mapped. What it had instead was a test, so a function
// that shipped nothing carried five green assertions.
//
// This gate therefore stopped being a comparison of two named files and became a
// search: it finds every private rune-mapping sanitiser under cmd/ and holds it
// to the vault's set. At zero copies it has nothing to compare, so the vault's
// own extraction is asserted unconditionally -- that half is the premise, and a
// premise that can quietly return nothing is how a gate becomes vacuous.
//
// Nothing can call the bridge's unexported code and the bridge cannot import
// internal/, so the comparison lives here, the one package allowed to read both
// sides, and it reads them as source rather than calling them -- the same
// arrangement as decoy_paths_test.go.

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// canonicalSanitizer is the one implementation that ships, and the set every
// copy is held to.
var canonicalSanitizer = struct{ file, fn string }{
	filepath.Join("internal", "httputil", "safelog.go"), "SafeLogValue",
}

// sanitizerRoots are searched for a private copy. cmd/ is where a stdlib-only
// binary would write one; internal/ can import the canonical function and has no
// reason to.
var sanitizerRoots = []string{"cmd"}

func TestNoPrivateCopyOfTheLogSanitizerDriftsFromTheVaults(t *testing.T) {
	root := repoRoot(t)

	// The premise. If the extractor stops finding the canonical rune set, every
	// comparison below is against an empty list and passes whatever a copy does.
	want := safelogCases(t, filepath.Join(root, canonicalSanitizer.file), canonicalSanitizer.fn)
	if len(want) == 0 {
		t.Fatalf("%s: extracted no rune cases from %s; the extractor is broken, not the code",
			canonicalSanitizer.file, canonicalSanitizer.fn)
	}

	copies := findRuneMappers(t, root, sanitizerRoots)
	for _, c := range copies {
		got := safelogCases(t, filepath.Join(root, c.file), c.fn)
		if !equalStrings(want, got) {
			t.Errorf("%s %s neutralizes a different set of runes from %s %s.\n"+
				"  canonical: %v\n"+
				"  copy:      %v\n"+
				"Two copies of a sanitiser that drift are worse than one, because the drift is "+
				"invisible from either side. Widen the narrower one, or delete the copy if that "+
				"package is allowed to import internal/httputil.",
				c.file, c.fn, canonicalSanitizer.file, canonicalSanitizer.fn, want, got)
		}
	}
	t.Logf("%d rune-mapping sanitizer(s) found under %v, checked against %s",
		len(copies), sanitizerRoots, canonicalSanitizer.fn)
}

// sanitizerImpl is one private rune-mapping function found by the search.
type sanitizerImpl struct{ file, fn string }

// findRuneMappers returns every top-level function under the given roots whose
// body is built around a strings.Map with a rune switch -- the shape a log
// sanitiser takes, found by what it does rather than by what it is called, so a
// copy under a different name is still a copy.
func findRuneMappers(t *testing.T, root string, roots []string) []sanitizerImpl {
	t.Helper()

	var out []sanitizerImpl
	for _, sub := range roots {
		err := filepath.WalkDir(filepath.Join(root, sub), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Body == nil {
					continue
				}
				if mapsRunesInASwitch(fn) {
					out = append(out, sanitizerImpl{file: filepath.ToSlash(rel), fn: fn.Name.Name})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].fn < out[j].fn
	})
	return out
}

// mapsRunesInASwitch reports whether a function calls strings.Map with a
// closure that switches -- which is what every version of this sanitiser, in
// both packages, has looked like.
func mapsRunesInASwitch(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Map" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "strings" {
			return true
		}
		for _, arg := range call.Args {
			lit, isFunc := arg.(*ast.FuncLit)
			if !isFunc {
				continue
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				if _, isSwitch := inner.(*ast.SwitchStmt); isSwitch {
					found = true
				}
				return !found
			})
		}
		return !found
	})
	return found
}

// safelogCases returns the printed case expressions of the switch inside the
// named function's strings.Map closure, sorted, so the comparison is over the
// rune set rather than over the order it happens to be written in.
func safelogCases(t *testing.T, path, fnName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	fn := findTopLevelFunc(file, fnName)
	if fn == nil {
		t.Fatalf("%s no longer declares %s", path, fnName)
	}

	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		clause, ok := n.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 {
			return true
		}
		for _, expr := range clause.List {
			var buf strings.Builder
			if err := printer.Fprint(&buf, fset, expr); err != nil {
				t.Fatalf("print case expression in %s: %v", path, err)
			}
			out = append(out, strings.Join(strings.Fields(buf.String()), " "))
		}
		return true
	})
	sort.Strings(out)
	return out
}

func findTopLevelFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
