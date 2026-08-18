package spec_test

// The log sanitiser exists twice.
//
// httputil.SafeLogValue is the vault's; cmd/bridge carries a private copy
// because that binary is deliberately stdlib-only and imports nothing under
// internal/ (cmd/bridge/main.go says so). Two copies of a security control are
// tolerable only while something keeps them the same, and nothing did: commit
// 27b1735 widened the vault's set to neutralize U+2028 and U+2029 — a log
// shipper splits records on those as readily as on a newline — and the bridge
// copy, written later, still mapped only the C0/C1 ranges and DEL. Bridge log
// lines stayed forgeable by a value an attacker controls, which is the CWE-117
// gap the original fix closed, reopened under a second name.
//
// Neither package can see the other: the bridge cannot import internal/, and
// nothing can call its unexported copy. So the comparison lives here, the one
// package allowed to read both sides, and it reads them as source rather than
// calling them — the same arrangement as decoy_paths_test.go.

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The two implementations. Each is a func whose body contains exactly one
// strings.Map call, and the rune set is the switch inside that call's closure.
var safelogImpls = []struct {
	file string
	fn   string
}{
	{filepath.Join("internal", "httputil", "safelog.go"), "SafeLogValue"},
	{filepath.Join("cmd", "bridge", "proxy.go"), "safeLogValue"},
}

func TestTheTwoLogSanitizersNeutralizeTheSameRunes(t *testing.T) {
	root := repoRoot(t)

	sets := make([][]string, 0, len(safelogImpls))
	for _, impl := range safelogImpls {
		cases := safelogCases(t, filepath.Join(root, impl.file), impl.fn)
		if len(cases) == 0 {
			t.Fatalf("%s: extracted no rune cases from %s; the extractor is broken, not the code",
				impl.file, impl.fn)
		}
		sets = append(sets, cases)
	}

	want, got := sets[0], sets[1]
	if !equalStrings(want, got) {
		t.Errorf("the two log sanitizers no longer neutralize the same runes.\n"+
			"  %s %s: %v\n"+
			"  %s %s: %v\n"+
			"Two copies of a sanitiser that drift are worse than one, because the drift is invisible "+
			"from either side. Widen the narrower one, or delete the copy if cmd/bridge is ever "+
			"allowed to import internal/httputil.",
			safelogImpls[0].file, safelogImpls[0].fn, want,
			safelogImpls[1].file, safelogImpls[1].fn, got)
	}
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
