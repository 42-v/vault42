package attack

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Production regular expressions are compiled with Go's RE2 engine, which is
// linear in the input, so the classical catastrophic-backtracking shapes do not
// apply. Two things can still go wrong, and both are checked here against the
// PATTERNS THE PRODUCT ACTUALLY USES, read out of the source rather than
// retyped: a pattern compiled inside a handler puts automaton construction on
// every request, and a pattern can still be slow enough to matter at the body
// cap.
//
// The earlier version of this file compiled its own copies of four patterns it
// described as "exact copies of the production ones". A production pattern that
// changed for the worse could not have failed it, which makes it a test that
// cannot fail — worse than no test.

type prodRegexp struct {
	pattern  string
	file     string
	line     int
	inFunc   string
	funcName string
}

// collectProductionRegexps walks the non-test Go source under internal/ and
// cmd/ and returns every regexp.MustCompile call with a literal pattern,
// together with whether it sits inside a function body.
func collectProductionRegexps(t *testing.T) []prodRegexp {
	t.Helper()

	var found []prodRegexp
	for _, root := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}

			// Record the extent of every function body so a call can be
			// attributed to one.
			type span struct {
				name       string
				start, end token.Pos
			}
			var funcs []span
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				funcs = append(funcs, span{fn.Name.Name, fn.Body.Pos(), fn.Body.End()})
			}

			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "MustCompile" && sel.Sel.Name != "MustCompilePOSIX" {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "regexp" {
					return true
				}
				if len(call.Args) != 1 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					// A pattern built at runtime is not something this test can
					// time, but it is also not a literal that can silently rot.
					return true
				}
				pattern, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				pos := fset.Position(call.Pos())
				entry := prodRegexp{pattern: pattern, file: path, line: pos.Line}
				for _, f := range funcs {
					if call.Pos() >= f.start && call.Pos() < f.end {
						entry.inFunc = f.name
						entry.funcName = f.name
						break
					}
				}
				found = append(found, entry)
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(found) < 10 {
		t.Fatalf("found only %d literal regexp.MustCompile calls in production source; the walk "+
			"is not seeing them", len(found))
	}
	return found
}

// TestDoS_EveryProductionRegexpIsCompiledOnce is the F14 regression, stated as
// the general rule rather than as one handler's line number. MustCompile builds
// an automaton; building it inside a handler pays that cost on every request
// and buys nothing, because the pattern is a constant.
func TestDoS_EveryProductionRegexpIsCompiledOnce(t *testing.T) {
	t.Parallel()

	for _, re := range collectProductionRegexps(t) {
		if re.inFunc == "" {
			continue // package-level var or const — compiled once at init
		}
		// A function that exists to build the thing once is fine; anything on a
		// request path is not. There is no reliable way to tell them apart from
		// the AST, so the rule is the simple one: no MustCompile inside any
		// function body.
		t.Errorf("%s:%d: regexp.MustCompile inside func %s — hoist it to a package-level var so "+
			"the automaton is built at init instead of per call\n\tpattern: %s",
			re.file, re.line, re.funcName, re.pattern)
	}
}

// TestDoS_ProductionRegexpsAreLinearOnHostileInput times the real patterns
// against inputs sized at the caps a caller can actually reach: the 8 KiB
// global body limit and the 64 KiB service-document limit.
func TestDoS_ProductionRegexpsAreLinearOnHostileInput(t *testing.T) {
	t.Parallel()

	// Shapes chosen to stress the constructs these patterns are built from:
	// character classes, alternation, anchors, and the negated classes the HTML
	// sanitiser uses.
	inputs := []struct {
		name string
		s    string
	}{
		{"8KiB of '<'", strings.Repeat("<", 8*1024)},
		{"8KiB of '<meta '", strings.Repeat("<meta ", 8*1024/6)},
		{"8KiB of 'a'", strings.Repeat("a", 8*1024)},
		{"8KiB of '.'", strings.Repeat(".", 8*1024)},
		{"8KiB of '-'", strings.Repeat("-", 8*1024)},
		{"8KiB of 'a.'", strings.Repeat("a.", 4*1024)},
		{"8KiB of '@'", strings.Repeat("@", 8*1024)},
		{"64KiB of '{'", strings.Repeat("{", 64*1024)},
		{"64KiB alphanumeric", strings.Repeat("aA0-_.", 64*1024/6)},
	}

	// Generous: this is a guard against a swap to a backtracking engine or a
	// pattern that is quadratic in practice, not a benchmark. A machine under
	// heavy parallel load must not turn it red.
	const budget = 250 * time.Millisecond

	for _, re := range collectProductionRegexps(t) {
		compiled, err := regexp.Compile(re.pattern)
		if err != nil {
			t.Errorf("%s:%d: production pattern does not compile: %v", re.file, re.line, err)
			continue
		}
		for _, in := range inputs {
			start := time.Now()
			_ = compiled.MatchString(in.s)
			_ = compiled.FindAllStringIndex(in.s, 64)
			if elapsed := time.Since(start); elapsed > budget {
				t.Errorf("%s:%d took %v on %s, over the %v budget\n\tpattern: %s",
					re.file, re.line, elapsed, in.name, budget, re.pattern)
			}
		}
	}
}
