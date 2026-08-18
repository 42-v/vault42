// The anti-drift gate for DSN redaction.
//
// pgx puts the DSN it dialed into its connect errors, so every binary that logs
// one raw prints the database password. The redaction that stops it lives in
// internal/httputil.RedactDSN, and that function's doc comment says out loud
// that it is the shared home for a pattern cmd/vault and cmd/admin-gateway each
// used to carry a private copy of.
//
// The copies were the problem the helper was written to solve, and they outlived
// it. Three regexes with one job drift silently: making the shared pattern
// case-insensitive - a strict improvement, and green in every package - left both
// copies matching only a lowercase scheme, so `POSTGRES://user:pw@host` was
// redacted by cmd/recover and printed in full by the other two binaries. Nothing
// went red, because nothing anywhere asserted that the three agreed.
//
// This gate is the assertion. It parses every non-test Go file under cmd/ and
// internal/ and fails if a DSN-shaped regexp literal is compiled anywhere except
// in the one file that owns it. A future copy-paste has to delete this test to
// land, which is a deliberate act rather than an oversight.
//
// It is read-only and never writes to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// redactionOwner is the one file allowed to compile a DSN-shaped pattern.
var redactionOwner = filepath.Join("internal", "httputil", "dberror.go")

// dsnMarkers are the substrings that make a regexp literal DSN-shaped. A pattern
// mentioning a PostgreSQL URL scheme is either the redaction or something close
// enough to it that a reviewer should look; either way it does not belong in a
// second file.
var dsnMarkers = []string{"postgres://", "postgresql://", "postgres(?:ql)?://", "postgres(ql)?://"}

// scanRoots are the trees that hold the binaries and the shared packages. The
// test tree is deliberately excluded below: a test may legitimately compile a
// DSN pattern of its own to prove something about the real one.
var scanRoots = []string{"cmd", "internal"}

func TestDSNRedactionHasOneDefinition(t *testing.T) {
	root := repoRoot(t)

	type finding struct {
		file    string
		line    int
		pattern string
	}
	var found []finding

	for _, scanRoot := range scanRoots {
		base := filepath.Join(root, scanRoot)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if rel == redactionOwner {
				return nil
			}

			fset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, unquoteErr := strconv.Unquote(lit.Value)
				if unquoteErr != nil {
					return true
				}
				for _, marker := range dsnMarkers {
					if strings.Contains(value, marker) && looksLikeAPattern(value) {
						found = append(found, finding{
							file:    rel,
							line:    fset.Position(lit.Pos()).Line,
							pattern: value,
						})
						break
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", scanRoot, err)
		}
	}

	for _, f := range found {
		t.Errorf("%s:%d compiles a DSN-shaped pattern of its own:\n\t%s\n"+
			"There is one redaction, in %s, and it is shared precisely so the copies cannot drift. "+
			"cmd/vault and cmd/admin-gateway each carried one of these, and an improvement to the shared "+
			"pattern left both behind with the whole suite green - which is the database password reaching "+
			"a log in two binaries and nothing saying so. Call httputil.RedactDSN.",
			f.file, f.line, f.pattern, redactionOwner)
	}
}

// looksLikeAPattern separates a regular expression from an ordinary string that
// happens to contain a DSN - a doc example, a default value, a test fixture URL.
// A regex for this job carries at least one character class or quantifier;
// without this the gate would fire on every mention of a connection string in
// the tree and would be turned off within a week.
func looksLikeAPattern(s string) bool {
	for _, metachar := range []string{"[^", "[a-", "(?:", "(?i)", ".*", ".+", "\\s", "\\S", "]+", "]*"} {
		if strings.Contains(s, metachar) {
			return true
		}
	}
	return false
}

// The gate is only worth having if the file it exempts still holds the
// redaction. An exemption pointing at a file that no longer compiles a pattern
// would let every other copy through while still passing.
func TestDSNRedactionOwnerStillHoldsThePattern(t *testing.T) {
	path := filepath.Join(repoRoot(t), redactionOwner)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", redactionOwner, err)
	}

	var patterns int
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, unquoteErr := strconv.Unquote(lit.Value)
		if unquoteErr != nil {
			return true
		}
		for _, marker := range dsnMarkers {
			if strings.Contains(value, marker) && looksLikeAPattern(value) {
				patterns++
				return true
			}
		}
		return true
	})

	if patterns == 0 {
		t.Errorf("%s no longer compiles a DSN-shaped pattern, so the exemption in "+
			"TestDSNRedactionHasOneDefinition points at nothing and that gate now passes vacuously. "+
			"If the redaction moved, move the exemption with it.", redactionOwner)
	}
}
