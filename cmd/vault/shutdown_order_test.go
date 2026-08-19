package main

// The shutdown order of the four teardown defers in main, read off the source.
//
// Defers run LIFO, so the registration order in the file IS the shutdown order,
// reversed. Nothing else states it: internal/deferwork documents the cache and
// database half of the rule ("It must run BEFORE the cache and the database pool
// are closed ... register the defer after theirs") and the audit logger was
// never included in it, so LIFO closed the audit logger first and a row written
// by a job still on the pool -- notifyNewCountry writes one -- went into a buffer
// nothing would flush again.
//
// A runtime test cannot see this: the ordering only shows up as a missing row
// during a shutdown that happens to race a pool job, which is exactly the shape
// of thing that passes in CI and loses evidence in production.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// shutdownDefers are the teardown defers of main, named by the identifier that
// makes each recognizable, in the order they MUST be registered.
//
// Reversed, this is the order they run: deferwork first, then the audit logger,
// then the cache, then the database pool. Each entry depends on everything
// before it still being open.
var shutdownDefers = []struct {
	ident string
	why   string
}{
	{"db", "the pool behind every repository; closed last"},
	{"appCache", "a deferred send writes its verification token here before mailing the link"},
	{"auditLogger", "notifyNewCountry writes an audit row from a deferwork job"},
	{"deferwork", "the pool whose jobs need all three above; drained first"},
}

func TestShutdownDefersRunInDependencyOrder(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(mainSourceDir(t), "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	mainFn := findFunc(file, "main")
	if mainFn == nil {
		t.Fatal("cmd/vault/main.go no longer declares func main")
	}

	// The order the recognized defers were registered in.
	var got []string
	var lines []int
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		for _, want := range shutdownDefers {
			if mentions(d, want.ident) {
				got = append(got, want.ident)
				lines = append(lines, fset.Position(d.Defer).Line)
				break
			}
		}
		return true
	})

	want := make([]string, 0, len(shutdownDefers))
	for _, d := range shutdownDefers {
		want = append(want, d.ident)
	}

	if len(got) != len(want) {
		t.Fatalf("found %v at lines %v, want exactly one defer for each of %v; a teardown defer was "+
			"added, removed or renamed and this gate cannot see it any more", got, lines, want)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("teardown defers are registered %v (lines %v), want %v.\n"+
			"Defers run LIFO, so registration order reversed is shutdown order: %s must be torn down "+
			"before the things it needs. Each entry's reason is in shutdownDefers.",
			got, lines, want, want[len(want)-1])
	}
}

// mentions reports whether the defer statement contains the identifier
// anywhere, which is what distinguishes the four from each other and from the
// unrelated defers (drainCancel, ticker stops) inside them.
func mentions(d *ast.DeferStmt, name string) bool {
	var found bool
	ast.Inspect(d, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

func findFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// mainSourceDir is the directory this package's source lives in. The test binary
// runs with its working directory set there, so it is simply the cwd — stated
// through a helper so a failure to find main.go reads as a broken assumption
// rather than a broken parse.
func mainSourceDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Fatalf("main.go is not in the test working directory %s: %v", dir, err)
	}
	return dir
}
