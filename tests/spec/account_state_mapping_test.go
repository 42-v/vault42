// Account-state error mapping gate.
//
// Three service errors say the same thing: the account exists, the credential
// was fine, and policy refuses anyway. ErrAccountBanned, ErrAccountDisabled and
// ErrAccountLocked are what make an operator's ban take effect on a session
// that is already partway through authenticating.
//
// Every transport that can receive one has to map it to a 403 naming the
// policy. Two did not. completeMFAIfChallenge mapped two errors and sent the
// rest to 500, and the refresh handler mapped the three token errors and did
// the same. Both control paths worked perfectly and then reported themselves as
// a server fault: a bulk ban spiked the 5xx rate, and a caller could not tell a
// refusal by policy from a vault42 that was broken.
//
// The audit that found the first one asserted the refresh handler was already
// correct. It was not, which is why this gate derives the transports from the
// code rather than from a list someone believed.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// accountStateErrors are the refusals that must never surface as a 5xx.
var accountStateErrors = []string{"ErrAccountBanned", "ErrAccountDisabled", "ErrAccountLocked"}

// serviceCallsReturningAccountState are the AuthService entry points whose
// bodies can return those errors. Derived below rather than assumed, so a new
// entry point that grows the behavior is included automatically.
func serviceCallsReturningAccountState(t *testing.T, root string) map[string]bool {
	t.Helper()

	path := filepath.Join(root, "internal", "service", "auth.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing internal/service/auth.go: %v", err)
	}
	src := readFileString(t, path)

	out := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || !fn.Name.IsExported() {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		if start < 0 || end > len(src) || start >= end {
			continue
		}
		body := src[start:end]
		for _, e := range accountStateErrors {
			if strings.Contains(body, e) {
				out[fn.Name.Name] = true
				break
			}
		}
	}

	if len(out) == 0 {
		t.Fatal("no AuthService method returns an account-state error; this gate has stopped " +
			"seeing what it guards")
	}
	return out
}

// TestEveryTransportMapsAccountStateRefusals fails when a handler calls a
// service method that can refuse on account state and does not map all three
// refusals.
//
// It works on the enclosing function's source text: what matters is that the
// same function which makes the call also names each error, not where in the
// ladder it sits.
func TestEveryTransportMapsAccountStateRefusals(t *testing.T) {
	root := repoRoot(t)
	returning := serviceCallsReturningAccountState(t, root)

	dir := filepath.Join(root, "internal", "handler")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		// ParseDir's filter signature differs across Go versions; fall back to
		// walking the files this gate cares about.
		t.Fatalf("parsing internal/handler: %v", err)
	}

	var checked int
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			src := readFileString(t, filepath.Join(dir, filepath.Base(name)))

			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				start := fset.Position(fn.Body.Pos()).Offset
				end := fset.Position(fn.Body.End()).Offset
				if start < 0 || end > len(src) || start >= end {
					continue
				}
				body := src[start:end]

				var calls []string
				for method := range returning {
					if strings.Contains(body, "."+method+"(") {
						calls = append(calls, method)
					}
				}
				if len(calls) == 0 {
					continue
				}
				sort.Strings(calls)
				checked++

				var missing []string
				for _, e := range accountStateErrors {
					if !strings.Contains(body, "service."+e) {
						missing = append(missing, e)
					}
				}
				if len(missing) > 0 {
					t.Errorf("%s:%d %s calls %s, which can refuse on account state, and does not "+
						"map %s. Those refusals fall to the default branch and answer 500, so an "+
						"operator's ban takes effect while reporting itself as a server fault and "+
						"the caller cannot tell policy from breakage.",
						filepath.Base(name), fset.Position(fn.Pos()).Line, fn.Name.Name,
						strings.Join(calls, ", "), strings.Join(missing, ", "))
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no handler calls a service method that can refuse on account state; the wiring " +
			"changed and this gate has stopped seeing what it guards")
	}
}
