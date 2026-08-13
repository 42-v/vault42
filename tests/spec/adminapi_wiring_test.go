// Admin-gateway dependency wiring gate.
//
// adminapi.NewHandler takes its repositories positionally, and cmd/admin-gateway
// passed a bare `nil` for one of them while holding a perfectly good instance
// two dozen lines earlier. Nothing failed at build time, because nil is a valid
// value for an interface parameter, and nothing failed at startup, because the
// handler only touches that repository on one route.
//
// The route is POST /admin/users/{id}/lock, the documented first response to a
// suspected account takeover. It wrote the lock, then dereferenced the nil
// repository, and the recovery middleware turned the panic into a 500. So the
// operator saw "lock failed" on an account that was in fact locked, the
// sessions the lock is supposed to revoke were left alive, and no audit row was
// written. An operator who then unlocks to try again hands the account back.
//
// A nil literal in a positional argument list is invisible to every tool this
// repository runs. This gate is the one thing that can see it.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestAdminGatewayPassesEveryRepositoryItBuilds fails when a constructor call in
// cmd/admin-gateway passes an untyped nil where a dependency belongs.
//
// It checks the call rather than a named parameter, because the defect is a
// positional argument nobody counted. Any nil in that list is a dependency the
// process built and then declined to hand over, or one it never built at all,
// and both are worth failing on.
func TestAdminGatewayPassesEveryRepositoryItBuilds(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "admin-gateway", "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing cmd/admin-gateway/main.go: %v", err)
	}

	// Constructors whose arguments are all live dependencies. A nil in any of
	// them is a subsystem silently switched off.
	wantNoNil := map[string]bool{
		"NewHandler":     true,
		"NewAuthHandler": true,
	}

	var checked int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !wantNoNil[sel.Sel.Name] {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "adminapi" {
			return true
		}
		checked++

		for i, arg := range call.Args {
			id, ok := arg.(*ast.Ident)
			if !ok || id.Name != "nil" {
				continue
			}
			t.Errorf("cmd/admin-gateway/main.go:%d passes nil as argument %d to adminapi.%s. "+
				"The handler dereferences its repositories without a nil guard, so the route "+
				"that uses this one panics into a 500 after its side effect has already "+
				"committed. That is how POST /admin/users/{id}/lock came to write the lock, "+
				"fail to revoke the sessions, write no audit row, and report failure.",
				fset.Position(call.Pos()).Line, i+1, sel.Sel.Name)
		}
		return true
	})

	if checked == 0 {
		t.Fatal("cmd/admin-gateway/main.go makes no adminapi constructor call this gate knows " +
			"about; the wiring changed and it has stopped seeing what it guards")
	}
}
