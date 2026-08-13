// Readiness-probe wiring gate.
//
// handler.ReadyzDeps has a PingCache field and handler.Readyz reports on it,
// and cmd/vault built the struct with PingDB alone. The cache key was therefore
// absent from every /readyz response the server ever served, so a vault running
// on the per-process memory fallback was indistinguishable from one whose Redis
// was healthy.
//
// That mattered because the fallback is silent by design: cache.NewCache
// returns an error, main logs one line and substitutes a memory cache, and
// every cross-replica control quietly becomes per-pod. The login and
// password-reset limiters multiply by the replica count, the KMS unwrap budget
// with them, OAuth state written on one pod cannot be read on another, and the
// TOTP replay guard only blocks a replay that lands on the pod that saw the
// first use. One startup log line was the entire signal.
//
// The gate is on the wiring rather than on the behavior because the behavior
// is already tested: internal/handler proves Readyz reports what it is given.
// What no test in that package can see is whether anything gives it anything.
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

// TestVaultPopulatesEveryReadinessProbe fails when cmd/vault builds a
// ReadyzDeps that leaves a probe unset.
//
// Every field of ReadyzDeps is required rather than a named list, so a probe
// added later is wired or this fails, which is the whole point of checking the
// wiring instead of the fields anyone remembered.
func TestVaultPopulatesEveryReadinessProbe(t *testing.T) {
	root := repoRoot(t)

	want := readyzDepsFields(t, root)
	if len(want) == 0 {
		t.Fatal("handler.ReadyzDeps has no fields; this gate has stopped seeing what it guards")
	}

	path := filepath.Join(root, "cmd", "vault", "main.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing cmd/vault/main.go: %v", err)
	}

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ReadyzDeps" {
			return true
		}
		found = true

		set := map[string]bool{}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				set[key.Name] = true
			}
		}

		for _, field := range want {
			if !set[field] {
				t.Errorf("cmd/vault/main.go:%d builds handler.ReadyzDeps without %s, so /readyz "+
					"never reports on it and an operator cannot tell a lost dependency from a "+
					"healthy one.", fset.Position(lit.Pos()).Line, field)
			}
		}
		return true
	})

	if !found {
		t.Fatal("cmd/vault/main.go builds no handler.ReadyzDeps; readiness reporting was removed " +
			"or restructured and this gate has stopped seeing what it guards")
	}
}

// readyzDepsFields reads the field names off the struct definition, so the gate
// tracks the type rather than a list someone has to remember to update.
func readyzDepsFields(t *testing.T, root string) []string {
	t.Helper()

	path := filepath.Join(root, "internal", "handler", "health.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing health.go: %v", err)
	}

	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "ReadyzDeps" {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				out = append(out, name.Name)
			}
		}
		return false
	})
	return out
}
