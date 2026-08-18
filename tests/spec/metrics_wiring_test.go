// Metrics wiring gate.
//
// internal/crypto exports accessors whose whole purpose is to be scraped, and
// the commit that added the queue-depth pair said in its own source that the
// mean wait "is the number an alert should be written against". Neither reached
// a collector: NewCollector took three accessors, cmd/vault passed those three,
// and the two new ones were exported, tested, and read by nobody.
//
// That is the shape this release exists to end -- a control present, tested, and
// not on the path it claims to serve -- so the wiring gets a gate rather than a
// promise.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// argon2AccessorsNotScraped lists exported Argon2 accessors that are deliberately
// not metrics, with the reason. Every other one must reach the collector.
var argon2AccessorsNotScraped = map[string]string{
	"Argon2MaxVerifyMemory": "a configuration ceiling read by tests to build a worst-case hash from the real bound, not a runtime signal",
}

// TestEveryArgon2SignalReachesTheCollector fails when internal/crypto exports an
// Argon2 accessor that cmd/vault never hands to the metrics collector.
func TestEveryArgon2SignalReachesTheCollector(t *testing.T) {
	root := repoRoot(t)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, "internal", "crypto", "argon2.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsing argon2.go: %v", err)
	}

	var accessors []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() {
			return true
		}
		if !strings.HasPrefix(fn.Name.Name, "Argon2") {
			return true
		}
		if fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
			return true // takes arguments, so it is not a bare signal read
		}
		if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			return true
		}
		accessors = append(accessors, fn.Name.Name)
		return true
	})

	if len(accessors) == 0 {
		t.Fatal("no exported Argon2 accessor was found in internal/crypto/argon2.go; the " +
			"naming changed and this gate has stopped seeing what it guards")
	}

	wiring := commentFreeSource(t, filepath.Join(root, "cmd", "vault", "main.go"))
	for _, name := range accessors {
		if reason, exempt := argon2AccessorsNotScraped[name]; exempt {
			if reason == "" {
				t.Errorf("%q is exempted from the metrics wiring with no reason given", name)
			}
			continue
		}
		if !containsIdentifier(wiring, "vaultcrypto."+name) {
			t.Errorf("internal/crypto exports %s and cmd/vault/main.go never passes it to the "+
				"metrics collector, so the signal is computed on every request and read by "+
				"nobody. Wire it, or add %q to argon2AccessorsNotScraped with the reason it is "+
				"not a runtime signal.", name, name)
		}
	}
}

// TestTheArgon2ExemptionListHasNoStaleEntries keeps the list above honest, for
// the same reason the fail-open register has the same test: an entry naming a
// function that no longer exists is an exemption a future accessor could inherit
// by reusing the name.
func TestTheArgon2ExemptionListHasNoStaleEntries(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), "internal", "crypto", "argon2.go"))
	for name := range argon2AccessorsNotScraped {
		if !strings.Contains(src, "func "+name+"(") {
			t.Errorf("argon2AccessorsNotScraped names %q, which internal/crypto no longer "+
				"exports. Remove the entry.", name)
		}
	}
}

// hibpAccessorsNotScraped is the same list for internal/service's HIBP client.
// It is empty, and an entry needs the same kind of reason: not "nobody wired it
// yet" but "this is not a runtime signal".
var hibpAccessorsNotScraped = map[string]string{}

// TestEveryHIBPSignalReachesTheCollector is the Argon2 gate one package over.
//
// HIBPClient.ShedCount had exactly the defect the Argon2 gate was written for,
// and the gate could not see it because it only ever looked at internal/crypto.
// The field the counter sits behind says so itself: "Each one is a breached
// password that was accepted, so it is a number an operator has to be able to
// read, not a log line." A log line was all there was.
func TestEveryHIBPSignalReachesTheCollector(t *testing.T) {
	root := repoRoot(t)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, "internal", "service", "hibp.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsing hibp.go: %v", err)
	}

	var accessors []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			return true
		}
		if !isHIBPClientReceiver(fn) {
			return true
		}
		// A bare signal read: no arguments, one result, and no error to handle.
		if fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
			return true
		}
		if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			return true
		}
		if ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || ident.Name == "error" {
			return true
		}
		accessors = append(accessors, fn.Name.Name)
		return true
	})

	if len(accessors) == 0 {
		t.Fatal("no bare signal accessor was found on *HIBPClient in internal/service/hibp.go; " +
			"the shape changed and this gate has stopped seeing what it guards")
	}

	wiring := commentFreeSource(t, filepath.Join(root, "cmd", "vault", "main.go"))
	for _, name := range accessors {
		if reason, exempt := hibpAccessorsNotScraped[name]; exempt {
			if reason == "" {
				t.Errorf("%q is exempted from the metrics wiring with no reason given", name)
			}
			continue
		}
		if !containsIdentifier(wiring, "hibpClient."+name) {
			t.Errorf("internal/service exports HIBPClient.%s and cmd/vault/main.go never passes "+
				"it to the metrics collector. The number is counted on the request path and "+
				"read by nobody, which for a fail-open control means the operator cannot tell "+
				"a working breach check from one that has been shedding every call. Wire it, "+
				"or add %q to hibpAccessorsNotScraped with the reason it is not a runtime "+
				"signal.", name, name)
		}
	}
}

// isHIBPClientReceiver reports whether fn is a method on *HIBPClient.
func isHIBPClientReceiver(fn *ast.FuncDecl) bool {
	if len(fn.Recv.List) == 0 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "HIBPClient"
}

// TestTheHIBPExemptionListHasNoStaleEntries mirrors the Argon2 one.
func TestTheHIBPExemptionListHasNoStaleEntries(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), "internal", "service", "hibp.go"))
	for name := range hibpAccessorsNotScraped {
		if !strings.Contains(src, ") "+name+"(") {
			t.Errorf("hibpAccessorsNotScraped names %q, which internal/service no longer "+
				"exports on HIBPClient. Remove the entry.", name)
		}
	}
}
