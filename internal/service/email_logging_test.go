package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// emailBearingIdents are the local variable names that hold a full email
// address in this package. Logging one of them raw puts a user's address in
// plaintext into whatever collects the logs.
//
// The list is names rather than types because Go has no email type here; every
// one of these is a plain string. It is deliberately short: a name added later
// that holds an address and is not on this list will not be caught, which is
// why the gate is a floor rather than a proof.
var emailBearingIdents = map[string]bool{
	"to":        true,
	"emailAddr": true,
	"email":     true,
	"addr":      true,
}

// TestNoLogLineCarriesARawEmailAddress is the regression for two log lines that
// disagreed with the rest of the file about whether an address is PII.
//
// The package already decided this question. maskEmail exists, and the same
// address that reached log.Printf raw at auth.go:380 was masked 37 lines
// earlier before going into the audit metadata. IPs get the same treatment
// through httputil.ObfuscatedIP in the lockout fallback logs. Only the two
// mail-send failure paths were missed.
//
// Those are exactly the lines that fire during an incident. A mail provider
// outage writes one per registration attempt, so the failure mode is a burst of
// user email addresses into the log aggregator at the moment everyone is
// looking at it, from a service that ships a PRIVACY.md.
//
// The check is a shallow AST walk rather than a regex so a rename of the log
// helper does not silently disable it, and it names the variable in the failure
// so the fix is obvious.
func TestNoLogLineCarriesARawEmailAddress(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing internal/service: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no package parsed; this gate cannot prove anything against an empty set")
	}

	var checked int
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "log" {
					return true
				}
				checked++

				// Only direct identifier arguments. maskEmail(to) is a CallExpr
				// and is therefore correct by construction here.
				for _, arg := range call.Args {
					id, ok := arg.(*ast.Ident)
					if !ok || !emailBearingIdents[id.Name] {
						continue
					}
					t.Errorf("%s:%d logs %q raw. It holds a full email address, and this package "+
						"masks addresses everywhere else (maskEmail) before they reach a log or "+
						"an audit record. Wrap it: maskEmail(%s).",
						filepath.Base(name), fset.Position(id.Pos()).Line, id.Name, id.Name)
				}
				return true
			})
		}
	}

	if checked == 0 {
		t.Fatal("internal/service makes no log calls; this gate has stopped seeing what it guards")
	}
}

// TestMaskEmailKeepsTheAddressUnrecoverable pins the masking itself, since every
// call site above is only as good as what it calls.
func TestMaskEmailKeepsTheAddressUnrecoverable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice@example.com", "a***@example.com"},
		{"a@example.com", "a***@example.com"},
		{"", "***"},
		{"no-at-sign", "***"},
		{"@example.com", "***"},
		{"very.long.local.part@example.com", "v***@example.com"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := maskEmail(tc.in)
			if got != tc.want {
				t.Errorf("maskEmail(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// The domain is deliberately kept: an operator debugging a mail
			// outage needs to know whether one provider is failing. The local
			// part is what identifies a person.
			if len(tc.in) > 1 && strings.Contains(got, tc.in) {
				t.Errorf("maskEmail(%q) = %q, which still contains the whole input", tc.in, got)
			}
		})
	}
}
