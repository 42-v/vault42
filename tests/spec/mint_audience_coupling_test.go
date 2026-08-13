// Mint-audience coupling gate.
//
// POST /mint is a subject-assertion signing oracle: it signs a subject vault42
// never authenticated. What stops a minted token from being replayed as a
// session against vault42 itself is that it carries a different audience, so
// vault42's own audience validation rejects it. Without that, token_type is the
// single remaining control between an assertion and a session, which is not
// enough for a signing oracle.
//
// Two places enforce it. config.Validate refuses VAULT_MINT_AUDIENCE equal to
// VAULT_ORIGIN, and mint.New refuses a mint audience equal to the vault42
// issuer. Both compare against the ISSUER side. Neither compares against the
// audience vault42 actually stamps on its own access tokens.
//
// Today those are the same string, because cmd/vault constructs the token
// service as NewTokenService(key, kid, cfg.Origin, cfg.Origin, ...), passing
// Origin as both issuer and audience. So the check works, by coincidence of one
// call site rather than by anything that says so.
//
// Giving the token audience its own configuration is an ordinary change to
// want, and the moment someone makes it, VAULT_MINT_AUDIENCE could equal the
// token audience while still differing from the issuer. Every existing check
// would pass and every minted token would authenticate against vault42 as the
// subject it names.
//
// This gate is the sentence nobody had written down: the mint audience checks
// are only sound while the token audience equals the issuer. If that stops
// being true, this fails and points at the checks that need a second comparison.
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

// TestTokenAudienceIsStillTheIssuer fails when cmd/vault stops passing the same
// expression as issuer and audience to the token service.
//
// It reads the call rather than the running config, because the coupling is a
// property of the wiring: a deployment cannot make these differ today, and the
// point is to catch the commit that lets it.
func TestTokenAudienceIsStillTheIssuer(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "vault", "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing cmd/vault/main.go: %v", err)
	}

	src := readFileString(t, path)

	var found int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewTokenService" {
			return true
		}
		found++

		// NewTokenService(key, kid, issuer, audience, ...): positions 2 and 3.
		if len(call.Args) < 4 {
			t.Fatalf("NewTokenService is called with %d arguments; its signature changed and this "+
				"gate can no longer tell the issuer from the audience", len(call.Args))
		}

		issuer := mintExprText(t, src, fset, call.Args[2])
		audience := mintExprText(t, src, fset, call.Args[3])

		if issuer != audience {
			t.Errorf("cmd/vault/main.go:%d now passes issuer %q and audience %q to the token "+
				"service. Both mint-audience checks compare only against the ISSUER "+
				"(config.Validate against VAULT_ORIGIN, mint.New against cfg.Issuer), and they "+
				"were sound only while these two were the same string. A VAULT_MINT_AUDIENCE "+
				"equal to %q would now pass every check and every minted token would "+
				"authenticate against vault42 as the subject it names. Add the second "+
				"comparison before landing this.",
				fset.Position(call.Pos()).Line, issuer, audience, audience)
		}
		return true
	})

	if found == 0 {
		t.Fatal("cmd/vault/main.go constructs no token service; the wiring changed and this gate " +
			"has stopped seeing what it guards")
	}
}

// mintExprText returns the source text of an expression, so the check compares what
// was written rather than a resolved value.
func mintExprText(t *testing.T, src string, fset *token.FileSet, e ast.Expr) string {
	t.Helper()

	start := fset.Position(e.Pos()).Offset
	end := fset.Position(e.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		t.Fatalf("expression offsets [%d,%d) fall outside the source", start, end)
	}
	return src[start:end]
}
