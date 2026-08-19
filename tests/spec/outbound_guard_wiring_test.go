// Outbound destination policy wiring gate.
//
// internal/oauth2 enforces the domain rule on the four endpoints a discovery
// document names whether or not a policy is installed: outbound.Policy's nil
// behavior is the strict one, so that half cannot be lost by forgetting to
// wire it. The other half can. The dial-time address check -- the one that
// refuses a name resolving into the instance-metadata range, and refuses a
// redirect that never passed through the endpoint check at all -- lives in a
// transport, and a transport reaches a provider only through SetGuard.
//
// So a provider built without SetGuard keeps the rule and loses the guard, and
// nothing in internal/oauth2 can see the difference: that package's tests
// construct their own providers. The only place the omission is visible is the
// construction site, which is what this reads.
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

// TestVaultGuardsEveryOIDCProviderItBuilds fails when cmd/vault constructs a
// generic OIDC provider and does not install the deployment's outbound policy
// on it.
//
// It matches on the construction rather than on a count, so a second provider
// added later has to be guarded too.
func TestVaultGuardsEveryOIDCProviderItBuilds(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "vault", "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing cmd/vault/main.go: %v", err)
	}

	var constructed, guarded, policyBuilt int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch {
		case pkg.Name == "oauth2" && sel.Sel.Name == "NewOIDCProvider":
			constructed++
		case pkg.Name == "outbound" && sel.Sel.Name == "New":
			policyBuilt++
		case sel.Sel.Name == "SetGuard":
			guarded++
		}
		return true
	})

	if constructed == 0 {
		t.Fatal("cmd/vault/main.go no longer constructs a generic OIDC provider; this gate has stopped " +
			"seeing what it guards. If the construction moved, follow it.")
	}
	if policyBuilt == 0 {
		t.Error("cmd/vault/main.go never builds an outbound.Policy, so the deployment's " +
			"VAULT_OUTBOUND_ALLOWED_HOSTS and VAULT_OUTBOUND_ALLOW_PRIVATE settings reach nothing. " +
			"The endpoint rule still holds; the dial-time address check does not.")
	}
	if guarded < constructed {
		t.Errorf("cmd/vault/main.go constructs %d generic OIDC provider(s) and calls SetGuard %d time(s). "+
			"A provider built without it keeps the endpoint rule and silently loses the dial-time "+
			"check, so a name that resolves into the deployment, or a redirect into the "+
			"instance-metadata range, is dialed.", constructed, guarded)
	}
}
