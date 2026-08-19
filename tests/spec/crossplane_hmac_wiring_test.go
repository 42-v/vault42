// Cross-plane HMAC_SECRET wiring gate.
//
// vault42 ships as two binaries that hold their own copy of HMAC_SECRET and
// never see each other's configuration. identity.profiles, objects.blobs and
// objects.service_documents are all addressed by a subject pseudonym HMAC'd
// under that secret, so two planes holding different secrets erase by strings
// no row ever carried: zero rows cleared, no error, an AccountErased audit row,
// and the data still in the database.
//
// config.VerifyHMACPlaneAgreement is what stops such a deployment from
// starting, and like SetServiceDocs before it, it is a call that is optional to
// the compiler and mandatory in fact. A refactor of either main() can drop it
// and every test in the tree still passes, because what it guards against is a
// configuration no test configures by accident.
//
// So the gate is structural, in the same instrument erasure_cascade_test.go
// uses: any cmd/ binary that reads config's HMACSecret must also call the
// check. Read-only; it never writes to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// crossPlaneSecretField is the config field that makes a binary a plane:
	// it derives subject pseudonyms, so it has to agree with the other one.
	crossPlaneSecretField = "HMACSecret"
	// crossPlaneCheck is the call that must accompany it.
	crossPlaneCheck = "VerifyHMACPlaneAgreement"
)

// TestEveryPlaneThatDerivesPseudonymsChecksTheOther fails when a cmd/ binary
// reads the HMAC secret without verifying it against the plane it shares a
// database with.
//
// Per package rather than per function: the two binaries read the secret and
// run the check in the same main(), but a refactor that lifts either into a
// helper is a reorganization, not a regression, and a gate that failed on it
// would be noise.
func TestEveryPlaneThatDerivesPseudonymsChecksTheOther(t *testing.T) {
	root := repoRoot(t)

	readsSecret := map[string]token.Position{}
	runsCheck := map[string]bool{}

	for _, path := range goFilesUnder(t, filepath.Join(root, "cmd")) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		pkg := filepath.Dir(path)

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if node.Sel.Name == crossPlaneSecretField {
					if _, seen := readsSecret[pkg]; !seen {
						readsSecret[pkg] = fset.Position(node.Pos())
					}
				}
			case *ast.CallExpr:
				if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == crossPlaneCheck {
					runsCheck[pkg] = true
				}
			}
			return true
		})
	}

	for pkg, at := range readsSecret {
		if runsCheck[pkg] {
			continue
		}
		rel, err := filepath.Rel(root, at.Filename)
		if err != nil {
			rel = at.Filename
		}
		t.Errorf("%s:%d reads %s but never calls config.%s. This binary derives subject "+
			"pseudonyms from a secret nothing checks against the other plane, so an account "+
			"erasure can clear zero rows from identity.profiles, objects.blobs and "+
			"objects.service_documents and still report success.",
			rel, at.Line, crossPlaneSecretField, crossPlaneCheck)
	}

	// A gate that matches nothing passes for the wrong reason. Both planes are
	// expected; if the field is renamed, they vanish from this check at once.
	if len(readsSecret) < 2 {
		var found []string
		for pkg := range readsSecret {
			rel, err := filepath.Rel(root, pkg)
			if err != nil {
				rel = pkg
			}
			found = append(found, rel)
		}
		t.Fatalf("found %d cmd/ binary/binaries reading %s (%s); expected at least 2 "+
			"(cmd/vault and cmd/admin-gateway). Either the field was renamed or this gate "+
			"has stopped seeing the code it guards.",
			len(readsSecret), crossPlaneSecretField, strings.Join(found, ", "))
	}
}
