package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// AR-25 names the decrypted blob plaintext and label as the buffers that are
// never wiped. They are the last ones: the master key, the KMS root key and the
// HMAC secret are zeroed in cmd/vault, the keystore signing-key PEM in
// keystore.go, and the decrypted identity plaintext in identity.go. What is
// left is BlobService, which decrypts a user's blob and its label into slices
// it owns and then abandons them to the heap, where a core dump, a swapped
// page, or the next allocation that reuses the arena carries them.
//
// The buffers are function-local and never escape, so no caller can observe
// them; this reads the source instead and requires every plaintext that
// vaultcrypto.Decrypt produces here to be handed to config.ZeroBytes.
func TestBlobServiceZeroesEveryDecryptedBuffer(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "blob.go", nil, 0)
	if err != nil {
		t.Fatalf("parse blob.go: %v", err)
	}

	var decrypts int
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		zeroed := zeroedIdents(fn.Body)
		for _, name := range decryptedIdents(fn.Body) {
			decrypts++
			if !zeroed[name.ident] {
				t.Errorf("%s (blob.go:%d): the plaintext in %q is never passed to config.ZeroBytes",
					fn.Name.Name, fset.Position(name.pos).Line, name.ident)
			}
		}
		return true
	})

	// A gate that finds no call sites passes for the wrong reason.
	if decrypts < 3 {
		t.Fatalf("found %d vaultcrypto.Decrypt results in blob.go, want at least 3; "+
			"the decrypt sites moved and this gate is now checking nothing", decrypts)
	}
}

type decryptedIdent struct {
	ident string
	pos   token.Pos
}

// decryptedIdents collects the identifier each vaultcrypto.Decrypt result is
// assigned to.
func decryptedIdents(body *ast.BlockStmt) []decryptedIdent {
	var found []decryptedIdent
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		if !isSelectorCall(assign.Rhs[0], "vaultcrypto", "Decrypt") {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			found = append(found, decryptedIdent{ident: id.Name, pos: id.Pos()})
		}
		return true
	})
	return found
}

// zeroedIdents collects every identifier passed to config.ZeroBytes, whether
// called directly or deferred.
func zeroedIdents(body *ast.BlockStmt) map[string]bool {
	zeroed := map[string]bool{}
	record := func(call *ast.CallExpr) {
		if !isSelectorCall(call, "config", "ZeroBytes") || len(call.Args) != 1 {
			return
		}
		if id, ok := call.Args[0].(*ast.Ident); ok {
			zeroed[id.Name] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.DeferStmt:
			record(stmt.Call)
		case *ast.ExprStmt:
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				record(call)
			}
		}
		return true
	})
	return zeroed
}

func isSelectorCall(expr ast.Expr, pkg, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}
