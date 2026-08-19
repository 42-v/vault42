// Mint claim-collision gate.
//
// A minted token asserts a subject vault42 never authenticated, so it must never
// look like a token vault42 issued to a service it authenticated. The claim that
// draws that line is client_id: internal/handler/servicedoc.go treats a non-empty
// client_id as proof of a service caller (requireClient) and as the ownership
// axis of the document store, and ClientRateLimitKey buckets on it. A minted
// token carrying client_id would therefore be admitted to another client's
// private documents for whatever subject the mint holder named.
//
// Attribution still has to reach the relying party, because the audit trail that
// records who minted what is only readable by whoever can read vault42's
// database. That is the minted_by claim, and the whole point of its name is that
// nothing anywhere authorizes on it.
//
// The two facts are one edit apart. Renaming minted_by to client_id, or adding
// client_id "for consistency" with the other issuance paths, compiles, passes
// every existing test that checks a mint response body, and silently opens the
// service document store. This gate reads the claim literal itself so that edit
// fails the build instead.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// mintClaimsSource is the one place a minted token's claim set is built.
var mintClaimsSource = filepath.Join("internal", "service", "mint.go")

// TestTheMintedClaimSetNamesTheClientWithoutClaimingToBeOne fails when the claim
// literal in MintService.Mint either sets ClientID or stops setting MintedBy.
//
// It reads the composite literal rather than minting a token, because the
// property is about which claims the code is allowed to set at all. A runtime
// check would pass for any request that happened to leave the field empty.
func TestTheMintedClaimSetNamesTheClientWithoutClaimingToBeOne(t *testing.T) {
	path := filepath.Join(repoRoot(t), mintClaimsSource)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", mintClaimsSource, err)
	}

	fn := mintMethodDecl(t, file)
	literals := 0
	sawMintedBy := false

	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isVaultClaimsLit(lit) {
			return true
		}
		literals++

		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "ClientID":
				t.Errorf("%s:%d sets ClientID on a minted token. requireClient and "+
					"ClientRateLimitKey in internal/handler/servicedoc.go read that claim as proof "+
					"of an authenticated service caller, so every minted token would be admitted to "+
					"the service document store as the client named here and could read and "+
					"overwrite that client's private documents for any subject the mint holder "+
					"asserts. Attribution belongs in MintedBy, which nothing authorizes on.",
					mintClaimsSource, fset.Position(kv.Pos()).Line)
			case "MintedBy":
				sawMintedBy = true
			}
		}
		return true
	})

	if literals == 0 {
		t.Fatalf("MintService.Mint in %s builds no VaultClaims literal; the signing path moved and "+
			"this gate has stopped seeing what it guards", mintClaimsSource)
	}
	if !sawMintedBy {
		t.Errorf("MintService.Mint in %s no longer sets MintedBy. A relying party then holds a "+
			"token it can tell was minted, from token_type, but cannot attribute to a mint "+
			"credential, and the only record of who asserted the subject is an audit row in "+
			"vault42's database that the relying party cannot read.", mintClaimsSource)
	}
}

// TestNoTokenClaimIsSpelledBothWays fails when VaultClaims carries two fields
// with the same JSON name, which is how minted_by would quietly become client_id
// on the wire while the Go code still reads as if the two were separate.
func TestNoTokenClaimIsSpelledBothWays(t *testing.T) {
	path := filepath.Join(repoRoot(t), "internal", "crypto", "jwt.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing internal/crypto/jwt.go: %v", err)
	}

	tags := map[string]string{}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "VaultClaims" {
			return true
		}
		found = true
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			if f.Tag == nil || len(f.Names) == 0 {
				continue
			}
			name := jsonClaimName(f.Tag.Value)
			if name == "" {
				continue
			}
			if prior, dup := tags[name]; dup {
				t.Errorf("VaultClaims fields %s and %s both serialize as %q. Whichever is written "+
					"last wins on the wire, so a minted token could ship the attribution claim "+
					"under a name that other code reads as authorization.", prior, f.Names[0].Name, name)
			}
			tags[name] = f.Names[0].Name
		}
		return false
	})

	if !found {
		t.Fatal("VaultClaims is no longer declared in internal/crypto/jwt.go; this gate has stopped " +
			"seeing what it guards")
	}
	if tags["minted_by"] != "MintedBy" {
		t.Errorf("the minted_by claim is served by %q, want MintedBy; renaming it breaks every "+
			"relying party that attributes minted tokens", tags["minted_by"])
	}
	if tags["client_id"] != "ClientID" {
		t.Errorf("the client_id claim is served by %q, want ClientID", tags["client_id"])
	}
}

// mintMethodDecl returns the MintService.Mint declaration.
func mintMethodDecl(t *testing.T, file *ast.File) *ast.FuncDecl {
	t.Helper()

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Mint" || fn.Recv == nil {
			continue
		}
		return fn
	}
	t.Fatal("no MintService.Mint method found in internal/service/mint.go; the signing path moved " +
		"and this gate has stopped seeing what it guards")
	return nil
}

// isVaultClaimsLit reports whether a composite literal builds crypto.VaultClaims,
// under whatever alias the file imports the package as.
func isVaultClaimsLit(lit *ast.CompositeLit) bool {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "VaultClaims"
}

// jsonClaimName extracts the wire name from a raw struct tag, ignoring options
// such as omitempty. It returns "" for a field with no json tag or with `json:"-"`.
func jsonClaimName(rawTag string) string {
	tag, err := strconv.Unquote(rawTag)
	if err != nil {
		return ""
	}
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return ""
	}
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	if value == "-" {
		return ""
	}
	return value
}
