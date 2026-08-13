// Capability scope parity gate.
//
// vault42 names its own capability scopes twice, in two languages, and both
// copies answer the same question: which scope strings are this service's
// privileged endpoints rather than an application's own vocabulary.
//
//   - service.mintDeniedScopes (internal/service/mint.go) refuses to put one on
//     a minted token, so a mint holder cannot pivot onto POST /kms/unwrap.
//   - auth.capability_scopes() (migration 023) refuses to let vault_app write one
//     into an auth.clients row, so anything reaching the database as the
//     application role cannot issue itself the credential in the first place.
//
// Neither can be derived from the other. A trigger cannot call into the process,
// and the process would have to query the database before it could refuse
// anything, which puts a network round trip inside a validation path and makes
// the refusal depend on a connection being up. So the lists are duplicated on
// purpose, and duplicated lists drift: adding a capability scope in Go leaves the
// database handing it out, which is the exact hole 023 was written to close,
// arriving quietly through the change that was supposed to widen the guard.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// mintDeniedScopesSource is the Go half of the pair.
var mintDeniedScopesSource = filepath.Join("internal", "service", "mint.go")

// sqlScopeLiteral pulls the quoted scope names out of a SQL array literal.
var sqlScopeLiteral = regexp.MustCompile(`'([^']*)'`)

// TestTheCapabilityScopesGoRefusesToMintAreTheOnesTheDatabaseRefusesToGrant
// fails when the two lists stop naming the same set.
func TestTheCapabilityScopesGoRefusesToMintAreTheOnesTheDatabaseRefusesToGrant(t *testing.T) {
	root := repoRoot(t)

	inGo := goCapabilityScopes(t, filepath.Join(root, mintDeniedScopesSource))
	inSQL, migration := sqlCapabilityScopes(t, root)

	if len(inGo) == 0 {
		t.Fatal("no scopes were read out of mintDeniedScopes, so this gate proves nothing")
	}
	if len(inSQL) == 0 {
		t.Fatal("no scopes were read out of auth.capability_scopes(), so this gate proves nothing")
	}

	for _, scope := range inGo {
		if !contains(inSQL, scope) {
			t.Errorf("%q is refused on a minted token by service.mintDeniedScopes but is not in "+
				"auth.capability_scopes() (migrations/%s).\n"+
				"vault_app can therefore write it into an auth.clients row and authenticate as "+
				"that client, which hands out the capability the Go list exists to withhold.",
				scope, migration)
		}
	}
	for _, scope := range inSQL {
		if !contains(inGo, scope) {
			t.Errorf("%q is refused on a client row by auth.capability_scopes() (migrations/%s) but "+
				"is not in service.mintDeniedScopes.\n"+
				"POST /mint will therefore issue a token carrying it, which reaches the same "+
				"endpoint by the other door.", scope, migration)
		}
	}
}

// TestTheCapabilityScopeListHasOneCopyInTheMigration fails when a scope name
// appears in executable SQL outside auth.capability_scopes().
//
// The trigger's WHEN clause is the place this goes wrong: inlining the array
// there reads as an optimization, keeps every test green, and creates a second
// list that the gate above cannot see, because it compares Go against the
// function body only.
func TestTheCapabilityScopeListHasOneCopyInTheMigration(t *testing.T) {
	root := repoRoot(t)
	scopes, migration := sqlCapabilityScopes(t, root)

	sql := stripSQLComments(t, migration, readFileString(t, filepath.Join(root, "migrations", migration)))
	for _, scope := range scopes {
		if n := strings.Count(sql, "'"+scope+"'"); n != 1 {
			t.Errorf("migrations/%s spells %q %d times in executable SQL, want 1.\n"+
				"auth.capability_scopes() is the single source of truth; every other site must "+
				"call it so a scope added there is added everywhere.", migration, scope, n)
		}
	}
}

// goCapabilityScopes returns the keys of the mintDeniedScopes map literal.
func goCapabilityScopes(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", mintDeniedScopesSource, err)
	}

	var scopes []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "mintDeniedScopes" {
			return true
		}
		for _, value := range spec.Values {
			lit, ok := value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.BasicLit)
				if !ok || key.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(key.Value)
				if err != nil {
					t.Fatalf("unquoting %s: %v", key.Value, err)
				}
				scopes = append(scopes, unquoted)
			}
		}
		return false
	})

	sort.Strings(scopes)
	return scopes
}

// sqlCapabilityScopes returns the scope names auth.capability_scopes() yields,
// and the migration that last defined it.
//
// The last definition wins, the way 018 and 019 supersede the functions 012 and
// 001 introduced. History here is append-only, so reading the first definition
// would judge the tree by a body no longer in force.
func sqlCapabilityScopes(t *testing.T, root string) (scopes []string, migration string) {
	t.Helper()

	dir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		sql := stripSQLComments(t, name, readFileString(t, filepath.Join(dir, name)))
		idx := strings.Index(sql, "FUNCTION auth.capability_scopes()")
		if idx < 0 {
			continue
		}
		body := sql[idx:]
		open := strings.Index(body, "ARRAY[")
		if open < 0 {
			t.Fatalf("migrations/%s defines auth.capability_scopes() with no ARRAY literal, so this "+
				"gate cannot read the list it is supposed to compare", name)
		}
		closeIdx := strings.Index(body[open:], "]")
		if closeIdx < 0 {
			t.Fatalf("migrations/%s has an unterminated ARRAY literal in auth.capability_scopes()", name)
		}

		var found []string
		for _, m := range sqlScopeLiteral.FindAllStringSubmatch(body[open:open+closeIdx], -1) {
			found = append(found, m[1])
		}
		sort.Strings(found)
		scopes, migration = found, name
	}

	if migration == "" {
		t.Fatal("no migration defines auth.capability_scopes(), so the database is not guarding " +
			"the capability scopes at all")
	}
	return scopes, migration
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
