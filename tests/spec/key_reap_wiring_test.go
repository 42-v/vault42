// Expired signing key reaping gate.
//
// keystore.CleanupExpired has existed since the DB-backed keystore shipped and
// nothing in the product ever called it. Its only callers were tests, so in a
// real deployment every retired signing key stayed in auth.signing_keys forever
// and the function documented as preventing table bloat prevented none. The
// second half was worse: 001 grants vault_app SELECT, INSERT and UPDATE on that
// table and no DELETE, so the sweep could not have removed a row even once
// something called it. Two independent halves, each of which makes the other
// invisible, which is why neither was noticed.
//
// The gates here are on the wiring and on the shape of the grant, because the
// behavior is covered elsewhere: internal/keystore proves the sweeper loops and
// stops, and tests/integration proves the SQL deletes the rows it should and
// refuses the rest. What no test in either place can see is whether cmd/vault
// ever starts the thing, or whether the DELETE privilege that makes it work is
// narrow enough to be safe.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// reapMigration is the migration that grants the DELETE and bounds it.
const reapMigration = "020_reap_expired_signing_keys.sql"

// revocationMigration is the migration whose trigger makes a revoked row
// terminal. Its trigger and function names are pinned below so a later
// migration cannot quietly take them over.
const revocationMigration = "017_signing_key_revocation_terminal.sql"

// TestVaultStartsTheExpiredSigningKeySweeperAfterTheCLISubcommandCheck fails
// when cmd/vault does not run the sweeper, and when it runs it on the wrong
// side of the early return that ends a CLI invocation.
//
// Both halves matter. Without the first, retired keys accumulate exactly as
// they did before. Without the second, the sweeper joins the audit and recovery
// sweepers in the mistake their comments describe: it sweeps once on start, so
// starting it above the CLI check would make `vault list-clients` delete signing
// key rows as a side effect of listing clients.
func TestVaultStartsTheExpiredSigningKeySweeperAfterTheCLISubcommandCheck(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "vault", "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing cmd/vault/main.go: %v", err)
	}

	// The sweeper is found through its constructor rather than through a
	// variable name, so renaming the variable does not silently disarm this.
	sweeper := assignedFromCall(file, "keystore", "NewRetention")
	if sweeper == "" {
		t.Fatal("cmd/vault/main.go never calls keystore.NewRetention, so expired signing keys " +
			"are still reaped by nothing and keystore.CleanupExpired remains dead code in " +
			"every deployment")
	}

	startLine := methodCallLine(fset, file, sweeper, "Start")
	if startLine == 0 {
		t.Fatalf("cmd/vault/main.go builds the signing key sweeper as %q but never calls %s.Start, "+
			"so it is constructed and never runs", sweeper, sweeper)
	}
	if methodCallLine(fset, file, sweeper, "Stop") == 0 {
		t.Errorf("cmd/vault/main.go never calls %s.Stop, so the sweep loop can outlive the "+
			"database pool the deferred close tears down underneath it", sweeper)
	}

	cliLine := methodCallLine(fset, file, "cliHandler", "Run")
	if cliLine == 0 {
		t.Fatal("cmd/vault/main.go no longer calls cliHandler.Run; the CLI early return this " +
			"gate orders against has moved and the gate has stopped seeing what it guards")
	}

	if startLine < cliLine {
		t.Errorf("cmd/vault/main.go:%d starts the signing key sweeper above the CLI check at line %d. "+
			"The sweep runs immediately on start, so every `vault add-client`, `vault rotate-jwks`, … "+
			"would delete signing key rows as a side effect of an unrelated subcommand. Start it "+
			"below the check, where the audit and recovery sweepers are.", startLine, cliLine)
	}
}

// TestTheDeleteGrantOnSigningKeysIsNarrowedByATrigger pins the reason the grant
// is safe to make at all.
//
// Postgres has no row scope for a privilege and no column list for DELETE, so
// `GRANT DELETE ON auth.signing_keys` is all-rows by construction: it also lets
// anything running as vault_app delete the ACTIVE key, whose encrypted private
// material is the only copy that exists, and every retired key still inside its
// retention window, which strands live tokens. The privilege is therefore not
// the boundary. A BEFORE DELETE trigger that refuses every row the sweep is not
// meant to touch is the boundary, and it has to ship in the same migration as
// the grant or the grant is naked between the two.
func TestTheDeleteGrantOnSigningKeysIsNarrowedByATrigger(t *testing.T) {
	root := repoRoot(t)
	sql := readFileString(t, filepath.Join(root, "migrations", reapMigration))
	live := stripSQLComments(t, reapMigration, sql)

	if !strings.Contains(live, "GRANT DELETE ON auth.signing_keys TO vault_app;") {
		t.Error("migrations/" + reapMigration + " does not grant vault_app DELETE on " +
			"auth.signing_keys, so keystore.CleanupExpired still cannot remove a row: it fails " +
			"with 42501 on every sweep in a real deployment")
	}

	if !strings.Contains(live, "BEFORE DELETE ON auth.signing_keys") {
		t.Error("migrations/" + reapMigration + " grants DELETE without installing a BEFORE " +
			"DELETE trigger to bound it. The privilege covers every row in the table, including " +
			"the active key and retired keys still verifying live tokens.")
	}
}

// TestTheReapScopeTriggerLeavesRevokedRowsToTheRevocationTrigger pins the
// division of responsibility between the two DELETE guards on this table.
//
// 017 froze revoked rows because the row is the tombstone: while it exists the
// kid is taken and cannot be re-inserted, and an attacker who read the
// ciphertext out of the row could otherwise free that identifier and publish a
// key of their own under it. Its trigger is the one that must speak for a
// revoked row, and Postgres fires same-event triggers in name order, so a
// second BEFORE DELETE trigger sorting ahead of it would answer first and
// replace its message with one about reaping.
//
// Excluding revoked rows from the new trigger's WHEN clause makes the ordering
// irrelevant instead of merely lucky, and makes it structurally impossible for
// the reap scope to have any opinion about a revoked row at all.
func TestTheReapScopeTriggerLeavesRevokedRowsToTheRevocationTrigger(t *testing.T) {
	root := repoRoot(t)
	live := stripSQLComments(t, reapMigration,
		readFileString(t, filepath.Join(root, "migrations", reapMigration)))

	when, ok := whenClause(live)
	if !ok {
		t.Fatal("migrations/" + reapMigration + " installs a trigger with no WHEN clause, so it " +
			"enters plpgsql for every delete including the ones the sweep is allowed to make")
	}
	if !strings.Contains(when, "OLD.status <> 'revoked'") {
		t.Errorf("the reap-scope trigger's WHEN clause does not exclude revoked rows:\n\t%s\n"+
			"Triggers on the same event fire in name order, so this one can answer a delete of a "+
			"revoked row before signing_keys_revocation_terminal does and report the wrong reason "+
			"for the refusal. Exclude revoked rows and let 017 own them.", when)
	}
}

// TestNoLaterMigrationRedefinesTheRevocationTerminalityTrigger fails on any
// migration after 017 that drops, replaces or disables the guard that makes a
// revoked signing key terminal.
//
// The reap needed a DELETE privilege on this table, which is precisely the
// future 017 wrote itself against: its header says the freeze "guards against a
// future grant rather than a present hole". That grant now exists, so the
// freeze stopped being belt-and-suspenders and became the only thing between a
// leaked kid and re-insertion under a key the attacker chose. This gate makes
// weakening it a deliberate act rather than a side effect of a migration about
// something else.
func TestNoLaterMigrationRedefinesTheRevocationTerminalityTrigger(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "migrations")

	// The names 017 installs. Either one being rebound elsewhere changes what
	// happens to a revoked row.
	guarded := []string{
		"signing_keys_revocation_terminal",
		"auth.deny_revoked_signing_key_change",
	}

	names := migrationNames(t, dir)
	var checked int
	for _, name := range names {
		if name <= revocationMigration {
			continue
		}
		checked++

		live := stripSQLComments(t, name, readFileString(t, filepath.Join(dir, name)))
		for _, g := range guarded {
			if strings.Contains(live, g) {
				t.Errorf("migrations/%s names %s in executable SQL. Only 017 may define it: it is "+
					"the whole reason a revoked kid cannot be freed for re-insert, and vault_app "+
					"now holds DELETE on this table.", name, g)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no migration after 017 was checked, so this gate proves nothing")
	}
}

// migrationNames lists the migration file names in applied order.
func migrationNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// assignedFromCall returns the name of the variable a pkg.fn(...) call is
// assigned to, or "" when the call is absent.
func assignedFromCall(file *ast.File, pkg, fn string) string {
	var out string
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fn {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != pkg {
			return true
		}
		if lhs, ok := as.Lhs[0].(*ast.Ident); ok {
			out = lhs.Name
		}
		return false
	})
	return out
}

// methodCallLine returns the line of the first recv.method(...) call, or 0.
func methodCallLine(fset *token.FileSet, file *ast.File, recv, method string) int {
	var line int
	ast.Inspect(file, func(n ast.Node) bool {
		if line != 0 {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != recv {
			return true
		}
		line = fset.Position(call.Pos()).Line
		return false
	})
	return line
}

// whenClause returns the text between WHEN ( and the matching close paren of a
// CREATE TRIGGER, with whitespace collapsed so a wrapped clause reads as one
// line in a failure message.
func whenClause(sql string) (string, bool) {
	i := strings.Index(sql, "WHEN (")
	if i < 0 {
		return "", false
	}
	rest := sql[i+len("WHEN ("):]
	depth := 1
	for j, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 {
			return strings.Join(strings.Fields(rest[:j]), " "), true
		}
	}
	return "", false
}
