// Trigger audit write gate.
//
// Two trigger functions tried to record a blocked privilege escalation like
// this:
//
//	BEGIN
//	    INSERT INTO audit.audit_log (...);
//	EXCEPTION WHEN OTHERS THEN
//	    NULL;
//	END;
//	RAISE EXCEPTION 'role escalation denied: ...';
//
// The INSERT never survived. The subtransaction commits it, then the RAISE
// aborts the statement that fired the trigger and the row goes with it. A
// transaction that is about to abort cannot persist anything, so no arrangement
// of BEGIN and EXCEPTION around the INSERT makes it work.
//
// It read as correct, which is why it lasted. The EXCEPTION WHEN OTHERS THEN
// NULL made it worse: the write was already being discarded deliberately, so
// nothing distinguished "never wrote a row" from "wrote a row that was rolled
// back", and no test could tell either.
//
// Migration 019 replaced both with RAISE WARNING, which is a log message rather
// than a row and therefore survives the abort. This gate stops the row-shaped
// version coming back, in these functions or in a new one.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoTriggerWritesAnAuditRowItIsAboutToRollBack fails when a migration
// INSERTs into audit.audit_log in a function body that later RAISEs an
// exception on the same path.
//
// The check is per function body rather than per file, because a migration may
// legitimately contain both a function that raises and an unrelated one that
// audits.
func TestNoTriggerWritesAnAuditRowItIsAboutToRollBack(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "migrations")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	// Migrations 001 and 016 introduced the pattern and 019 replaces both
	// functions. History is append-only here, so the originals keep their text
	// and are judged by what 019 leaves in force.
	superseded := map[string]bool{
		"001_initial_schema.sql":                true,
		"016_admin_insert_escalation_guard.sql": true,
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || superseded[e.Name()] {
			continue
		}
		checked++

		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sql := stripSQLComments(t, e.Name(), string(raw))

		for _, fn := range splitFunctionBodies(sql) {
			if !strings.Contains(strings.ToUpper(fn.body), "INSERT INTO AUDIT.AUDIT_LOG") {
				continue
			}
			if !strings.Contains(strings.ToUpper(fn.body), "RAISE EXCEPTION") {
				continue
			}
			t.Errorf("migrations/%s:%d has a function that INSERTs into audit.audit_log and "+
				"also RAISEs an exception.\n"+
				"If the RAISE is reachable from the INSERT, the row is rolled back with the "+
				"aborting transaction and the event is recorded nowhere. Use RAISE WARNING, "+
				"which is a log message and survives the abort, or have the application catch "+
				"the error and write the row from a transaction that commits.",
				e.Name(), fn.line)
		}
	}

	if checked == 0 {
		t.Fatal("no migrations were checked, so this gate proves nothing")
	}
}

type sqlFunction struct {
	line int
	body string
}

// splitFunctionBodies returns each CREATE FUNCTION body in the file, so the gate
// can ask its question of one function at a time.
//
// Bodies are delimited by the $$ pairs this tree uses throughout. A migration
// using a different dollar-quote tag would be missed, which is why the gate
// reports how many files it checked rather than passing silently on an empty
// walk.
func splitFunctionBodies(sql string) []sqlFunction {
	var out []sqlFunction

	lines := strings.Split(sql, "\n")
	var cur *sqlFunction
	for n, line := range lines {
		upper := strings.ToUpper(line)
		if cur == nil {
			if strings.Contains(upper, "CREATE OR REPLACE FUNCTION") || strings.Contains(upper, "CREATE FUNCTION") {
				cur = &sqlFunction{line: n + 1}
			}
			continue
		}
		if strings.Contains(line, "$$") && strings.Contains(upper, "LANGUAGE") {
			out = append(out, *cur)
			cur = nil
			continue
		}
		cur.body += line + "\n"
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// TestEscalationBlocksStillCarryTheAttemptDetails pins that replacing the row
// write did not also drop the fields an investigator needs.
//
// A RAISE WARNING with no detail would satisfy the gate above while leaving the
// same hole: the block is visible, the attempt is not.
func TestEscalationBlocksStillCarryTheAttemptDetails(t *testing.T) {
	root := repoRoot(t)
	const name = "019_escalation_block_leaves_a_trace.sql"

	// Comments are stripped first. Migration 019's header quotes the dead
	// pattern it removes, so a raw read finds EXCEPTION WHEN OTHERS THEN in the
	// explanation and fails the file for describing its own fix. The retention
	// gate hit this same trap, and the answer is the same: judge executable SQL,
	// never prose.
	src := stripSQLComments(t, name, readFileString(t, filepath.Join(root, "migrations", name)))

	for _, want := range []string{
		"RAISE WARNING 'admin:role_escalation_blocked path=update",
		"RAISE WARNING 'admin:role_escalation_blocked path=insert",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("migration 019 no longer emits %q", want)
		}
	}

	for _, field := range []string{"admin_id=%", "username=%", "old_role=%", "new_role=%"} {
		if strings.Count(src, field) < 2 {
			t.Errorf("%s appears in fewer than both escalation warnings; an investigator needs "+
				"the same fields from the insert path and the update path", field)
		}
	}

	if strings.Contains(src, "EXCEPTION WHEN OTHERS THEN") {
		t.Error("migration 019 reintroduced the swallowed-exception wrapper. It made the " +
			"original defect invisible: a discarded write and a rolled-back write looked " +
			"identical, so nothing could tell them apart. Line " +
			strconv.Itoa(strings.Count(src[:strings.Index(src, "EXCEPTION WHEN OTHERS THEN")], "\n")+1))
	}
}
