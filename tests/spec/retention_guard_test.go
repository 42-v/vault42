// Retention guard drift gate.
//
// A guard that validates one value and applies another is only correct by
// coincidence. audit.cleanup_old_entries got that wrong in a way nothing could
// catch: it compared the caller's INTERVAL against a minimum, then subtracted
// that same INTERVAL from NOW() to build the DELETE predicate.
//
// Those are different operations. Interval comparison canonicalizes a month to
// 30 days, because two intervals have to be ordered without a reference date.
// Interval subtraction from a timestamp has a reference date and uses the real
// calendar month. So INTERVAL '1 mon -29 days' compares as 1 day and passes,
// while in February it subtracts to a cutoff one day in the future and the
// DELETE takes the whole table.
//
// That function is the only path that can delete an audit row, it turns the
// append-only trigger off to do it, and vault_app holds EXECUTE. The minimum
// horizon is the only limit on the blast radius of one call.
//
// The behavioral regression lives in tests/integration, where a real Postgres
// can evaluate the arithmetic. This gate is the cheap half: it runs with no
// container and fails if anyone reintroduces the shape, including in a new
// retention function that has not been written yet.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// intervalParamComparison matches a guard that compares an interval-typed
// parameter against an interval literal, which is the shape that decides
// something different from what the DELETE will do.
//
// It deliberately does not match a comparison against a timestamp expression
// such as `cutoff > NOW() - INTERVAL '1 day'`, which is the correct form: there
// the left side is the value the DELETE uses.
var intervalParamComparison = regexp.MustCompile(`(?i)\b(\w*interval\w*)\s*[<>]=?\s*INTERVAL\s*'`)

// stripSQLComments removes -- line comments so the gate reads executable SQL
// only.
//
// Without it the gate fires on any migration whose header quotes the defect it
// fixes, which is every migration worth reading. Migration 018 tripped its own
// gate that way. A rule that punishes explaining the bug teaches the next author
// to stop explaining.
//
// Line comments are enough here. Postgres also has /* */ blocks and a --
// sequence can appear inside a string literal, but no migration in this tree
// uses either, and a gate that silently mis-parses is worse than one with a
// stated limit, so this asserts the limit instead of guessing.
func stripSQLComments(t *testing.T, name, src string) string {
	t.Helper()

	if strings.Contains(src, "/*") {
		t.Fatalf("migrations/%s contains a block comment. stripSQLComments only handles -- "+
			"line comments, so this gate would read commented-out SQL as live. Extend it.", name)
	}

	var out strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// TestRetentionGuardsCompareTheComputedCutoffNotTheRawInterval walks every
// migration and fails on a guard that tests an interval parameter directly.
func TestRetentionGuardsCompareTheComputedCutoffNotTheRawInterval(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "migrations")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	// Migration 012 introduced the defect and migration 018 replaces the
	// function. History is append-only here, so 012 keeps its original text and
	// is judged by what 018 leaves in force rather than by its own body.
	const supersededByLaterMigration = "012_audit_function_hardening.sql"

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() == supersededByLaterMigration {
			continue
		}
		checked++

		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}

		sql := stripSQLComments(t, e.Name(), string(src))
		for _, m := range intervalParamComparison.FindAllStringSubmatch(sql, -1) {
			t.Errorf("migrations/%s guards on %q compared against an INTERVAL literal.\n"+
				"Interval comparison treats a month as 30 days; subtracting an interval from a "+
				"timestamp uses the real calendar month. A caller picks the gap by mixing units, "+
				"so INTERVAL '1 mon -29 days' passes a 1-day minimum and in February yields a "+
				"cutoff in the future. Compute the cutoff once, guard the cutoff, and delete on "+
				"the same variable.", e.Name(), m[1])
		}
	}

	if checked == 0 {
		t.Fatal("no migrations were checked, so this gate proves nothing")
	}
}

// TestAuditCleanupDeletesOnTheValueItValidated pins the structural property that
// makes the class impossible rather than the instance: the guard and the DELETE
// must name the same variable.
//
// Without it, a later edit that recomputes NOW() - retention_interval inside the
// DELETE would restore the original defect while still passing the regex gate
// above, because the guard itself would still look correct.
func TestAuditCleanupDeletesOnTheValueItValidated(t *testing.T) {
	root := repoRoot(t)
	src := readFileString(t, filepath.Join(root, "migrations", "018_audit_retention_guard_uses_cutoff.sql"))

	body := src[strings.Index(src, "CREATE OR REPLACE FUNCTION audit.cleanup_old_entries"):]

	if !strings.Contains(body, "cutoff := NOW() - retention_interval;") {
		t.Error("the cutoff is no longer computed once into a variable")
	}
	if !strings.Contains(body, "DELETE FROM audit.audit_log WHERE timestamp < cutoff;") {
		t.Error("the DELETE no longer uses the cutoff variable the guard validated. " +
			"Recomputing NOW() - retention_interval here reopens the bypass: the guard would " +
			"check one value and the DELETE would apply another.")
	}
	if strings.Contains(body, "retention_interval < INTERVAL") {
		t.Error("the guard compares the raw interval again")
	}
}
