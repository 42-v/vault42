// Grant line shape gate.
//
// tests/integration/containers_test.go builds its schema by applying every
// migration to a bare Postgres that has none of the production roles. It removes
// the role grants first, with stripRoleGrants, which matches GRANT, REVOKE and
// ALTER DEFAULT only at the start of a line.
//
// That makes the formatting of a grant load-bearing, which is not a property
// anyone expects SQL to have:
//
//   - An indented grant is not stripped. It reaches a database with no vault_app
//     role, and the whole migration fails.
//   - A grant wrapped across two lines has its first line stripped and its tail
//     left behind, which is a syntax error rather than a missing grant, so the
//     failure names the wrong thing.
//
// Grants inside a DO block are the deliberate exception. They are indented by
// necessity and survive stripping on purpose, which is how migration 009 gets
// its grants into the integration database at all.
//
// This was written down as a note telling future authors to keep grants on one
// unindented line. A note is not a gate. The integration suite that would catch
// a violation needs a container, so on a machine without one the migration looks
// fine until CI.
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

// grantKeywords are the statement prefixes stripRoleGrants recognizes. Kept in
// the same order and spelling as the harness so a reader can compare them.
var grantKeywords = []string{"GRANT ", "REVOKE ", "ALTER DEFAULT"}

// TestEveryGrantIsShapedSoTheIntegrationHarnessCanStripIt walks the migrations
// and fails on a grant the harness would mangle.
func TestEveryGrantIsShapedSoTheIntegrationHarnessCanStripIt(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "migrations")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		checked++

		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}

		// Comments are stripped so a header quoting a grant is not mistaken for
		// one. The harness does not strip them, but the harness only ever looks
		// at column zero, and a comment there starts with "--".
		sql := stripSQLComments(t, e.Name(), string(raw))

		inDoBlock := false
		for n, line := range strings.Split(sql, "\n") {
			// $$ opens and closes a DO body. Counting toggles rather than
			// tracking depth is enough: Postgres does not nest the same tag.
			if strings.Contains(line, "$$") {
				inDoBlock = !inDoBlock
				continue
			}

			trimmed := strings.TrimSpace(line)
			if !hasGrantKeyword(trimmed) {
				continue
			}
			if inDoBlock {
				continue
			}

			where := "migrations/" + e.Name() + ":" + strconv.Itoa(n+1)

			if trimmed != line {
				t.Errorf("%s indents a grant:\n\t%s\n"+
					"stripRoleGrants in tests/integration/containers_test.go matches only at "+
					"column zero, so this one is not stripped. It reaches a Postgres with no "+
					"vault_app role and the migration fails. Put it at column zero, or move it "+
					"inside a DO block if it has to be conditional.", where, trimmed)
				continue
			}

			if !strings.HasSuffix(trimmed, ";") {
				t.Errorf("%s wraps a grant across lines:\n\t%s\n"+
					"stripRoleGrants removes this line and leaves the continuation behind, which "+
					"is a syntax error rather than a missing grant, so the failure names the "+
					"wrong thing. Keep the statement on one line.", where, trimmed)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no migrations were checked, so this gate proves nothing")
	}
}

func hasGrantKeyword(line string) bool {
	upper := strings.ToUpper(line)
	for _, kw := range grantKeywords {
		if strings.HasPrefix(upper, kw) {
			return true
		}
	}
	return false
}
