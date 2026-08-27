package spec_test

import (
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// POST /admin/users/import bounds three fields, and the numbers it bounds them
// with are the widths of three columns in three different migrations. Nothing
// joined the two, so the handler could go on believing 64 after somebody widened
// imported_from, or -- the way it actually failed -- believe nothing at all.
//
// This gate reads BOTH sides. A constant checked against another constant in the
// same package agrees with itself; what makes this bite is that one side is the
// migration file.
//
// It is deliberately separate from the sanitizer/column gate. That one holds
// internal/sanitize's own bounds against their columns. This one holds a
// HANDLER's bounds against theirs, which is a different failure: the sanitizer
// was not wrong here, it was not called.

func importConst(t *testing.T, root, name string) int {
	t.Helper()
	src := commentFreeSource(t, filepath.Join(root, "internal", "adminapi", "import.go"))
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=\s*(\d+)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("internal/adminapi/import.go declares no `%s = <n>`. It is the bound this gate "+
			"holds against the database; inlining the number at the call site is how the two drift.", name)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s = %q is not a number: %v", name, m[1], err)
	}
	return n
}

func migrationColumnWidth(t *testing.T, root, migration, column string) int {
	t.Helper()
	src := readFileString(t, filepath.Join(root, "migrations", migration))
	re := regexp.MustCompile(`(?m)` + regexp.QuoteMeta(column) + `\s+VARCHAR\((\d+)\)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("no `%s VARCHAR(n)` in migrations/%s. If the column moved or changed type, move "+
			"this gate with it rather than deleting it: what it holds is an import that writes "+
			"more than the column can take and reports it as a bad record.", column, migration)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("width %q of %s is not a number: %v", m[1], column, err)
	}
	return n
}

func TestImportBoundsMatchTheColumnsTheyWriteInto(t *testing.T) {
	root := repoRoot(t)

	for _, tc := range []struct {
		constName string
		migration string
		column    string
	}{
		{"maxImportSourceLen", "006_account_import.sql", "imported_from"},
		{"maxImportBanReasonLen", "004_user_account_flags.sql", "ban_reason"},
	} {
		bound := importConst(t, root, tc.constName)
		width := migrationColumnWidth(t, root, tc.migration, tc.column)
		if bound != width {
			t.Errorf("internal/adminapi.%s is %d but auth.users.%s is VARCHAR(%d) in "+
				"migrations/%s.\nToo wide and PostgreSQL refuses the whole INSERT with 22001, which "+
				"this endpoint reports as a per-record \"create_failed\" naming nothing. Too narrow "+
				"and the import silently refuses or truncates values the column would have held.",
				tc.constName, bound, tc.column, width, tc.migration)
		}
	}
}

// locale is the third field, and it is bounded by sanitize.Locale rather than by
// a constant here -- which is the point: the two other write paths already went
// through it, and the import was the one that did not. Holding sanitize.Locale's
// own number against the column keeps that shared clamp honest.
func TestSanitizeLocaleFitsTheLocaleColumn(t *testing.T) {
	root := repoRoot(t)
	src := commentFreeSource(t, filepath.Join(root, "internal", "sanitize", "sanitize.go"))

	re := regexp.MustCompile(`(?s)func Locale\(locale string\) string \{.*?\n\}`)
	body := re.FindString(src)
	if body == "" {
		t.Fatal("internal/sanitize has no Locale function; the import path depends on it for the " +
			"locale column's bound")
	}
	lenRe := regexp.MustCompile(`len\(locale\)\s*>\s*(\d+)`)
	m := lenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("sanitize.Locale no longer bounds its input by length. auth.users.locale is a " +
			"VARCHAR, and this is the only thing standing between a caller-supplied tag and 22001.")
	}
	bound, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("bound %q is not a number: %v", m[1], err)
	}

	width := migrationColumnWidth(t, root, "001_initial_schema.sql", "locale")
	if bound > width {
		t.Errorf("sanitize.Locale admits %d characters but auth.users.locale is VARCHAR(%d)", bound, width)
	}
}
