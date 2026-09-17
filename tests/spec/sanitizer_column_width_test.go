package spec_test

import (
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// A sanitizer must not admit more than the column it feeds can hold.
//
// internal/sanitize.AvatarURL accepted 2048 bytes and auth.users.avatar_url is
// VARCHAR(1024), so a URL between 1025 and 2048 characters passed every check
// the application makes and was refused by PostgreSQL with 22001, "value too
// long for type character varying(1024)". That fails the whole UPDATE: the user
// is told their profile could not be saved, with a 500 and nothing naming the
// field, and the display name they changed in the same request goes with it.
//
// A bound wider than its column is not a sanitizer. It is a check that moves
// the failure from a place with a message to a place without one.
//
// The gate reads both numbers rather than pinning either. A constant compared
// against another constant in the same file would have agreed with itself here;
// what makes this bite is that one side is the migration.

// columnWidth finds `<name> VARCHAR(<n>)` in a migration.
func columnWidth(t *testing.T, root, migration, column string) int {
	t.Helper()
	src := readFileString(t, filepath.Join(root, "migrations", migration))
	re := regexp.MustCompile(`(?m)` + regexp.QuoteMeta(column) + `\s+VARCHAR\((\d+)\)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("no `%s VARCHAR(n)` in migrations/%s. If the column moved or changed type, "+
			"move this gate with it rather than deleting it: the defect it holds is an "+
			"application bound wider than the column it writes into.", column, migration)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("width %q of %s is not a number: %v", m[1], column, err)
	}
	return n
}

// sanitizerBound finds `<name> = <n>` in internal/sanitize.
func sanitizerBound(t *testing.T, root, constName string) int {
	t.Helper()
	src := commentFreeSource(t, filepath.Join(root, "internal", "sanitize", "sanitize.go"))
	re := regexp.MustCompile(`(?m)^\s*const\s+` + regexp.QuoteMeta(constName) + `\s*=\s*(\d+)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("internal/sanitize declares no `const %s = <n>`. It is the bound this gate "+
			"holds against the database; inlining the number is how the two drift.", constName)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("bound %q of %s is not a number: %v", m[1], constName, err)
	}
	return n
}

func TestSanitizerBoundsFitTheColumnsTheyWriteInto(t *testing.T) {
	root := repoRoot(t)

	for _, tc := range []struct {
		constName string
		migration string
		column    string
	}{
		{"avatarURLColumn", "001_initial_schema.sql", "avatar_url"},
	} {
		bound := sanitizerBound(t, root, tc.constName)
		width := columnWidth(t, root, tc.migration, tc.column)
		if bound > width {
			t.Errorf("internal/sanitize.%s admits %d but %s is VARCHAR(%d).\n"+
				"A value between %d and %d passes every application check and is then refused "+
				"by PostgreSQL with 22001, failing the whole statement rather than the field.",
				tc.constName, bound, tc.column, width, width+1, bound)
		}
		// Equal is the intent. A bound well under the column is not a defect,
		// but it is worth saying out loud so nobody widens the column believing
		// the application will follow.
		if bound < width {
			t.Logf("note: %s is %d against a VARCHAR(%d) column; the column has room the "+
				"application will not use", tc.constName, bound, width)
		}
	}
}
