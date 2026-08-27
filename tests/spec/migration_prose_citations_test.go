package spec_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A `file.go:NNN` citation in a migration header must land on the thing it names.
//
// 024 explains why two of five columns keep their vault_app grant, and cites the
// method that writes each one. One citation was exact; the other pointed at
// `user.go:202`, which is a comment line inside a different method's doc block.
// VerifyEmail is at :268. The neighboring citation being right is what made the
// wrong one read as verified.
//
// Line numbers in prose rot on the first edit above them, and nothing was
// checking these -- the register's citation gates cover docs/, not migrations/.
// There are only two such citations in the whole migrations tree, which is
// exactly the number a cheap gate can hold: it resolves each to the line it
// names and requires that line to DECLARE the symbol the prose claims is there.

var migrationCitation = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_]*)\.(\w+)\s+\((\w+\.go):(\d+)\)`)

func TestMigrationProseCitationsLandOnWhatTheyName(t *testing.T) {
	root := repoRoot(t)

	entries, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read migrations/: %v", err)
	}

	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src := readFileString(t, filepath.Join(root, "migrations", e.Name()))
		for _, m := range migrationCitation.FindAllStringSubmatch(src, -1) {
			receiver, method, file, lineStr := m[1], m[2], m[3], m[4]
			line, convErr := strconv.Atoi(lineStr)
			if convErr != nil {
				t.Errorf("%s cites %s:%s, which is not a line number", e.Name(), file, lineStr)
				continue
			}
			found++

			// The citation is a bare basename and several packages have a
			// user.go, so the RECEIVER disambiguates: the file meant is the one
			// that declares this method on it. Picking the first basename match
			// pointed at internal/handler/user.go and made both citations look
			// wrong when only one was.
			want := fmt.Sprintf("func (r *%s) %s(", receiver, method)
			paths := goFilesNamed(t, root, file)
			if len(paths) == 0 {
				t.Errorf("%s cites %s, and no such file exists under internal/", e.Name(), file)
				continue
			}
			var path string
			for _, p := range paths {
				if strings.Contains(readFileString(t, p), want) {
					if path != "" {
						t.Errorf("%s cites %s.%s and both %s and %s declare it; the citation "+
							"cannot be resolved", e.Name(), receiver, method, path, p)
					}
					path = p
				}
			}
			if path == "" {
				t.Errorf("%s cites %s.%s, and no %s under internal/ declares it. The method was "+
					"renamed or removed, and the reasoning that cites it needs rechecking, not "+
					"just the number.", e.Name(), receiver, method, file)
				continue
			}
			lines := strings.Split(readFileString(t, path), "\n")
			if line < 1 || line > len(lines) {
				t.Errorf("%s cites %s:%d and that file has %d lines", e.Name(), file, line, len(lines))
				continue
			}

			// The line must declare the method the prose names. A comment line
			// that happens to sit at the right number is the exact failure this
			// gate exists for.
			got := lines[line-1]
			if !strings.Contains(got, want) {
				where := declaringLine(lines, method)
				t.Errorf("%s cites %s.%s at %s:%d, but that line is:\n    %s\n"+
					"%s is declared at %s:%d. A citation that resolves to a comment reads as "+
					"verified and is not; correct the number rather than removing the citation.",
					e.Name(), receiver, method, file, line, strings.TrimSpace(got), method, file, where)
			}
		}
	}

	// If the citations disappear, this gate silently guards nothing. Say so.
	if found == 0 {
		t.Error("no `Receiver.Method (file.go:NNN)` citations were found in migrations/. " +
			"Either the convention changed -- in which case move this gate to whatever replaced " +
			"it -- or the prose that justified the grants is gone.")
	}
}

func goFilesNamed(t *testing.T, root, base string) []string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(filepath.Join(root, "internal"), func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a walk error just means this subtree contributes nothing
		}
		if filepath.Base(path) == base {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

// declaringLine reports the 1-indexed line that declares method, or 0.
func declaringLine(lines []string, method string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, "func ") && strings.Contains(l, ") "+method+"(") {
			return i + 1
		}
	}
	return 0
}
