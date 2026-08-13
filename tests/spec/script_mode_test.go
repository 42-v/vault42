// Executable-bit gate for the repository's own tooling.
//
// Before 1.0.0, 22 tracked shell scripts were committed with mode 100644 while
// README.md, CONTRIBUTING.md and CLAUDE.md all documented them as bare commands
// (`scripts/precommit.sh`, `scripts/coverage.sh`, `scripts/release-check.sh`).
// Every one of those documented invocations failed with "Permission denied" on a
// fresh clone. Nothing caught it because CI happened to reach its three scripts
// through paths that did not need the bit, and everyone else had a working tree
// old enough to predate the loss.
//
// Git tracks exactly one permission bit, so this is a property the repository
// can assert about itself: a file that starts with a shebang is a program, and a
// program that is not executable is broken. Checking the checked-out file mode
// rather than shelling out to `git ls-files -s` keeps the test dependency-free
// and still measures the same thing, because a checkout materializes the index
// mode onto disk.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// skipDirs are directories whose contents are not ours to assert on: build
// output, dependencies fetched by a package manager, and the scratch areas that
// are gitignored. Matching by base name rather than by path keeps a nested
// node_modules from slipping through.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"dist":         true,
	"coverage":     true,
	"tmp":          true,
	"secrets":      true,
}

// shebang is the two-byte prefix that makes a file a program to the kernel's
// execve. Nothing else in the tree is interpreted this way, so it is the exact
// boundary the executable bit has to agree with.
const shebang = "#!"

// hasShebang reports whether the file begins with "#!". It reads two bytes, not
// the whole file, so this stays cheap across a tree with hundreds of files.
func hasShebang(path string) (bool, error) {
	fh, err := os.Open(path) //nolint:gosec // path comes from a walk of this repo
	if err != nil {
		return false, err
	}
	defer func() { _ = fh.Close() }()

	buf := make([]byte, len(shebang))
	n, err := fh.Read(buf)
	if err != nil && n == 0 {
		// An empty file is not a program; a real read error is.
		if err.Error() == "EOF" {
			return false, nil
		}
		return false, nil
	}
	return string(buf[:n]) == shebang, nil
}

// repoRoot is shared with route_drift_test.go; every path in this file is
// repository-relative and resolved through it.

// TestShebangFilesAreExecutable fails when a program in the tree cannot be run.
//
// The failure message lists every offender with the exact fix, because the
// remedy is a mode change that is easy to make and easy to forget: `git
// update-index --chmod=+x` is what actually records it, and a plain `chmod +x`
// alone leaves the index untouched on some workflows.
func TestShebangFilesAreExecutable(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		ok, err := hasShebang(path)
		if err != nil || !ok {
			return nil //nolint:nilerr // an unreadable file is not this test's finding
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o111 == 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d file(s) start with a shebang but are not executable:\n  %s\n\n"+
			"Fix with:\n  git update-index --chmod=+x %s",
			len(offenders),
			strings.Join(offenders, "\n  "),
			strings.Join(offenders, " "))
	}
}

// documentedScripts are the scripts the published documentation tells a reader
// to run as a bare command. They are named explicitly rather than scraped out of
// the markdown, so that deleting the line from a doc does not silently drop the
// guarantee: if one of these stops being a documented entry point, removing it
// here is a deliberate edit.
var documentedScripts = []string{
	"scripts/build-all.sh",
	"scripts/check.sh",
	"scripts/coverage.sh",
	"scripts/deploy-dev.sh",
	"scripts/generate-secrets.sh",
	"scripts/loc.sh",
	"scripts/precommit.sh",
	"scripts/readme-gen.sh",
	"scripts/release-check.sh",
	"scripts/security-scan.sh",
	"scripts/setup-microk8s.sh",
	"scripts/t.sh",
	"scripts/tcount.sh",
	"scripts/version-bump.sh",
}

// TestDocumentedScriptsExistAndRun is the narrower, louder half of the gate: it
// names the scripts a user is told to type. TestShebangFilesAreExecutable would
// catch a missing bit on any of them, but only this test catches one being
// renamed or deleted out from under the documentation.
func TestDocumentedScriptsExistAndRun(t *testing.T) {
	root := repoRoot(t)

	for _, rel := range documentedScripts {
		t.Run(rel, func(t *testing.T) {
			info, err := os.Stat(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("documented in README.md/CONTRIBUTING.md/CLAUDE.md but not present: %v", err)
			}
			if info.Mode().Perm()&0o111 == 0 {
				t.Errorf("documented as a bare command but not executable (mode %v); "+
					"a fresh clone gets Permission denied", info.Mode().Perm())
			}
		})
	}
}
