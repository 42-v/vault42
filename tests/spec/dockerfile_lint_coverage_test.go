// Dockerfile lint coverage gate.
//
// CI lints Dockerfiles through a hadolint matrix that names each file by hand.
// web/Dockerfile was never in it, so the one image in this repo that actually
// shipped a problem, nginx running as root on a writable root filesystem with
// its tag defaulting to latest, was also the one image no linter read.
//
// A hand-maintained matrix fails quietly in exactly one direction: adding a
// Dockerfile and forgetting the matrix entry looks like a passing build. Nothing
// reports that a file went unlinted, because nothing knows the file exists.
//
// This compares the matrix against the tree, so the omission becomes a failing
// test rather than a silence.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryDockerfileIsLintedByCI fails when a Dockerfile exists that the
// hadolint matrix does not name.
func TestEveryDockerfileIsLintedByCI(t *testing.T) {
	root := repoRoot(t)

	matrix := hadolintMatrix(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	if len(matrix) == 0 {
		t.Fatal("no dockerfile entries were parsed out of the hadolint matrix in ci.yml, so this " +
			"gate would pass no matter what the tree holds")
	}

	for _, found := range repoDockerfiles(t, root) {
		if !matrix[found] {
			t.Errorf("%s exists but the hadolint matrix in .github/workflows/ci.yml does not name "+
				"it, so nothing lints it. The matrix is maintained by hand and only fails in this "+
				"direction: the build stays green and the file is simply never read.", found)
		}
	}
}

// TestTheHadolintMatrixNamesOnlyRealFiles catches the opposite drift. A matrix
// entry for a file that no longer exists makes hadolint fail on a missing path,
// or worse, silently lint nothing while the job reports success.
func TestTheHadolintMatrixNamesOnlyRealFiles(t *testing.T) {
	root := repoRoot(t)

	for name := range hadolintMatrix(t, filepath.Join(root, ".github", "workflows", "ci.yml")) {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("the hadolint matrix names %q, which does not exist: %v", name, err)
		}
	}
}

// hadolintMatrix reads the dockerfile list out of the lint job.
//
// Parsed as indented list items under a `dockerfile:` key rather than with a
// YAML library, to keep tests/spec free of a parser dependency for one list. The
// shape is asserted rather than assumed: an empty result fails the caller above,
// so a reformatted workflow surfaces as a failure and not as a gate that quietly
// checks nothing.
func hadolintMatrix(t *testing.T, path string) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	var inList bool
	for _, line := range strings.Split(readFileString(t, path), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "dockerfile:" {
			inList = true
			continue
		}
		if !inList {
			continue
		}
		if !strings.HasPrefix(trimmed, "- ") {
			inList = false
			continue
		}
		out[strings.Trim(strings.TrimPrefix(trimmed, "- "), `"'`)] = true
	}
	return out
}

// repoDockerfiles walks the tree for anything hadolint would recognize.
func repoDockerfiles(t *testing.T, root string) []string {
	t.Helper()

	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "Dockerfile") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo for Dockerfiles: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no Dockerfiles were found, so this gate proves nothing")
	}
	return found
}
