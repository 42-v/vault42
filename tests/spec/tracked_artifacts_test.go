// Build-artifact tracking gate.
//
// Two compiled binaries were committed to this repository: `bridge` at 13.1 MB
// and `recover` at 13.6 MB, 26.7 MB of build output living beside the source
// that produces it. Nothing was wrong with the build; the problem is that they
// are tracked, and so every local `go build` in the repository root rewrites a
// tracked file.
//
// That is not cosmetic. An agent working in a sandbox worktree ran `go build`
// to verify its change, the harness's `git add -A` swept the rewritten binary
// into the task's commits, and a review diff that should have been seven source
// files was eight, one of which was 13 MB of unreadable object code. It also
// means anyone cloning the repository downloads two stale binaries built from
// whatever the committer's tree happened to be, which is a supply-chain
// question the release does not need to answer.
//
// The gate is on the property rather than on the two names, because the next
// one will be a different name. Any tracked file whose first bytes are an
// executable image fails, and a new binary at the repository root has to be
// gitignored before it can be committed.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// executableMagics are the leading bytes of the executable formats a Go build
// can emit. A tracked file starting with any of them is a build artifact
// regardless of what it is called.
var executableMagics = map[string][]byte{
	"ELF":                    {0x7f, 'E', 'L', 'F'},
	"Mach-O 64-bit":          {0xcf, 0xfa, 0xed, 0xfe},
	"Mach-O 64-bit (big)":    {0xfe, 0xed, 0xfa, 0xcf},
	"Mach-O universal":       {0xca, 0xfe, 0xba, 0xbe},
	"PE/COFF (DOS stub)":     {'M', 'Z'},
	"WebAssembly":            {0x00, 'a', 's', 'm'},
	"Linux a.out / obj dump": {0x01, 0xdf},
}

// trackedFiles lists everything git has under version control, using git itself
// rather than a directory walk so that ignored and untracked build output is
// invisible to this gate by construction.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()

	cmd := exec.Command("git", "-C", root, "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		t.Fatal("git ls-files returned nothing; this gate cannot prove anything against an empty set")
	}
	return files
}

// TestNoCompiledBinaryIsTracked fails when a file under version control starts
// with an executable image's magic bytes.
//
// It reads only the first bytes of each file, so it costs one small read per
// tracked file and does not care how large the artifact is.
func TestNoCompiledBinaryIsTracked(t *testing.T) {
	root := repoRoot(t)

	for _, name := range trackedFiles(t, root) {
		// Test fixtures are allowed to contain arbitrary bytes: a suite that
		// exercises binary handling needs a binary to hand it.
		if strings.Contains(name, "testdata/") {
			continue
		}

		head, err := readHead(filepath.Join(root, name), 4)
		if err != nil {
			// A tracked path that is not readable as a regular file (a submodule
			// gitlink, a symlink to nowhere) is not what this gate is about.
			continue
		}

		for format, magic := range executableMagics {
			if len(head) >= len(magic) && bytes.Equal(head[:len(magic)], magic) {
				t.Errorf("%s is a tracked %s executable. Committed build output is rewritten by "+
					"every local build, so it lands in unrelated commits and ships stale to "+
					"anyone who clones. Add it to .gitignore and `git rm --cached` it.",
					name, format)
			}
		}
	}
}

// TestRootBuildArtifactsAreIgnored is the forward half of the same property.
//
// Removing the two binaries makes the check above pass and leaves nothing
// stopping the next `go build ./cmd/bridge` from recreating and re-committing
// them, since a `git add -A` picks up whatever is untracked. Naming them in
// .gitignore is what makes the removal stick, so that is asserted separately
// rather than assumed.
func TestRootBuildArtifactsAreIgnored(t *testing.T) {
	root := repoRoot(t)

	// The command names that `go build ./cmd/<name>` drops in the repository
	// root when run without -o.
	for _, name := range commandNames(t, root) {
		cmd := exec.Command("git", "-C", root, "check-ignore", "-q", name)
		if err := cmd.Run(); err != nil {
			t.Errorf("a `go build ./cmd/%s` in the repository root writes ./%s, and that path is "+
				"not gitignored, so the next `git add -A` commits a build artifact.", name, name)
		}
	}
}

// readHead reads at most n leading bytes, which is all the magic check needs.
func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from git ls-files inside the repo
	if err != nil {
		return nil, err
	}
	defer f.Close() // #nosec G104 -- read-only handle

	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:read], nil
}

// commandNames lists the directories under cmd/, which are the binary names a
// bare `go build ./cmd/...` would leave in the repository root.
func commandNames(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("cmd/ holds no commands; this gate has stopped seeing what it guards")
	}
	return names
}
