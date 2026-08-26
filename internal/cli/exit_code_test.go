package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A recognized command that failed has to exit non-zero.
//
// Run's bool answers "was this a CLI invocation", which cmd/vault turned
// straight into a bare return -- so every error the CLI printed left the process
// exiting 0. The message reached the operator; the exit status did not.
//
// That is worst where nothing reads stderr. `vault seed` is the documented way
// to seed declaratively from an init container, and an init container gates on
// the exit status: it saw success while nothing had been seeded, and the
// workload came up against an empty database. The same held for every other
// subcommand, so this is not a seed-specific fix.

func TestFailed_IsFalseUntilACommandFails(t *testing.T) {
	c := &CLI{}
	if c.Failed() {
		t.Fatal("a CLI that has run nothing reports failure")
	}
}

func TestFail_MarksFailureAndStaysRecognized(t *testing.T) {
	c := &CLI{}
	// Recognized is the question Run's bool answers, and the answer is still
	// yes: `vault seed --file missing` is a seed invocation that failed, not an
	// unrecognized argument that should fall through to booting the server.
	if got := c.fail("ERROR: %v\n", os.ErrNotExist); !got {
		t.Error("fail reported the command unrecognized; cmd/vault would fall through to boot")
	}
	if !c.Failed() {
		t.Error("fail did not mark the command failed, so the process still exits 0")
	}
}

// The seed path end to end, because it is the one an init container gates on.
func TestRunSeed_MissingFileIsAFailure(t *testing.T) {
	c := &CLI{}
	if got := c.runSeed(context.Background(), []string{
		"vault", "seed", "--file",
		filepath.Join(t.TempDir(), "does-not-exist.json"),
	}); !got {
		t.Fatal("runSeed reported the command unrecognized")
	}
	if !c.Failed() {
		t.Error("a seed against a file that does not exist exited 0. An init container " +
			"gating on the status sees success and the workload starts against an " +
			"unseeded database.")
	}
}

func TestRunSeed_NoFileFlagIsAFailure(t *testing.T) {
	c := &CLI{}
	if got := c.runSeed(context.Background(), []string{"vault", "seed"}); !got {
		t.Fatal("runSeed reported the command unrecognized")
	}
	if !c.Failed() {
		t.Error("a usage error exited 0")
	}
}
