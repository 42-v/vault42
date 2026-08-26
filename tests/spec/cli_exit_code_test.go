package spec_test

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A CLI error has to reach the exit status, not only stderr.
//
// CLI.Run returns whether a command was RECOGNIZED. cmd/vault turned that
// straight into a bare return, so a subcommand that printed an error still
// exited 0 -- and every one of the thirty-four error paths in internal/cli did
// exactly that. The message reached whoever was reading stderr; the status
// reached whoever was not.
//
// That is worst where nothing reads stderr at all. `vault seed` is the
// documented way to seed declaratively from an init container, and an init
// container gates on the exit status: it saw success while nothing had been
// seeded and the workload started against an empty database.
//
// The failure is now recorded on the CLI and read once by cmd/vault. This gate
// holds the shape that makes that work: an error printed to stderr goes through
// fail, which is the only thing that sets the flag. A new subcommand written in
// the old style compiles, runs, prints, and exits 0 -- and fails here instead.
//
// The tests are read-only. They never write to the source tree.

var cliSource = filepath.Join("internal", "cli", "cli.go")

// The defect's exact shape: a stderr write that ENDS the command with an error,
// followed by a bare `return true`.
//
// Deliberately not every stderr write. This file also prints WARNINGs and NOTEs
// the command continues past -- the argv disclosure warning, the JWKS note, the
// admin-token-mismatch warning -- and none of those is a failed command. The
// admin-authentication refusal at Run is excluded too: it already calls
// exitProcess(1) on the next line, which is the older mechanism for the same
// thing and is correct where it is.
var errorWrite = regexp.MustCompile(`fmt\.Fprint(f|ln)\(os\.Stderr, "(ERROR:|Usage:)`)

func TestEveryCLIErrorPathReachesTheExitStatus(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), cliSource))
	lines := strings.Split(src, "\n")

	flagged := make([]string, 0, 4)
	var seen int
	inFail := false
	for i, line := range lines {
		if strings.Contains(line, "func (c *CLI) fail(") {
			inFail = true
			continue
		}
		if inFail {
			// The helper's own body is where the sanctioned write lives.
			if strings.HasPrefix(line, "}") {
				inFail = false
			}
			continue
		}
		if !errorWrite.MatchString(line) {
			continue
		}
		seen++
		// Only a failure if the command returns straight after. A write followed
		// by exitProcess, or by anything that keeps going, is not this defect.
		tail := lines[i+1:]
		if len(tail) > 3 {
			tail = tail[:3]
		}
		endsCommand := false
		for _, next := range tail {
			t := strings.TrimSpace(next)
			if t == "return true" {
				endsCommand = true
				break
			}
			if t != "" && !strings.HasPrefix(t, `"`) && !strings.HasSuffix(t, "+") {
				break
			}
		}
		if !endsCommand {
			continue
		}
		flagged = append(flagged, cliSource+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
	}

	if len(flagged) > 0 {
		t.Errorf("%d stderr write(s) in %s bypass fail(), so the message reaches the "+
			"operator and the exit status stays 0:\n\t%s\n"+
			"Route them through c.fail(...), which prints and records the failure that "+
			"cmd/vault turns into a non-zero exit.",
			len(flagged), cliSource, strings.Join(flagged, "\n\t"))
	}

	// The gate has to have looked at a file that still has error paths in it.
	if !strings.Contains(src, "return c.fail(") {
		t.Fatalf("no c.fail( call found in %s. If the mechanism was renamed, rename it here "+
			"too: what this holds is that a CLI failure changes the exit status.", cliSource)
	}
}

// And cmd/vault has to actually read the flag. Recording a failure nobody
// consults is the same silence with more code.
func TestCmdVaultExitsNonZeroOnAFailedCommand(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), "cmd", "vault", "main.go"))
	if !strings.Contains(src, "cliHandler.Failed()") {
		t.Error("cmd/vault/main.go does not consult cliHandler.Failed(), so a recognized " +
			"command that failed still exits 0 -- which is the defect the flag exists for")
	}
	if !strings.Contains(src, "os.Exit(1)") {
		t.Error("cmd/vault/main.go never exits non-zero, so nothing the CLI reports can " +
			"reach a caller that gates on the status")
	}
}
