package spec_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// =============================================================================
// A skipped test reports success.
//
// Seven chart assertions in this package skipped for an entire release because
// no CI job installed helm. `go test ./tests/spec/...` printed `ok`, the pull
// requests went green, and nobody counted the [no tests to run] lines. A skip
// and a pass are the same color, which makes a skipped gate strictly worse
// than a deleted one: the deleted gate is at least missing from the report.
//
// The rule this file implements: an external tool a gate cannot work without is
// *optional on a developer's machine* and *mandatory on a CI runner*. Locally,
// skipping keeps `go test ./...` usable without a Kubernetes toolchain
// installed. On a runner, the whole point of the job is to run the gate, so a
// missing tool is the job failing to do what it was asked, and it has to be
// red.
//
// tests/compliance/gate_liveness_test.go holds the registry of every skip in
// this suite and refuses an unregistered one.
// =============================================================================

// ciEnvVars are the environment variables a CI runner sets. GitHub Actions sets
// both; CI alone is the near-universal convention, and is what a self-hosted
// runner or a container job is most likely to carry.
var ciEnvVars = []string{"CI", "GITHUB_ACTIONS"}

// runningInCI reports whether this process is a CI runner rather than a
// developer's shell.
//
// An explicitly falsy value counts as not-CI, so `CI=false go test ./...`
// behaves the way a reader would expect rather than the way a naive
// `os.Getenv() != ""` would.
func runningInCI() bool {
	for _, key := range ciEnvVars {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "", "0", "false", "no", "off":
			continue
		default:
			return true
		}
	}
	return false
}

// toolAction is what the absence of an external tool means.
type toolAction int

const (
	// toolPresent: the tool resolved, so the gate runs.
	toolPresent toolAction = iota
	// toolMissingIsFatal: no tool, on a runner. The job exists to run this
	// gate; it did not run, so the job failed.
	toolMissingIsFatal
	// toolMissingIsSkip: no tool, on a developer's machine. Skipping keeps the
	// suite runnable without a Kubernetes toolchain; CI is what enforces it.
	toolMissingIsSkip
)

// missingToolAction is the decision, factored out of requireTool so it can be
// asserted directly rather than through a testing.T that would have to actually
// fail to be observed. TestAMissingToolIsFatalOnACIRunner is the assertion.
func missingToolAction(found, ci bool) toolAction {
	switch {
	case found:
		return toolPresent
	case ci:
		return toolMissingIsFatal
	default:
		return toolMissingIsSkip
	}
}

// requireTool resolves an external program a gate cannot run without, and
// decides what its absence means by missingToolAction.
//
// consequence names what stops being checked, so the CI failure says which
// property went unasserted rather than only which binary was missing.
func requireTool(t *testing.T, name, consequence string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	switch missingToolAction(err == nil, runningInCI()) {
	case toolPresent:
		return path
	case toolMissingIsFatal:
		t.Fatalf("%s is not on PATH and this is a CI runner (%s set), so %s. A skip here would "+
			"report the same green as a gate that ran, which is how seven chart assertions went "+
			"unasserted for a release. Install %s in the job.",
			name, strings.Join(setCIEnvVars(), ", "), consequence, name)
	case toolMissingIsSkip:
		t.Skipf("%s is not on PATH, so %s. This skips locally and fails on a CI runner; install "+
			"%s to run the gate here.", name, consequence, name)
	}
	return ""
}

// setCIEnvVars names the variables that made runningInCI true, so the failure
// message can be checked against the environment that produced it.
func setCIEnvVars() []string {
	var set []string
	for _, key := range ciEnvVars {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "", "0", "false", "no", "off":
			continue
		default:
			set = append(set, key+"="+os.Getenv(key))
		}
	}
	return set
}

// A missing tool must be fatal on a runner and a skip everywhere else. This is
// the whole claim of this file, and it is asserted rather than described,
// because the failure it prevents is invisible by construction.
func TestAMissingToolIsFatalOnACIRunner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		found bool
		ci    bool
		want  toolAction
	}{
		{"present on a runner", true, true, toolPresent},
		{"present locally", true, false, toolPresent},
		{"missing on a runner", false, true, toolMissingIsFatal},
		{"missing locally", false, false, toolMissingIsSkip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := missingToolAction(tc.found, tc.ci); got != tc.want {
				t.Errorf("missingToolAction(found=%v, ci=%v) = %v, want %v", tc.found, tc.ci, got, tc.want)
			}
		})
	}
}

// runningInCI has to read the runner's environment rather than a hardcoded
// variable name, and an explicitly falsy value has to mean what it says. A
// runner that sets CI=1 and nothing else must still be recognized, because the
// alternative is the silent-skip defect returning on a self-hosted runner.
func TestRunningInCIReadsTheRunnerEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"a developer shell", map[string]string{}, false},
		{"GitHub Actions", map[string]string{"CI": "true", "GITHUB_ACTIONS": "true"}, true},
		{"CI alone", map[string]string{"CI": "1"}, true},
		{"GITHUB_ACTIONS alone", map[string]string{"GITHUB_ACTIONS": "true"}, true},
		{"explicitly disabled", map[string]string{"CI": "false"}, false},
		{"empty is not set", map[string]string{"CI": ""}, false},
		{"zero is not set", map[string]string{"CI": "0"}, false},
		{"whitespace and case", map[string]string{"CI": "  TRUE  "}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range ciEnvVars {
				t.Setenv(key, "")
			}
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			if got := runningInCI(); got != tc.want {
				t.Errorf("runningInCI() = %v with %v, want %v", got, tc.env, tc.want)
			}
			if tc.want && len(setCIEnvVars()) == 0 {
				t.Errorf("runningInCI() is true with %v but setCIEnvVars() names nothing, so the "+
					"CI failure message could not say what made it fatal", tc.env)
			}
		})
	}
}
