package spec_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A job that runs tests/spec has to check out the history those gates read.
//
// actions/checkout defaults to a depth-1 clone with no tags. Several gates in
// tests/spec read git, and what they do without history is not fail -- it is
// SKIP. chart_immutable_selector_test.go bails with "no release tag other than
// <self> is reachable from HEAD", and that is the gate holding the chart's
// spec.selector immutable, which is the upgrade failure docs/UPGRADING.md warns
// about in every single section. A skipped assertion reports as a pass, so the
// job was green on a check it never ran.
//
// This is the third time the shape has bitten. ci.yml already guards the same
// failure for a different reason two ways -- it refuses to start if helm is
// missing, because "the rendered-manifest assertions in tests/spec would skip
// and report green" -- and the release workflow's own coverage job carries that
// helm guard while checking out shallow. The reasoning was there; it had not
// been pointed at git.
//
// The gate is on the property rather than on the three job names, because the
// next workflow to run the suite will have a different one.

// specSuiteMarkers are the strings that identify a job as running tests/spec.
//
// `./tests/spec` with the leading slash-dot rather than bare `tests/spec`,
// deliberately: ci.yml's helm guard echoes the words "in tests/spec would skip
// and report green" inside a run block, and matching that would flag a job for
// its error message rather than for what it executes.
var specSuiteMarkers = []string{"./tests/spec", "cov_run"}

func TestWorkflowsRunningTheSpecSuiteCheckOutHistory(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	type checkout struct {
		with map[string]any
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		var wf struct {
			Jobs map[string]struct {
				Steps []struct {
					Uses string         `yaml:"uses"`
					Run  string         `yaml:"run"`
					With map[string]any `yaml:"with"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}

		names := make([]string, 0, len(wf.Jobs))
		for name := range wf.Jobs {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			job := wf.Jobs[name]

			var script strings.Builder
			var checkouts []checkout
			for _, st := range job.Steps {
				script.WriteString(st.Run)
				script.WriteString("\n")
				if strings.Contains(st.Uses, "actions/checkout") {
					checkouts = append(checkouts, checkout{with: st.With})
				}
			}

			runsSuite := false
			for _, marker := range specSuiteMarkers {
				if strings.Contains(script.String(), marker) {
					runsSuite = true
					break
				}
			}
			if !runsSuite {
				continue
			}
			checked++

			if len(checkouts) == 0 {
				t.Errorf("%s job %q runs the spec suite and never checks the repository out",
					e.Name(), name)
				continue
			}
			for _, co := range checkouts {
				// 0 means full history. fetch-tags alone is not enough and is
				// not accepted: it brings the tag refs into a depth-1 clone
				// without the commits they point at, so `git ls-tree <tag>`
				// then fails on a missing object instead of reading it.
				if depth, ok := co.with["fetch-depth"]; !ok || depth != 0 {
					t.Errorf("%s job %q runs the spec suite and checks out with fetch-depth=%v.\n"+
						"Those gates read git history, and without it they SKIP rather than "+
						"fail -- so the job goes green on assertions it never made. Set "+
						"fetch-depth: 0.", e.Name(), name, co.with["fetch-depth"])
				}
			}
		}
	}

	// A gate that matched nothing would pass. Three jobs run the suite today;
	// asserting the floor means a marker that stops matching fails here rather
	// than going quiet.
	if checked < 3 {
		t.Errorf("only %d jobs were recognized as running the spec suite, and there are at "+
			"least three. Either specSuiteMarkers stopped matching how the suite is invoked, "+
			"or the workflows stopped running it.", checked)
	}
}
