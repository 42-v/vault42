package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The rehearsal has to rehearse the real thing.
//
// ci.yml carries a release-artifact-roundtrip job that uploads a set of files
// under the release's own names and downloads them again, because release.yml
// has no pull_request trigger: every change to it first executes during a
// release. actions/download-artifact was moved from v4 to v8 in a pull request
// and has never once run, and four major versions of path-handling behavior
// sit between the version that was tested and the version that will publish.
//
// A rehearsal is only worth its runtime while it exercises the same pair. Pin a
// different SHA in one file and the job still passes, still reports green, and
// tests an action the release does not use -- which is worse than not having it,
// because the name promises coverage that is not there.
//
// So this holds the two ends together: same action SHAs, same artifact path
// globs. The artifact NAME deliberately differs (release-artifacts versus
// release-artifacts-rehearsal) so a rehearsal running on a pull request can
// never collide with a real release's artifact in the same repository, and that
// difference is asserted too rather than left to look like drift.

const (
	rehearsalJob   = "release-artifact-roundtrip"
	publishJob     = "artifacts"
	consumerJob    = "github-release"
	uploadAction   = "actions/upload-artifact"
	downloadAction = "actions/download-artifact"
)

type wfJob struct {
	Name  string `yaml:"name"`
	Steps []struct {
		Name string         `yaml:"name"`
		Uses string         `yaml:"uses"`
		With map[string]any `yaml:"with"`
	} `yaml:"steps"`
}

func workflowJobs(t *testing.T, root, file string) map[string]wfJob {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var wf struct {
		Jobs map[string]wfJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return wf.Jobs
}

// stepUsing returns the first step in job whose `uses` names action, and the
// pinned reference it carries.
func stepUsing(t *testing.T, jobs map[string]wfJob, job, action string) (map[string]any, string) {
	t.Helper()
	j, ok := jobs[job]
	if !ok {
		t.Fatalf("no job %q; if it was renamed, rename it here too rather than deleting this gate", job)
	}
	for _, st := range j.Steps {
		if strings.HasPrefix(st.Uses, action+"@") {
			return st.With, st.Uses
		}
	}
	t.Fatalf("job %q has no step using %s", job, action)
	return nil, ""
}

func TestTheReleaseRehearsalPinsTheActionsTheReleaseUses(t *testing.T) {
	root := repoRoot(t)
	ci := workflowJobs(t, root, "ci.yml")
	release := workflowJobs(t, root, "release.yml")

	for _, tc := range []struct {
		action      string
		releaseJob  string
		whatItCosts string
	}{
		{
			uploadAction, publishJob,
			"the rehearsal would upload with one implementation and the release with another, " +
				"so a change in how paths are recorded goes untested",
		},
		{
			downloadAction, consumerJob,
			"the download is the half that has never executed, and it is the half that decides " +
				"whether the files land flat in dist/ or nested one directory down",
		},
	} {
		_, rehearsed := stepUsing(t, ci, rehearsalJob, tc.action)
		_, published := stepUsing(t, release, tc.releaseJob, tc.action)
		if rehearsed != published {
			t.Errorf("ci.yml %q pins %s and release.yml %q pins %s.\n%s.",
				rehearsalJob, rehearsed, tc.releaseJob, published, tc.whatItCosts)
		}
	}
}

// The globs decide which files reach the artifact at all, so rehearsing a
// different set rehearses a different question.
func TestTheReleaseRehearsalUploadsTheSameFileSet(t *testing.T) {
	root := repoRoot(t)
	rehearsalWith, _ := stepUsing(t, workflowJobs(t, root, "ci.yml"), rehearsalJob, uploadAction)
	releaseWith, _ := stepUsing(t, workflowJobs(t, root, "release.yml"), publishJob, uploadAction)

	globs := func(with map[string]any) []string {
		raw, _ := with["path"].(string)
		var out []string
		for _, line := range strings.Split(raw, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
		return out
	}

	got, want := globs(rehearsalWith), globs(releaseWith)
	if len(want) == 0 {
		t.Fatal("release.yml's artifact upload has no path globs; this gate compares them, so " +
			"an empty set would make it pass while comparing nothing")
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the rehearsal uploads %v and the release uploads %v.\n"+
			"The globs decide which files reach the artifact, so a rehearsal with a different "+
			"set proves the pair works for files the release does not ship.", got, want)
	}
}

// The names must differ, and for a reason worth stating rather than leaving to
// look like an oversight.
func TestTheRehearsalArtifactCannotCollideWithARealRelease(t *testing.T) {
	root := repoRoot(t)
	rehearsalWith, _ := stepUsing(t, workflowJobs(t, root, "ci.yml"), rehearsalJob, uploadAction)
	releaseWith, _ := stepUsing(t, workflowJobs(t, root, "release.yml"), publishJob, uploadAction)

	rehearsed, _ := rehearsalWith["name"].(string)
	published, _ := releaseWith["name"].(string)
	if rehearsed == "" || published == "" {
		t.Fatal("one of the two uploads has no artifact name")
	}
	if rehearsed == published {
		t.Errorf("both uploads use the artifact name %q. A pull-request rehearsal and a running "+
			"release would then write the same artifact in the same repository, and the release's "+
			"consumer could download the rehearsal's stand-in files -- which are one word of text "+
			"each and would satisfy every -s check in that job.", rehearsed)
	}
}
