// Release-signing wiring gate.
//
// cosign resolves registry credentials through go-containerregistry's default
// keychain, which reads ~/.docker/config.json. `helm registry login` does not
// write that file; it writes helm's own store at HELM_REGISTRY_CONFIG. A job
// that authenticates with helm and then signs with cosign is therefore not
// authenticated for the signing, and GHCR answers 401.
//
// The chart job did exactly that. Every release ran lint, package and push
// successfully, then failed on the last step, leaving the chart published in
// the registry and unsigned while the generated release notes told the reader
// it was cosign-signed. The images job had a docker/login-action from the
// start, so the two jobs sat in one file disagreeing about how to authenticate,
// and nothing could see it: workflow YAML has no type system, and the failure
// only appears on a real tag push against a real registry.
//
// The property checked here is the one that generalises. Any job that runs
// cosign must also perform a docker login, whatever else it does.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflowJob is the part of a GitHub Actions job this gate reads.
type workflowJob struct {
	Steps []struct {
		Name string `yaml:"name"`
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
	Needs yaml.Node `yaml:"needs"`
}

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

// parseWorkflow reads one workflow file.
func parseWorkflow(t *testing.T, root, name string) workflowFile {
	t.Helper()

	path := filepath.Join(root, ".github", "workflows", name)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s declares no jobs; this gate cannot prove anything against an empty set", name)
	}
	return wf
}

// TestEveryCosignJobLogsIntoTheRegistry fails when a job signs without having
// authenticated in a way cosign can see.
func TestEveryCosignJobLogsIntoTheRegistry(t *testing.T) {
	root := repoRoot(t)
	wf := parseWorkflow(t, root, "release.yml")

	var checked int
	for name, job := range wf.Jobs {
		var signs, dockerLogin, helmLogin bool
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "cosign sign") {
				signs = true
			}
			if strings.Contains(step.Uses, "docker/login-action") {
				dockerLogin = true
			}
			if strings.Contains(step.Run, "helm registry login") {
				helmLogin = true
			}
		}
		if !signs {
			continue
		}
		checked++

		if !dockerLogin {
			hint := ""
			if helmLogin {
				hint = " It runs `helm registry login`, which writes helm's own credential store " +
					"(HELM_REGISTRY_CONFIG) and not the ~/.docker/config.json cosign reads."
			}
			t.Errorf("release.yml job %q runs cosign sign with no docker/login-action step, so "+
				"cosign signs unauthenticated and the registry rejects it.%s", name, hint)
		}
	}

	if checked == 0 {
		t.Fatal("no job in release.yml runs cosign sign; signing was removed or renamed and this " +
			"gate has stopped seeing what it guards")
	}
}

// TestTheReleaseWaitsForEverythingItAdvertises keeps the announcement honest.
//
// github-release publishes notes that name the container images, the archives
// and the Helm chart, all at the released version. It depended on images and
// artifacts but not on chart, so a failed chart job produced a published
// release announcing a chart that was either missing or unsigned. nuget is
// deliberately excluded and stays excluded: it is a secondary consumer, it is
// independently retryable, and the notes do not promise it.
func TestTheReleaseWaitsForEverythingItAdvertises(t *testing.T) {
	root := repoRoot(t)
	wf := parseWorkflow(t, root, "release.yml")

	job, ok := wf.Jobs["github-release"]
	if !ok {
		t.Fatal("release.yml has no github-release job; this gate has stopped seeing what it guards")
	}

	var needs []string
	if err := job.Needs.Decode(&needs); err != nil {
		var single string
		if err := job.Needs.Decode(&single); err != nil {
			t.Fatalf("github-release needs is neither a list nor a string: %v", err)
		}
		needs = []string{single}
	}

	have := make(map[string]bool, len(needs))
	for _, n := range needs {
		have[n] = true
	}

	for _, want := range []string{"images", "artifacts", "chart"} {
		if !have[want] {
			t.Errorf("github-release does not depend on %q, so the release publishes and announces "+
				"that artifact even when the job producing it failed.", want)
		}
	}
}
