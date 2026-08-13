// Floating-tag gate for the release workflow.
//
// The release trigger accepts prerelease tags: `v[0-9]+.[0-9]+.[0-9]+-*` is a
// push filter of its own, the detect job's version regex admits an optional
// `-suffix`, and the GitHub release is marked prerelease when the version
// carries one. The images job did not know any of that. It pushed
// `ghcr.io/42-v/vault42:latest` beside the version tag on every run, so a single
// `v1.1.0-rc.1` tag moved the floating tag onto a release candidate.
//
// `:latest` is what an untagged `docker pull ghcr.io/42-v/vault42` resolves to,
// what the published quickstarts tell readers to run, and what any deployment
// left on a floating tag pulls on its next restart. Moving it onto a candidate
// build ships unfinished code to everyone who never asked for a candidate,
// silently, with no version number changing anywhere they can see.
//
// The property held here: a release publishes `:latest` when it is final and
// does not when it is a prerelease. It is checked by replaying the workflow's own
// version parsing and tag computation offline, for a final tag and for two
// prerelease tags, so a rewrite that keeps the rule keeps passing while one that
// drops it goes red without waiting for a real tag push to teach us.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// tagStep is the part of a release.yml step this gate reads. `with` is untyped
// because build-push-action mixes strings and booleans in one mapping.
type tagStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

type tagJob struct {
	Outputs map[string]string `yaml:"outputs"`
	Steps   []tagStep         `yaml:"steps"`
}

type tagWorkflow struct {
	Jobs map[string]tagJob `yaml:"jobs"`
}

// tagReplaySHA stands in for the released commit. The tag rule does not depend
// on which commit is published, only on the version it is published under.
const tagReplaySHA = "0123456789abcdef0123456789abcdef01234567"

// buildPushAction is the action whose `tags` input decides what the registry
// ends up holding.
const buildPushAction = "docker/build-push-action"

// tagExpr matches one `${{ ... }}` interpolation.
var tagExpr = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

// tagContext is the slice of GitHub Actions context this gate models: enough to
// replay a tag push offline.
type tagContext struct {
	refName string
	sha     string
	needs   map[string]map[string]string
	steps   map[string]map[string]string
}

func newTagContext(refName string) tagContext {
	return tagContext{
		refName: refName,
		sha:     tagReplaySHA,
		needs:   map[string]map[string]string{},
		steps:   map[string]map[string]string{},
	}
}

// expand resolves the interpolations in a workflow string against the replayed
// contexts. An expression it cannot resolve is an error rather than a silent
// pass-through, because a tag list this gate misreads is a tag list it does not
// actually guard.
func (c tagContext) expand(s string) (string, error) {
	var unresolved []string

	out := tagExpr.ReplaceAllStringFunc(s, func(match string) string {
		expr := strings.TrimSpace(tagExpr.FindStringSubmatch(match)[1])
		switch {
		case expr == "github.sha":
			return c.sha
		case expr == "github.ref_name":
			return c.refName
		case expr == "inputs.version":
			// A tag push carries no dispatch input.
			return ""
		case strings.HasPrefix(expr, "needs."), strings.HasPrefix(expr, "steps."):
			parts := strings.Split(expr, ".")
			if len(parts) == 4 && parts[2] == "outputs" {
				source := c.needs
				if parts[0] == "steps" {
					source = c.steps
				}
				if value, ok := source[parts[1]][parts[3]]; ok {
					return value
				}
			}
		}
		unresolved = append(unresolved, expr)
		return match
	})

	if len(unresolved) > 0 {
		return "", fmt.Errorf("cannot replay expression %s", strings.Join(unresolved, ", "))
	}
	return out, nil
}

// parseReleaseForTags reads release.yml into the shape above.
func parseReleaseForTags(t *testing.T, root string) tagWorkflow {
	t.Helper()

	path := filepath.Join(root, ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf tagWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	for _, name := range []string{"detect", "images"} {
		if _, ok := wf.Jobs[name]; !ok {
			t.Fatalf("release.yml has no %q job; the release was restructured and this gate has "+
				"stopped seeing what it guards", name)
		}
	}
	return wf
}

// runTagStep executes one step's shell the way the runner would and returns what
// it wrote to GITHUB_OUTPUT.
func runTagStep(t *testing.T, root string, step tagStep, ctx tagContext) map[string]string {
	t.Helper()

	script, err := ctx.expand(step.Run)
	if err != nil {
		t.Fatalf("release.yml step %q: %v", step.Name, err)
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write replay script: %v", err)
	}
	outputPath := filepath.Join(dir, "github_output")
	if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
		t.Fatalf("write replay output file: %v", err)
	}

	env := append(os.Environ(), "GITHUB_OUTPUT="+outputPath)
	for name, raw := range step.Env {
		value, err := ctx.expand(raw)
		if err != nil {
			t.Fatalf("release.yml step %q env %s: %v. Whether a version is a prerelease is decided "+
				"once, in the detect job, and passed down; a step that works it out again drifts from "+
				"the job that decides how the release itself is published, and the registry and the "+
				"GitHub release then disagree about what the version means", step.Name, name, err)
		}
		env = append(env, name+"="+value)
	}

	// The runner's default shell for a run block, so a step that leans on -e or
	// on pipefail behaves here exactly as it does in CI.
	cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", scriptPath) // #nosec G204 -- script written by this test
	cmd.Dir = root
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release.yml step %q rejects %s, so that version cannot be released at all: %v\n%s",
			step.Name, ctx.refName, err, out)
	}

	return parseGitHubOutput(t, outputPath)
}

// parseGitHubOutput reads the GITHUB_OUTPUT file format: `key=value` lines plus
// the heredoc form a multi-line value has to use.
func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()

	data, err := os.ReadFile(path) // #nosec G304 -- the file is created by this test
	if err != nil {
		t.Fatalf("read replayed step output: %v", err)
	}

	out := map[string]string{}
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if key, delimiter, ok := strings.Cut(lines[i], "<<"); ok {
			var body []string
			for i++; i < len(lines) && lines[i] != delimiter; i++ {
				body = append(body, lines[i])
			}
			out[key] = strings.Join(body, "\n")
			continue
		}
		if key, value, ok := strings.Cut(lines[i], "="); ok {
			out[key] = value
		}
	}
	return out
}

// replayDetectOutputs runs the steps behind the detect job's outputs and returns
// the outputs the downstream jobs would see.
func replayDetectOutputs(t *testing.T, root string, wf tagWorkflow, ctx tagContext) map[string]string {
	t.Helper()

	job := wf.Jobs["detect"]
	wanted := outputStepIDs(job.Outputs)
	for _, step := range job.Steps {
		if step.ID != "" && wanted[step.ID] {
			ctx.steps[step.ID] = runTagStep(t, root, step, ctx)
		}
	}

	out := map[string]string{}
	for name, raw := range job.Outputs {
		value, err := ctx.expand(raw)
		if err != nil {
			t.Fatalf("detect output %s: %v", name, err)
		}
		out[name] = value
	}
	return out
}

// replayImageTags replays the images job and returns, per build step, the tag
// list the registry would receive.
func replayImageTags(t *testing.T, root string, wf tagWorkflow, ctx tagContext) map[string][]string {
	t.Helper()

	job := wf.Jobs["images"]

	raw := map[string]string{}
	for _, step := range job.Steps {
		if !strings.Contains(step.Uses, buildPushAction) {
			continue
		}
		tags, ok := step.With["tags"].(string)
		if !ok {
			t.Fatalf("release.yml step %q passes no tags to %s, so nothing says what the image it "+
				"pushes is called", step.Name, buildPushAction)
		}
		raw[step.Name] = tags
	}
	if len(raw) == 0 {
		t.Fatal("no step in the images job builds and pushes an image; the release was restructured " +
			"and this gate has stopped seeing what it guards")
	}

	// Only the steps a tag list depends on are replayed. The rest of the job
	// signs images and reads git metadata, which this gate has no business
	// running.
	wanted := outputStepIDs(raw)
	for _, step := range job.Steps {
		if step.ID != "" && wanted[step.ID] {
			ctx.steps[step.ID] = runTagStep(t, root, step, ctx)
		}
	}

	out := map[string][]string{}
	for name, tags := range raw {
		expanded, err := ctx.expand(tags)
		if err != nil {
			t.Fatalf("release.yml step %q: %v. Whether a version is a prerelease is answered once, in "+
				"the detect job, and passed down; a job that re-derives it drifts from the job that "+
				"decides how the release itself is published", name, err)
		}
		for _, tag := range strings.Split(expanded, "\n") {
			if tag = strings.TrimSpace(tag); tag != "" {
				out[name] = append(out[name], tag)
			}
		}
	}
	return out
}

// outputStepIDs collects the step ids the given workflow strings read outputs
// from.
func outputStepIDs(values map[string]string) map[string]bool {
	ids := map[string]bool{}
	for _, value := range values {
		for _, match := range tagExpr.FindAllStringSubmatch(value, -1) {
			parts := strings.Split(strings.TrimSpace(match[1]), ".")
			if len(parts) == 4 && parts[0] == "steps" && parts[2] == "outputs" {
				ids[parts[1]] = true
			}
		}
	}
	return ids
}

// TestPrereleaseNeverMovesTheLatestTag fails when the tags a release would push
// disagree with what its version means.
func TestPrereleaseNeverMovesTheLatestTag(t *testing.T) {
	root := repoRoot(t)
	wf := parseReleaseForTags(t, root)

	cases := []struct {
		refName string
		final   bool
	}{
		{refName: "v1.0.0", final: true},
		{refName: "v1.1.0-rc.1", final: false},
		{refName: "v2.0.0-beta.2", final: false},
	}

	for _, tc := range cases {
		t.Run(tc.refName, func(t *testing.T) {
			version := strings.TrimPrefix(tc.refName, "v")

			ctx := newTagContext(tc.refName)
			ctx.needs["detect"] = replayDetectOutputs(t, root, wf, ctx)
			if got := ctx.needs["detect"]["version"]; got != version {
				t.Fatalf("detect reads %s as version %q, so every artifact would be published under "+
					"the wrong number", tc.refName, got)
			}

			for step, tags := range replayImageTags(t, root, wf, ctx) {
				var versioned bool
				var floating []string
				for _, tag := range tags {
					switch {
					case strings.HasSuffix(tag, ":"+version):
						versioned = true
					case strings.HasSuffix(tag, ":latest"):
						floating = append(floating, tag)
					}
				}

				if !versioned {
					t.Errorf("%s publishes no tag ending in :%s for %s, so the release notes point "+
						"readers at an image reference the registry does not hold. Tags: %s",
						step, version, tc.refName, strings.Join(tags, ", "))
				}
				switch {
				case tc.final && len(floating) == 0:
					t.Errorf("%s publishes no :latest tag for final release %s, so an untagged "+
						"`docker pull` and every deployment left on the floating tag keeps serving "+
						"the release before it. Tags: %s",
						step, tc.refName, strings.Join(tags, ", "))
				case !tc.final && len(floating) > 0:
					t.Errorf("%s publishes %s while releasing prerelease %s, so an untagged "+
						"`docker pull` and every deployment left on the floating tag hands a release "+
						"candidate to consumers who never asked for one",
						step, strings.Join(floating, ", "), tc.refName)
				}
			}
		})
	}
}

// TestTheImagesJobTakesItsPrereleaseAnswerFromDetect keeps one definition of
// what a prerelease is.
//
// detect already parses the version, and its regex is the only place that states
// a `-suffix` is legal. A job that re-derives the answer from the version string
// is a second definition, and two definitions drift: the release can be marked
// prerelease on GitHub while the registry treats it as final, or the reverse,
// with nothing failing to say so.
func TestTheImagesJobTakesItsPrereleaseAnswerFromDetect(t *testing.T) {
	root := repoRoot(t)
	wf := parseReleaseForTags(t, root)

	const (
		finalRef      = "v1.0.0"
		prereleaseRef = "v1.1.0-rc.1"
	)
	final := replayDetectOutputs(t, root, wf, newTagContext(finalRef))
	prerelease := replayDetectOutputs(t, root, wf, newTagContext(prereleaseRef))

	// An output that only restates the version is not a classification: it still
	// leaves the reading of it to whoever consumes it.
	var classifications []string
	for name, value := range final {
		if strings.Contains(value, strings.TrimPrefix(finalRef, "v")) ||
			strings.Contains(prerelease[name], strings.TrimPrefix(prereleaseRef, "v")) {
			continue
		}
		if value != prerelease[name] {
			classifications = append(classifications, name)
		}
	}
	sort.Strings(classifications)

	if len(classifications) == 0 {
		t.Fatalf("the detect job publishes no output that tells %s and %s apart, so every job that "+
			"has to treat a prerelease differently reads the version string for itself and they "+
			"drift apart", finalRef, prereleaseRef)
	}

	for _, step := range wf.Jobs["images"].Steps {
		text := step.Run + fmt.Sprint(step.Env) + fmt.Sprint(step.With)
		for _, name := range classifications {
			if strings.Contains(text, "needs.detect.outputs."+name) {
				return
			}
		}
	}
	t.Errorf("the images job never reads detect's %s output, so what the registry does with a "+
		"prerelease is decided somewhere other than where a prerelease is defined",
		strings.Join(classifications, " or "))
}
