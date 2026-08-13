// Release-ref gate.
//
// release.yml is tag-driven, and it also offers a workflow_dispatch path so a
// registry outage can be retried without burning a version number. That path
// takes a version string and nothing else. Every job then runs actions/checkout
// with no ref, which checks out GITHUB_SHA, and GITHUB_SHA on a
// workflow_dispatch is the head of whatever ref the run was started from. The
// version input never reaches a checkout.
//
// So dispatching 1.0.0 from main, after main has picked up commits since v1.0.0
// was cut, builds main and publishes it as 1.0.0: images retagged 1.0.0, a chart
// packaged 1.0.0, NuGet packages versioned 1.0.0, and archives attached to the
// v1.0.0 GitHub release. The tag still names the reviewed commit, so anyone who
// checks out v1.0.0 and rebuilds gets a different artifact than the registry
// serves, and nothing in the run says so. Version consistency does not catch it,
// because VERSION keeps the released value until the next bump lands, so main
// still reads 1.0.0 long after the tag was cut.
//
// The fix keeps GITHUB_SHA authoritative and refuses any run whose commit is not
// the released tag's commit. That is the only shape that stays consistent with
// the rest of the file, since GITHUB_SHA is also what the ancestor check, the
// sha- image tags, the GIT_COMMIT build arg and the release body record.
// Pointing the checkouts at the tag instead would leave all four naming a commit
// that is not the one they describe.
//
// The gate executes the detect job's guards against a purpose-built repository
// rather than reading them, so it measures what they do and not how they are
// spelled.
//
// The tests never write to the source tree. The fixture lives entirely inside
// the test's temporary directory.
package spec_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// dispatchStep is the part of a release.yml step this gate reads. Running a
// guard needs its script and the environment the runner would hand it, and
// `with` is untyped because checkout mixes strings and numbers in one mapping.
type dispatchStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

type dispatchWorkflow struct {
	Jobs map[string]struct {
		Steps []dispatchStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// fixtureVersion is the version the fixture repository is tagged at. Any
// semantic version works; this one matches the release being cut so the failure
// text reads like the incident it describes.
const fixtureVersion = "1.0.0"

// parseReleaseForDispatch reads release.yml with the step detail this gate needs.
func parseReleaseForDispatch(t *testing.T, root string) dispatchWorkflow {
	t.Helper()

	path := filepath.Join(root, ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf dispatchWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("release.yml declares no jobs; this gate cannot prove anything against an empty set")
	}
	return wf
}

// fixtureEnv isolates git from the developer running the suite. A global
// commit.gpgsign, an init template hook or a proxy setting would otherwise make
// this gate fail for reasons that have nothing to do with the release workflow.
func fixtureEnv(home string) []string {
	return []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"),
		"GIT_CONFIG_SYSTEM=" + filepath.Join(home, "gitconfig-system"),
		"GIT_AUTHOR_NAME=spec",
		"GIT_AUTHOR_EMAIL=spec@example.invalid",
		"GIT_COMMITTER_NAME=spec",
		"GIT_COMMITTER_EMAIL=spec@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	}
}

// fixtureGit runs one git command against the fixture.
func fixtureGit(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...) // #nosec G204 -- arguments are fixture paths this test built
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// releaseFixture builds a repository shaped like the one a re-release runs
// against: a tag at the reviewed commit, and a main branch that has moved on
// since. That gap is the whole defect, so the fixture has to contain it.
func releaseFixture(t *testing.T) (origin, root, taggedSHA, mainSHA string, env []string) {
	t.Helper()

	root = t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create fixture home: %v", err)
	}
	env = fixtureEnv(home)

	origin = filepath.Join(root, "origin.git")
	fixtureGit(t, root, env, "init", "--quiet", "--bare", "-b", "main", origin)

	seed := filepath.Join(root, "seed")
	fixtureGit(t, root, env, "init", "--quiet", "-b", "main", seed)

	if err := os.WriteFile(filepath.Join(seed, "VERSION"), []byte(fixtureVersion+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture VERSION: %v", err)
	}
	fixtureGit(t, seed, env, "add", "VERSION")
	fixtureGit(t, seed, env, "commit", "--quiet", "-m", "release "+fixtureVersion)
	fixtureGit(t, seed, env, "tag", "-a", "v"+fixtureVersion, "-m", "v"+fixtureVersion)
	taggedSHA = fixtureGit(t, seed, env, "rev-parse", "HEAD")

	// The commit that makes the two trees differ. VERSION deliberately stays at
	// the released value, because that is what main looks like between a release
	// and the next bump, and it is why version consistency waves this run
	// through.
	if err := os.WriteFile(filepath.Join(seed, "NOTES.md"), []byte("landed after the tag\n"), 0o600); err != nil {
		t.Fatalf("write fixture NOTES.md: %v", err)
	}
	fixtureGit(t, seed, env, "add", "NOTES.md")
	fixtureGit(t, seed, env, "commit", "--quiet", "-m", "feat: landed after the tag")
	mainSHA = fixtureGit(t, seed, env, "rev-parse", "HEAD")

	fixtureGit(t, seed, env, "remote", "add", "origin", origin)
	fixtureGit(t, seed, env, "push", "--quiet", "origin", "main", "--tags")

	return origin, root, taggedSHA, mainSHA, env
}

// fixtureWorkspaceAt reproduces what actions/checkout leaves on disk for a run
// whose GITHUB_SHA is sha: that commit checked out, with origin reachable.
func fixtureWorkspaceAt(t *testing.T, root, origin, sha string, env []string) string {
	t.Helper()

	work := filepath.Join(root, "work-"+sha[:8])
	fixtureGit(t, root, env, "clone", "--quiet", origin, work)
	fixtureGit(t, work, env, "checkout", "--quiet", "--detach", sha)
	return work
}

// detectGuards returns the detect job's run steps that reason about which commit
// the release is building. Selecting them by their use of GITHUB_SHA rather than
// by name means renaming a guard does not quietly drop it from this gate.
func detectGuards(t *testing.T, wf dispatchWorkflow) []dispatchStep {
	t.Helper()

	detect, ok := wf.Jobs["detect"]
	if !ok {
		t.Fatal("release.yml has no detect job; this gate has stopped seeing what it guards")
	}

	var guards []dispatchStep
	for _, step := range detect.Steps {
		if strings.Contains(step.Run, "GITHUB_SHA") {
			guards = append(guards, step)
		}
	}
	if len(guards) == 0 {
		t.Fatal("no step in release.yml's detect job examines GITHUB_SHA, so nothing checks which " +
			"commit the release publishes")
	}
	return guards
}

// guardEnvValue resolves the workflow expressions a guard may be handed on the
// dispatch this gate replays. An expression it does not model is refused rather
// than guessed, because a gate that invents a value proves nothing about the
// real run.
func guardEnvValue(t *testing.T, stepName, key, raw, refName string) string {
	t.Helper()

	switch strings.Join(strings.Fields(raw), " ") {
	case "${{ steps.parse.outputs.tag }}":
		return "v" + fixtureVersion
	case "${{ steps.parse.outputs.version }}", "${{ inputs.version }}":
		return fixtureVersion
	case "${{ github.ref_name }}":
		return refName
	case "${{ github.event_name }}":
		return "workflow_dispatch"
	}
	if strings.Contains(raw, "${{") {
		t.Fatalf("detect step %q sets %s from the workflow expression %q, which this gate does not "+
			"model, so the guard would go untested. Drive it from the version or tag that parse "+
			"already resolved.", stepName, key, raw)
	}
	return raw
}

// runDetectGuards executes the guards the way the runner would and reports
// whether they let the run proceed.
//
// Step-level `if:` conditions are ignored on purpose. A guard that only fires on
// one trigger still has to hold on the trigger this gate replays, and skipping a
// guard because of a condition this gate misread is how a green run would stop
// meaning anything.
func runDetectGuards(t *testing.T, guards []dispatchStep, work, sha, refName string, env []string) (string, bool) {
	t.Helper()

	scripts := t.TempDir()
	var log strings.Builder

	for i, step := range guards {
		// GitHub expands ${{ }} before bash sees the script, so an expression
		// inline in a run body is both untestable here and the shape that lets a
		// value carrying shell metacharacters become a command. Guards keep
		// their inputs in env.
		if strings.Contains(step.Run, "${{") {
			t.Fatalf("detect step %q interpolates a workflow expression into its script. Pass the "+
				"value through env: instead, so the guard can be exercised here and so a crafted "+
				"value cannot become a command.", step.Name)
		}

		path := filepath.Join(scripts, fmt.Sprintf("guard-%d.sh", i))
		if err := os.WriteFile(path, []byte(step.Run), 0o600); err != nil {
			t.Fatalf("write guard script: %v", err)
		}

		stepEnv := append([]string{}, env...)
		stepEnv = append(stepEnv,
			"GITHUB_SHA="+sha,
			"GITHUB_REF_NAME="+refName,
			"GITHUB_OUTPUT="+filepath.Join(scripts, "output"),
			"GITHUB_ENV="+filepath.Join(scripts, "env"),
		)
		for key, raw := range step.Env {
			stepEnv = append(stepEnv, key+"="+guardEnvValue(t, step.Name, key, raw, refName))
		}

		// The runner's default shell for a run block, so a guard relying on -e or
		// on pipefail behaves here exactly as it does in CI.
		cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", path) // #nosec G204 -- the script is written to this test's temp dir
		cmd.Dir = work
		cmd.Env = stepEnv
		out, err := cmd.CombinedOutput()

		fmt.Fprintf(&log, "--- %s ---\n%s", step.Name, out)
		if err != nil {
			fmt.Fprintf(&log, "(exit: %v)\n", err)
			return log.String(), false
		}
	}
	return log.String(), true
}

// TestDetectRefusesToPublishACommitTheTagDoesNotName is the gate on the
// re-release path.
//
// It runs the detect job's guards twice against one repository: once as a
// dispatch started from main, which is the failure being closed, and once as a
// run started from the tag, which has to keep working or the dispatch path is
// decoration.
func TestDetectRefusesToPublishACommitTheTagDoesNotName(t *testing.T) {
	guards := detectGuards(t, parseReleaseForDispatch(t, repoRoot(t)))
	origin, root, taggedSHA, mainSHA, env := releaseFixture(t)

	t.Run("dispatch from main is refused", func(t *testing.T) {
		work := fixtureWorkspaceAt(t, root, origin, mainSHA, env)
		log, proceeded := runDetectGuards(t, guards, work, mainSHA, "main", env)
		if proceeded {
			t.Errorf("detect accepted a v%s release whose commit is %s, while the tag names %s.\n"+
				"Every job checks out GITHUB_SHA, so this run builds main and publishes it as %s: "+
				"images, chart, NuGet packages and release archives all carry a version number whose "+
				"tag points somewhere else, and anyone rebuilding from v%s gets a different artifact "+
				"than the registry serves.\n%s",
				fixtureVersion, mainSHA, taggedSHA, fixtureVersion, fixtureVersion, log)
		}
	})

	t.Run("run from the tag proceeds", func(t *testing.T) {
		work := fixtureWorkspaceAt(t, root, origin, taggedSHA, env)
		log, proceeded := runDetectGuards(t, guards, work, taggedSHA, "v"+fixtureVersion, env)
		if !proceeded {
			t.Errorf("detect rejected a v%s release started from the tag's own commit %s.\n"+
				"That is the only supported way to re-run a release, so a registry outage costs a "+
				"version number again.\n%s", fixtureVersion, taggedSHA, log)
		}
	})
}

// TestReleaseJobsBuildTheCommitDetectValidated keeps the guard meaningful.
//
// detect proves one commit is the released tag's commit, and every other job
// inherits that proof only by checking out the same commit, which is what
// actions/checkout does when no ref is given. A job naming its own ref builds a
// tree nobody validated and publishes it under the released version, which is
// the failure detect exists to prevent.
func TestReleaseJobsBuildTheCommitDetectValidated(t *testing.T) {
	wf := parseReleaseForDispatch(t, repoRoot(t))

	var checkouts int
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !strings.Contains(step.Uses, "actions/checkout") {
				continue
			}
			checkouts++

			raw, ok := step.With["ref"]
			if !ok {
				continue
			}
			ref := fmt.Sprint(raw)
			if strings.Contains(ref, "needs.detect.outputs.tag") ||
				strings.Contains(ref, "steps.parse.outputs.tag") ||
				strings.Contains(ref, "github.sha") {
				continue
			}
			t.Errorf("release.yml job %q checks out ref %q instead of the commit detect validated "+
				"against the released tag, so it builds and publishes a tree no gate has seen.",
				name, ref)
		}
	}

	if checkouts == 0 {
		t.Fatal("no job in release.yml checks out the repository; this gate has stopped seeing what " +
			"it guards")
	}
}
