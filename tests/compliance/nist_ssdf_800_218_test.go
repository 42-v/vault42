package compliance

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1
//
// SSDF describes practices rather than controls, which makes it easy to claim
// and hard to evidence: "we review code" is not a fact a reader can check.
//
// The rule here is that every SSDF row names a workflow job or a tracked file,
// and this file asserts the named thing exists and does what the row says. A
// practice nobody automated is a practice nobody performs on the release that
// happens at 2am, so a row backed by a CI job is worth more than a row backed
// by a policy sentence.
//
// The delta was mostly writing down what already happens. The one place the
// register says so out loud is PO.3.2: there is no dependency-update automation
// in .github/, and the row says that rather than implying a scheduled scan is
// the same thing.
// =============================================================================

// workflowJob is a job the register cites as evidence for an SSDF practice.
type workflowJob struct {
	workflow string
	job      string
	practice string
	does     string
}

var ssdfJobs = []workflowJob{
	{
		"ci.yml", "modules", "PW.4.1 / PW.4.4",
		"reuses well-secured software: go mod verify checks every dependency against its recorded hash, and go mod tidy -diff fails if the manifest and the imports disagree",
	},
	{
		"ci.yml", "golangci", "PW.7.2",
		"automated review: the linters run on every pull request rather than being a habit",
	},
	{
		"ci.yml", "test", "PW.8.2",
		"tests the executable code: the compliance, spec, unit and attack suites",
	},
	{
		"ci.yml", "fuzz", "PW.8.2",
		"tests the executable code: fuzz targets over the parsers",
	},
	{
		"ci.yml", "chart", "PW.9.1",
		"secure-by-default configuration: every values file is rendered so a default that stops parsing stops the build",
	},
	{
		"nightly-security.yml", "govulncheck", "RV.1.1",
		"identifies vulnerabilities on an ongoing basis: govulncheck against the Go vulnerability database",
	},
	{
		"nightly-security.yml", "gosec", "RV.1.2",
		"reviews the code for residual vulnerabilities: static analysis",
	},
	{
		"nightly-security.yml", "trivy-source", "RV.1.1",
		"identifies vulnerabilities in dependencies",
	},
	{
		"nightly-security.yml", "trivy-image", "RV.1.1",
		"identifies vulnerabilities in the shipped image, not only in the source",
	},
	{
		"release.yml", "images", "PS.2.1 / PS.3.1",
		"provides a verification mechanism and archives the release: BuildKit provenance, SBOM and keyless cosign signatures over each image digest",
	},
	{
		"release.yml", "artifacts", "PS.1.1 / PS.2.1",
		"protects and verifies the released code: SHA256SUMS, syft SBOMs and a cosign signature over the checksum file",
	},
}

// TestSSDF_800_218_EveryCitedPracticeIsAutomated asserts that each job the
// register names exists in the workflow it names.
//
// A register row citing a job that has been renamed or deleted is the same
// defect as a Met row naming a test that does not exist, and the fix is the
// same: check it.
func TestSSDF_800_218_EveryCitedPracticeIsAutomated(t *testing.T) {
	root := repoRoot(t)
	jobHeading := regexp.MustCompile(`(?m)^  ([A-Za-z0-9_-]+):$`)

	cache := map[string]map[string]struct{}{}
	for _, j := range ssdfJobs {
		jobs, seen := cache[j.workflow]
		if !seen {
			raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", j.workflow))
			if err != nil {
				t.Errorf("SSDF: .github/workflows/%s is cited as evidence and does not exist", j.workflow)
				cache[j.workflow] = map[string]struct{}{}
				continue
			}
			jobs = map[string]struct{}{}
			for _, m := range jobHeading.FindAllStringSubmatch(string(raw), -1) {
				jobs[m[1]] = struct{}{}
			}
			if len(jobs) < 2 {
				t.Fatalf("SSDF: only %d jobs parsed out of %s; the scan is broken and would pass "+
					"vacuously", len(jobs), j.workflow)
			}
			cache[j.workflow] = jobs
		}
		if _, ok := jobs[j.job]; !ok {
			t.Errorf("SSDF %s: the register cites the %q job in .github/workflows/%s, which does not "+
				"exist. It was the automation for %s.", j.practice, j.job, j.workflow, j.does)
		}
	}
	t.Logf("SSDF: %d cited workflow jobs resolved", len(ssdfJobs))
}

// TestSSDF_800_218_ReleaseIntegrityMechanismsArePresent checks the PS practices
// by their artifacts rather than by the job names that produce them: PS.1 asks
// that the released code be protected from unauthorized change, PS.2 that a
// verification mechanism be provided, PS.3 that each release be archived with
// its provenance.
func TestSSDF_800_218_ReleaseIntegrityMechanismsArePresent(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	for _, want := range []struct{ token, practice, why string }{
		{"cosign sign --yes", "PS.2.1", "the verification mechanism for the images is a keyless signature over each digest"},
		{"provenance: true", "PS.3.2", "BuildKit provenance records how each image was built"},
		{"sbom: true", "PS.3.2", "an SBOM records what went into each image"},
		{"id-token: write", "PS.2.1", "keyless signing needs the OIDC token; without it the signature step is inert"},
	} {
		if !strings.Contains(release, want.token) {
			t.Errorf("SSDF %s: .github/workflows/release.yml no longer contains %q -- %s",
				want.practice, want.token, want.why)
		}
	}

	goreleaser := readProductionSource(t, ".goreleaser.yaml")
	for _, want := range []struct{ token, practice, why string }{
		{"checksum:", "PS.1.1", "the checksum file is what the single signature covers"},
		{"sboms:", "PS.3.2", "the release archives carry their own SBOMs"},
		{"signs:", "PS.2.1", "a detached signature over the checksum file verifies every archive at once"},
	} {
		if !strings.Contains(goreleaser, want.token) {
			t.Errorf("SSDF %s: .goreleaser.yaml no longer declares %q -- %s",
				want.practice, want.token, want.why)
		}
	}

	// PO.3.1: the toolchain is pinned, not floating. A build that resolves its
	// own tool versions at run time cannot be reproduced or attested.
	ci := readWorkflow(t, "ci.yml")
	if !strings.Contains(ci, "go-version-file: go.mod") {
		t.Error("SSDF PO.3.1: CI no longer pins the Go toolchain to go.mod, so the version that " +
			"builds a release is whatever the runner had that day")
	}
	nightly := readWorkflow(t, "nightly-security.yml")
	for _, pinned := range []string{"golang.org/x/vuln/cmd/govulncheck@v", "github.com/securego/gosec/v2/cmd/gosec@v"} {
		if !strings.Contains(nightly, pinned) {
			t.Errorf("SSDF PO.3.1: the security scanner %q is no longer installed at a pinned "+
				"version, so a scan result is not attributable to a known tool", pinned)
		}
	}
}

// TestSSDF_800_218_GovernanceArtifactsExist covers the PO and RV rows that rest
// on a tracked file rather than on a job: an owner for review (PO.2.1, PW.7.1)
// and a route for a report to arrive by (RV.1.3, RV.2.1).
func TestSSDF_800_218_GovernanceArtifactsExist(t *testing.T) {
	root := repoRoot(t)

	for _, f := range []struct{ path, practice, why string }{
		{".github/CODEOWNERS", "PO.2.1 / PW.7.1", "review has a named owner rather than whoever is around"},
		{"SECURITY.md", "RV.1.3 / RV.2.1", "a vulnerability report has a documented route in, and a documented policy for what happens next"},
		{"LICENSE", "PO.1.1", "the terms under which the software is released are stated"},
		{"CHANGELOG.md", "PS.3.1", "each release records what changed in it"},
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f.path))); err != nil {
			t.Errorf("SSDF %s: %s is missing -- %s", f.practice, f.path, f.why)
		}
	}

	// RV.2.1 is only satisfied if SECURITY.md says how to report and what to
	// expect, not merely that it exists.
	sec := readProductionSource(t, "SECURITY.md")
	if !strings.Contains(sec, "@") && !strings.Contains(strings.ToLower(sec), "advisor") {
		t.Error("SSDF RV.2.1: SECURITY.md names no channel for a report to arrive by")
	}
}

// TestSSDF_800_218_DependencyUpdateAutomationIsAutomated replaces the assertion
// that this practice was not performed.
//
// PO.3.2 asks that the toolchain be configured to improve the security of the
// software it produces, and an automated dependency-update tool was the one
// piece missing: nightly govulncheck and Trivy report a vulnerable dependency,
// and neither raises the pull request that fixes it. The register carried that
// distinction as CR-32 rather than letting the scanners stand in for an
// updater, and the test written to fail the day a configuration appeared is
// what moved the row.
//
// It now asserts the configuration exists and covers the ecosystems this
// repository actually has. A dependabot file that watches only GitHub Actions
// would satisfy "a file exists" while leaving the Go and pnpm dependency trees
// exactly as unmanaged as before.
func TestSSDF_800_218_DependencyUpdateAutomationIsAutomated(t *testing.T) {
	root := repoRoot(t)

	var config string
	for _, candidate := range []string{
		".github/dependabot.yml", ".github/dependabot.yaml",
		"renovate.json", ".renovaterc", ".renovaterc.json", ".github/renovate.json",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(candidate)))
		if err == nil {
			config = string(raw)
			t.Logf("SSDF PO.3.2: dependency updates configured by %s", candidate)
			break
		}
	}
	if config == "" {
		t.Fatal("SSDF PO.3.2: no dependency-update configuration exists. The register carries this " +
			"practice as Met on the strength of one; a scheduled scan is not an updater, because it " +
			"reports a vulnerable dependency and does not raise the pull request that fixes it.")
	}

	// The ecosystems the repository has, each with what goes unmanaged without
	// it. github-actions matters here specifically: every third-party action is
	// pinned to a commit SHA, which is the right thing and also the thing that
	// makes a human upgrade unlikely to happen by hand.
	for _, ecosystem := range []struct{ token, why string }{
		{"gomod", "the Go module graph, which is where govulncheck's findings live"},
		{"npm", "the pnpm workspace behind web/ and packages/"},
		{"github-actions", "the SHA-pinned third-party actions, which nobody bumps by hand"},
	} {
		if !strings.Contains(config, ecosystem.token) {
			t.Errorf("SSDF PO.3.2: the dependency-update configuration does not cover %q, so %s is "+
				"still updated only when somebody notices", ecosystem.token, ecosystem.why)
		}
	}
}

// readWorkflow is a small helper so a missing workflow fails with the practice
// it was evidence for rather than with a bare file-not-found.
func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", name))
	if err != nil {
		t.Fatalf("SSDF: .github/workflows/%s is cited across several rows and could not be read: %v", name, err)
	}
	return string(raw)
}

// publishedImageDockerfiles are the three Dockerfiles that .github/workflows/
// release.yml actually builds and pushes. Dockerfile.goreleaser* copy a
// prebuilt binary and compile nothing, so they are linted and scanned but have
// no build flags to check.
var publishedImageDockerfiles = []string{
	"Dockerfile",
	"Dockerfile.admin-gateway",
	"Dockerfile.bridge",
}

// hardeningBuildFlags are the `go build` flags a released binary is compiled
// with, and the reason each one is not optional.
var hardeningBuildFlags = []struct{ flag, why string }{
	{"-trimpath", "without it Go records every package's absolute build directory in the binary, so the image binary carries /build paths that the archive binary does not"},
	{"-buildvcs=false", "the default is `auto`, which stamps VCS state including a dirty-tree flag; .dockerignore excludes .git so it currently finds nothing, and saying `false` keeps a change to .dockerignore from quietly starting to stamp one in"},
	{"CGO_ENABLED=0", "a cgo build links against the builder's libc and stops being a static binary the distroless base can run"},
}

// TestSSDF_800_218_ImageAndArchiveBuildsUseTheSameFlags covers PW.6.1 and
// PW.6.2: choose build tool features that improve the security of the
// executable, and configure them consistently.
//
// vault42 ships the same three programs twice, by two different routes.
// .goreleaser.yaml compiles the release archives; the three Dockerfiles compile
// the images. They are supposed to be the same binary, and for two releases
// they were not: the goreleaser builds set -trimpath and -buildvcs=false and the
// Dockerfiles set neither, so `strings` on the image binary listed build paths
// that `strings` on the archive binary did not.
//
// Nothing caught it because nothing compared them. Both paths were individually
// correct-looking, both were linted, and the flags live in different files in
// different syntaxes. This is the comparison.
func TestSSDF_800_218_ImageAndArchiveBuildsUseTheSameFlags(t *testing.T) {
	goreleaser := readProductionSource(t, ".goreleaser.yaml")

	for _, want := range hardeningBuildFlags {
		if !strings.Contains(goreleaser, want.flag) {
			t.Errorf("SSDF PW.6.2: .goreleaser.yaml no longer sets %s -- %s", want.flag, want.why)
		}
	}

	goBuild := regexp.MustCompile(`(?s)go build\s*\\?\s*\n(.*?)-o\s`)

	for _, name := range publishedImageDockerfiles {
		source := readProductionSource(t, name)

		if !strings.Contains(source, "go build") {
			t.Errorf("SSDF PW.6.2: %s no longer compiles anything, so either it stopped being a "+
				"published image or this list is stale", name)
			continue
		}

		// Scoped to the build invocation. A flag named only in a comment
		// explaining why it is set would otherwise satisfy this.
		invocation := goBuild.FindStringSubmatch(source)
		if invocation == nil {
			t.Errorf("SSDF PW.6.2: could not find the `go build` invocation in %s; the scan is "+
				"broken and every assertion below it would pass vacuously", name)
			continue
		}

		for _, want := range hardeningBuildFlags {
			// CGO_ENABLED is an environment assignment on the line before the
			// flags, so it is checked against the whole RUN step.
			haystack := invocation[1]
			if strings.HasPrefix(want.flag, "CGO_") {
				haystack = source
			}
			if !strings.Contains(haystack, want.flag) {
				t.Errorf("SSDF PW.6.2: %s builds without %s while .goreleaser.yaml sets it. The "+
					"image and the archive are supposed to hold the same binary. %s",
					name, want.flag, want.why)
			}
		}
	}
}

// numberWords spells the job count the way CONTRIBUTING.md writes it. The
// document says "All eighteen jobs" in prose and then lists them, and the prose
// is the half a reader trusts without counting.
var numberWords = map[int]string{
	12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
	17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty",
	21: "twenty-one", 22: "twenty-two", 23: "twenty-three", 24: "twenty-four",
}

var (
	ciJobBlock     = regexp.MustCompile(`(?m)^jobs:\s*$`)
	ciJobName      = regexp.MustCompile(`(?m)^    name: (.+)$`)
	ciJobStart     = regexp.MustCompile(`(?m)^  ([a-z0-9][a-z0-9-]*):\s*$`)
	contributesRow = regexp.MustCompile(`(?m)^\| ([^|]+?) \|`)
)

// TestSSDF_800_218_TheDocumentedCIGatesAreTheOnesThatRun covers PO.4.1 and
// PW.8.1: define the criteria for the security checks a change must pass, and
// decide what testing is performed. Both are decisions, and a decision is only
// evidence if it is written down accurately.
//
// CONTRIBUTING.md carries that decision as a table of every CI job and what it
// does. 1.0.1 added three jobs -- the .NET coverage gate, its required watcher,
// and the non-Go linters -- and the table was not touched. So the document told
// a contributor that the .NET packages were "not built on a pull request" and
// that four linter configurations were "invoked by nothing", on the release
// where both had just stopped being true, and it said "All fifteen jobs" over a
// workflow that had eighteen.
//
// Nothing was wrong with the pipeline. What was wrong is that the only
// description of it drifted three jobs behind, in the direction that tells a
// contributor to skip a check.
func TestSSDF_800_218_TheDocumentedCIGatesAreTheOnesThatRun(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")

	loc := ciJobBlock.FindStringIndex(ci)
	if loc == nil {
		t.Fatal("SSDF PO.4.1: ci.yml has no `jobs:` block; the scan is broken")
	}
	body := ci[loc[1]:]

	starts := ciJobStart.FindAllStringSubmatchIndex(body, -1)
	if len(starts) < 10 {
		t.Fatalf("SSDF PO.4.1: only %d jobs parsed out of ci.yml; the scan is broken and this "+
			"test would pass against a table describing a workflow that no longer exists",
			len(starts))
	}

	jobNames := make(map[string]string, len(starts))
	for i, m := range starts {
		end := len(body)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		id := body[m[2]:m[3]]
		block := body[m[1]:end]
		if nm := ciJobName.FindStringSubmatch(block); nm != nil {
			jobNames[strings.TrimSpace(nm[1])] = id
		} else {
			t.Errorf("SSDF PO.4.1: ci.yml job %q declares no `name:`, so it appears in the checks "+
				"list under its id and cannot be matched to the table in CONTRIBUTING.md", id)
		}
	}

	contributing := readProductionSource(t, "CONTRIBUTING.md")
	const heading = "## What CI runs on your pull request"
	idx := strings.Index(contributing, heading)
	if idx < 0 {
		t.Fatalf("SSDF PW.8.1: CONTRIBUTING.md no longer has a %q section, so the decision about "+
			"what a change is tested against is written down nowhere", heading)
	}
	section := contributing[idx:]
	if next := strings.Index(section[len(heading):], "\n## "); next >= 0 {
		section = section[:len(heading)+next]
	}

	documented := make(map[string]bool)
	for _, m := range contributesRow.FindAllStringSubmatch(section, -1) {
		cell := strings.TrimSpace(m[1])
		if cell == "Job" || strings.HasPrefix(cell, "-") {
			continue
		}
		documented[cell] = true
	}

	for name, id := range jobNames {
		if !documented[name] {
			t.Errorf("SSDF PO.4.1: ci.yml runs the %q job (%s) and CONTRIBUTING.md's table does "+
				"not list it. A gate a contributor is not told about is a gate they will be "+
				"surprised by, and the omission always points the same way: the table describes "+
				"fewer checks than run.", name, id)
		}
	}
	for name := range documented {
		if _, ok := jobNames[name]; !ok {
			t.Errorf("SSDF PO.4.1: CONTRIBUTING.md's table lists %q and ci.yml declares no job by "+
				"that name, so the document promises a check that does not run", name)
		}
	}

	// The prose count, which is the part read without counting the rows.
	word, ok := numberWords[len(jobNames)]
	if !ok {
		t.Fatalf("SSDF PO.4.1: ci.yml has %d jobs and numberWords has no spelling for it; extend "+
			"the map rather than dropping the assertion", len(jobNames))
	}
	if !strings.Contains(section, "All "+word+" jobs") {
		t.Errorf("SSDF PO.4.1: ci.yml has %d jobs and CONTRIBUTING.md does not say %q. The row "+
			"count and the sentence above it drifted apart once already, and the sentence is the "+
			"half a reader believes.", len(jobNames), "All "+word+" jobs")
	}
	t.Logf("SSDF PO.4.1: %d CI jobs, all documented", len(jobNames))
}

// TestSSDF_800_218_SecurityCheckCriteriaAreDefinedAndTracked covers PO.4.1,
// PO.4.2 and PW.4.2.
//
// PO.4.1 asks for defined criteria for software security checks, tracked
// through the lifecycle; PO.4.2 for the information supporting those criteria
// to be gathered and safeguarded. "We aim for high coverage" is neither. A
// criterion is a number a build fails against, and the supporting information
// is the artifact that lets somebody else recompute it.
//
// Here the criteria are three floors -- Go against the reachable set, the two
// frontend packages against their own thresholds, the .NET SDKs against 100.00
// with no exclusions file -- and the supporting information is the coverage
// profile, which the run keeps rather than deleting on exit.
func TestSSDF_800_218_SecurityCheckCriteriaAreDefinedAndTracked(t *testing.T) {
	root := repoRoot(t)

	// The Go criterion is "100% of reachable", and the denominator is the
	// exclusion file. An exclusion set that can grow is not a criterion.
	raw, err := os.ReadFile(filepath.Join(root, ".coverage-exclusions.json"))
	if err != nil {
		t.Fatalf("SSDF PO.4.1: .coverage-exclusions.json is the denominator of the Go coverage "+
			"claim and could not be read: %v", err)
	}
	var exclusions struct {
		Policy  []string `json:"policy"`
		Entries []struct {
			File          string `json:"file"`
			Line          int    `json:"line"`
			Confirmed     bool   `json:"confirmed"`
			Justification string `json:"justification"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &exclusions); err != nil {
		t.Fatalf("SSDF PO.4.1: parse .coverage-exclusions.json: %v", err)
	}
	if len(exclusions.Entries) == 0 {
		t.Fatal("SSDF PO.4.1: the exclusion set is empty; the scan is broken and the assertions " +
			"below would pass vacuously")
	}
	if len(exclusions.Policy) == 0 {
		t.Error("SSDF PO.4.1: .coverage-exclusions.json states no policy. The set is the fine " +
			"print on a headline number, and fine print with no stated rule is just a list.")
	}
	for _, e := range exclusions.Entries {
		if !e.Confirmed || strings.TrimSpace(e.Justification) == "" {
			t.Errorf("SSDF PO.4.1: exclusion %s:%d is unconfirmed or carries no justification. "+
				"Every excluded statement is one the headline figure does not measure, so an "+
				"unjustified entry is a silent reduction of the denominator.", e.File, e.Line)
		}
	}

	// The .NET criterion, which is a floor rather than a set.
	dotnet := readProductionSource(t, "scripts/dotnet-coverage.py")
	if !strings.Contains(dotnet, `default=100.0`) {
		t.Error("SSDF PO.4.1: scripts/dotnet-coverage.py no longer defaults its floor to 100.0. " +
			"The .NET packages went from 46 tests nobody built to a gate with no exclusions file, " +
			"and the floor is the whole of that gate.")
	}

	// The frontend criteria live with the packages they measure.
	for _, cfg := range []string{"web/vite.config.ts", "packages/vue/vite.config.ts"} {
		source := readProductionSource(t, cfg)
		if !strings.Contains(source, "thresholds") {
			t.Errorf("SSDF PO.4.1: %s declares no coverage thresholds, so the frontend suite "+
				"reports a number without failing on one", cfg)
		}
	}

	// PO.4.2: the evidence outlives the run that produced it.
	coverage := readProductionSource(t, "scripts/coverage.sh")
	if !strings.Contains(coverage, "coverage/coverage.out") {
		t.Error("SSDF PO.4.2: scripts/coverage.sh no longer keeps the profile at a fixed path. " +
			"The profile is the only artifact that can answer which statements are uncovered; a " +
			"run that deletes it leaves the generated report as the sole record, at package " +
			"granularity, and destroys its own evidence.")
	}
}

// TestSSDF_800_218_DesignAndRiskDecisionsAreRecorded covers PW.1.1 and PW.1.2:
// use a form of risk modeling, and track the resulting requirements, risks and
// design decisions.
//
// The artifacts are an accepted-risk log where each entry argues itself, an
// architecture document describing the flows an attacker would target, and an
// attack suite that encodes the attacks rather than describing them. The last
// is the one that makes this more than a filing exercise: an attack test is a
// threat model that fails the build when the mitigation is removed.
func TestSSDF_800_218_DesignAndRiskDecisionsAreRecorded(t *testing.T) {
	security := readProductionSource(t, "docs/security.md")
	risks := regexp.MustCompile(`(?m)^### AR-\d+`).FindAllString(security, -1)
	if len(risks) < 10 {
		t.Errorf("SSDF PW.1.2: docs/security.md carries %d AR-nn entries. The engineering "+
			"risk log is where a decision to accept something is written down; a log this short "+
			"means either the scan broke or the log stopped being kept.", len(risks))
	}
	for _, section := range []string{"## Accepted Risks", "## Resolved Risks"} {
		if !strings.Contains(security, section) {
			t.Errorf("SSDF PW.1.2: docs/security.md no longer has a %q section, so there is no "+
				"distinction between a risk taken on and one closed out", section)
		}
	}

	arch := readProductionSource(t, "docs/architecture.md")
	for _, flow := range []string{"Login Flow", "Token Refresh Flow", "Password Reset Flow", "OAuth2 Flow"} {
		if !strings.Contains(arch, flow) {
			t.Errorf("SSDF PW.1.1: docs/architecture.md no longer documents the %s. Risk modeling "+
				"needs something to model, and these are the flows that carry a credential.", flow)
		}
	}

	// The attack suite: risk modeling with a build failure attached.
	attackTests := countTestFuncs(t, filepath.Join(repoRoot(t), "tests", "attack"))
	if attackTests < 100 {
		t.Errorf("SSDF PW.1.1: tests/attack holds %d tests. This is where an attack model stops "+
			"being a document: each test is an attack that used to work or must never work, and a "+
			"suite this small is not modeling anything.", attackTests)
	}
	t.Logf("SSDF PW.1.1: %d attack tests, %d accepted-risk entries", attackTests, len(risks))
}

// TestSSDF_800_218_SecureCodingStandardIsEnforcedByTools covers PW.5.1: follow
// secure coding practices appropriate to the language.
//
// The standard is .golangci.yml, and what makes it a standard rather than a
// preference is that the workflow runs it as a gate and the whole-tree run is
// held against a baseline that only ratchets down.
func TestSSDF_800_218_SecureCodingStandardIsEnforcedByTools(t *testing.T) {
	config := readProductionSource(t, ".golangci.yml")

	// Linters that catch a class of defect rather than a style preference.
	for _, linter := range []struct{ name, catches string }{
		{"bodyclose", "an HTTP response body that is never closed, which leaks a connection per request"},
		{"errorlint", "an error compared with == rather than errors.Is, which stops matching the moment a wrapper is added"},
		{"nilerr", "a nil error returned from a branch that only runs when the error was non-nil"},
		{"sqlclosecheck", "a rows handle that is never closed"},
	} {
		if !strings.Contains(config, "- "+linter.name) {
			t.Errorf("SSDF PW.5.1: .golangci.yml no longer enables %s, which catches %s",
				linter.name, linter.catches)
		}
	}

	ci := readWorkflow(t, "ci.yml")
	if !strings.Contains(ci, "golangci-lint-action") {
		t.Error("SSDF PW.5.1: ci.yml no longer runs golangci-lint, so .golangci.yml describes a " +
			"standard nothing holds anyone to")
	}
	if !strings.Contains(ci, "golangci-lint run --timeout 15m ./...") {
		t.Error("SSDF PW.5.1: ci.yml no longer runs golangci-lint over the whole tree. The diff " +
			"gate (--new-from-merge-base) would be the only check left, and a finding in code " +
			"nobody touched stays findable but never fails anything. This ran against a " +
			"hand-maintained baseline until the backlog reached zero; the plain run is what " +
			"replaced it, and it is stricter, not looser.")
	}
}

// TestSSDF_800_218_ShippedDefaultsAreDocumentedAndRestrictive covers PW.9.1 and
// PW.9.2: define a secure baseline, then implement those defaults and document
// each one.
//
// The chart is where an operator meets the defaults, and the reason to assert
// them here rather than leave it to the Kubernetes PSS rows is that PW.9.2 is
// about the pairing: a default is only a default if the document a reader
// consults agrees with the file the cluster reads.
func TestSSDF_800_218_ShippedDefaultsAreDocumentedAndRestrictive(t *testing.T) {
	values := readProductionSource(t, "charts/vault/values.yaml")

	for _, setting := range []struct{ token, why string }{
		{"runAsNonRoot: true", "a container that can run as root does, unless something says otherwise"},
		{"readOnlyRootFilesystem: true", "a writable root filesystem is where a dropped payload lands"},
		{"allowPrivilegeEscalation: false", "without it a setuid binary inside the image is a path out"},
		{"type: RuntimeDefault", "the seccomp profile; Unconfined is the default when none is named"},
	} {
		if !strings.Contains(values, setting.token) {
			t.Errorf("SSDF PW.9.2: charts/vault/values.yaml no longer sets %q by default -- %s",
				setting.token, setting.why)
		}
	}

	config := readProductionSource(t, "docs/config.md")
	for _, documented := range []string{"VAULT_PROFILE", "_FILE"} {
		if !strings.Contains(config, documented) {
			t.Errorf("SSDF PW.9.2: docs/config.md no longer documents %s, which is one of the "+
				"mechanisms that decides what an unset setting becomes", documented)
		}
	}
}

// TestSSDF_800_218_VulnerabilityResponseProcessIsDocumented covers RV.2.2:
// plan and implement risk responses for vulnerabilities.
//
// RV.1.3 is satisfied by SECURITY.md existing and naming a route in. RV.2.2 is
// the half after the report arrives, and it is a separate claim: what happens
// between a valid report and a user finding out.
func TestSSDF_800_218_VulnerabilityResponseProcessIsDocumented(t *testing.T) {
	security := readProductionSource(t, "SECURITY.md")

	for _, step := range []struct{ token, why string }{
		{"## How a security fix ships", "the response has to be written down before it is needed, not decided during one"},
		{"### Response timeline", "a reporter who is not told when to expect an answer discloses on their own schedule"},
		{"## Supported Versions", "a fix is only a response for someone running a version that will receive it"},
		{"### Security", "the changelog section is the signal that a release is a security release"},
	} {
		if !strings.Contains(security, step.token) {
			t.Errorf("SSDF RV.2.2: SECURITY.md no longer contains %q -- %s", step.token, step.why)
		}
	}
}

// countTestFuncs counts Go test functions under dir, recursively.
func countTestFuncs(t *testing.T, dir string) int {
	t.Helper()

	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil //nolint:nilerr // a parse failure surfaces in the build, not here
		}
		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				count++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return count
}

// requiredWrapperSuffix is the naming convention for the always-run job that
// stands in front of a conditional gate.
const requiredWrapperSuffix = "-required"

// TestSSDF_800_218_EveryConditionalGateHasAnAlwaysRunWrapper covers PO.4.1 and
// PW.7.2: the criteria a change must pass have to be the criteria that actually
// block a merge.
//
// GitHub branch protection counts a skipped job as a passing one. A gate that
// is conditional -- "only when a Go file changed", "only when packages/dotnet
// changed" -- therefore cannot be required directly: requiring it would let
// every pull request that does not trigger it merge on a green tick the job
// never earned. The pattern is a second job that always runs, looks at both the
// condition and the gate's result, and fails when the gate was owed and did not
// pass.
//
// The rule was learned twice and applied twice, to the Go coverage gate and
// then to the .NET one, and missed the third case. golangci-lint is conditional
// on the same Go-changed flag, had no wrapper, and so was never among the
// required checks -- while the register's CR-36 listed it as one of them. The
// claim went unchallenged because nothing compared the register's sentence to
// the workflow.
//
// This test does not know what branch protection requires; that is a repository
// setting and not in the tree. It asserts the half that is: that a wrapper
// exists for every conditional gate that has one, that each wrapper always runs,
// and that each consults the job it fronts.
func TestSSDF_800_218_EveryConditionalGateHasAnAlwaysRunWrapper(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")

	loc := ciJobBlock.FindStringIndex(ci)
	if loc == nil {
		t.Fatal("SSDF PO.4.1: ci.yml has no `jobs:` block; the scan is broken")
	}
	body := ci[loc[1]:]

	starts := ciJobStart.FindAllStringSubmatchIndex(body, -1)
	blocks := make(map[string]string, len(starts))
	for i, m := range starts {
		end := len(body)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		blocks[body[m[2]:m[3]]] = body[m[1]:end]
	}
	if len(blocks) < 10 {
		t.Fatalf("SSDF PO.4.1: only %d jobs parsed out of ci.yml; the scan is broken", len(blocks))
	}

	wrappers := 0
	for id, block := range blocks {
		if !strings.HasSuffix(id, requiredWrapperSuffix) {
			continue
		}
		wrappers++
		guarded := strings.TrimSuffix(id, requiredWrapperSuffix)

		if _, ok := blocks[guarded]; !ok {
			t.Errorf("SSDF PO.4.1: ci.yml has a %q job and no %q job for it to front. A wrapper "+
				"with nothing behind it is a required check that asserts nothing.", id, guarded)
			continue
		}

		if !strings.Contains(block, "if: always()") {
			t.Errorf("SSDF PO.4.1: the %q job does not declare `if: always()`. A wrapper that can "+
				"itself be skipped reintroduces the exact problem it exists to solve, because "+
				"branch protection reads a skipped job as a passing one.", id)
		}

		if !strings.Contains(block, "needs."+guarded+".result") {
			t.Errorf("SSDF PO.4.1: the %q job never reads needs.%s.result, so it reports success "+
				"without looking at the gate it is named after", id, guarded)
		}

		// The condition, not just the result: a wrapper that fails whenever the
		// gate was skipped would block every pull request that legitimately does
		// not trigger it.
		if !strings.Contains(block, "needs.changes.outputs.") {
			t.Errorf("SSDF PO.4.1: the %q job does not consult the changes job, so it cannot tell "+
				"a gate that was skipped for a good reason from one that was owed", id)
		}
	}

	if wrappers < 3 {
		t.Errorf("SSDF PO.4.1: found %d required-wrappers in ci.yml, expected at least 3 (the Go "+
			"coverage gate, the .NET coverage gate and golangci-lint). A conditional gate that "+
			"loses its wrapper stops being requirable, and nothing else would say so.", wrappers)
	}
	t.Logf("SSDF PO.4.1: %d conditional gates carry an always-run wrapper", wrappers)
}
