package compliance

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// OpenSSF Scorecard v5.5.0
//
// Scorecard is the one standard in this register whose assessor is not the
// maintainer: it runs weekly against the repository from outside, publishes its
// result to api.securityscorecards.dev, and scores the same twenty checks for
// every project. That makes it the closest thing here to an external audit, and
// the least forgiving place to overclaim -- a row asserting a check passes is
// contradicted by a URL anyone can open.
//
// Which is why the register carries the checks rather than a score. A score is
// one number over twenty weighted checks; the two this project cannot move
// (Contributors wants more than one organization, CII-Best-Practices wants a
// badge nobody has applied for) drag it down regardless of the eighteen it can,
// and quoting the number alone would either flatter or understate depending on
// which way the weighting fell that week.
//
// These tests assert the repository-side facts each Met row rests on. They
// cannot assert Scorecard's own verdict -- that needs the network and the live
// analysis -- so they assert the input: the workflow, the file, the pin, the
// permission block. When one of those disappears the row is wrong before the
// next weekly run says so.
// =============================================================================

// scorecardWorkflow is the workflow that produces the published result. Without
// it there is no external assessment at all and every row below is a claim
// about a run nobody performs.
const scorecardWorkflow = "scorecard.yml"

// TestScorecard_TheAssessmentItselfRuns is the gate under the other gates. The
// 1.0.0 release notes quoted a Scorecard score that no workflow produced and
// that api.securityscorecards.dev had never seen; the workflow exists now, and
// this is what keeps it existing.
func TestScorecard_TheAssessmentItselfRuns(t *testing.T) {
	wf := readWorkflow(t, scorecardWorkflow)

	for _, want := range []struct{ token, why string }{
		{"ossf/scorecard-action@", "the analysis is the action; nothing else produces a Scorecard result"},
		{"publish_results: true", "publishing is what makes the score checkable by someone who has never cloned this repository"},
		{"id-token: write", "the OIDC token is what the publish step authenticates with; without it the result stays private and the badge does not resolve"},
		{"security-events: write", "the SARIF upload is what puts a failing check in the Security tab instead of only in a log"},
		{"schedule:", "a push-only trigger reports a stale posture between releases: Scorecard reads repository settings and dependency metadata that change on their own schedule"},
	} {
		if !strings.Contains(wf, want.token) {
			t.Errorf("Scorecard: .github/workflows/%s no longer contains %q -- %s",
				scorecardWorkflow, want.token, want.why)
		}
	}
}

// TestScorecard_DependencyUpdateToolIsConfigured covers Dependency-Update-Tool.
//
// The check passes on the presence of the config, which is the weaker half of
// the claim. The stronger half is that the updates are actually taken: 1.0.1
// merged eighteen open dependabot pull requests that had accumulated behind
// 1.0.0, and the ecosystems below are the ones that opened them.
func TestScorecard_DependencyUpdateToolIsConfigured(t *testing.T) {
	cfg := readProductionSource(t, ".github/dependabot.yml")

	for _, ecosystem := range []string{"gomod", "github-actions", "docker", "npm", "nuget"} {
		if !strings.Contains(cfg, ecosystem) {
			t.Errorf("Scorecard Dependency-Update-Tool: .github/dependabot.yml no longer watches %q. "+
				"An ecosystem nobody watches is one where a known-vulnerable version sits until "+
				"someone happens to look.", ecosystem)
		}
	}
}

// TestScorecard_TokenPermissionsAreLeastPrivilege covers Token-Permissions.
//
// A top-level `permissions:` block is what turns the default write-all token
// into a read-only one. Without it every job in the workflow holds a token that
// can push to the repository, and any step that runs repository code -- the
// test suite, the attack suite -- runs holding it.
func TestScorecard_TokenPermissionsAreLeastPrivilege(t *testing.T) {
	topLevel := regexp.MustCompile(`(?m)^permissions:\s*$`)

	for _, wf := range workflowFiles(t) {
		raw := readWorkflow(t, wf)
		switch {
		case strings.Contains(raw, "\npermissions: read-all"):
			continue
		case strings.Contains(raw, "\npermissions:\n  contents: read"):
			continue
		case topLevel.MatchString(raw):
			continue
		}
		t.Errorf("Scorecard Token-Permissions: .github/workflows/%s declares no top-level "+
			"permissions block, so every job in it inherits the repository default. The default "+
			"is write.", wf)
	}
}

// TestScorecard_EveryActionIsPinnedByCommit covers Pinned-Dependencies for the
// half Scorecard weights highest.
//
// A tag is a mutable pointer. `uses: some/action@v4` runs whatever the owner of
// that repository has v4 pointing at when the job starts, which is a write
// primitive into this build held by every action author.
func TestScorecard_EveryActionIsPinnedByCommit(t *testing.T) {
	uses := regexp.MustCompile(`uses:\s+([^\s#]+)`)
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)

	pinnedCount := 0
	for _, wf := range workflowFiles(t) {
		for _, m := range uses.FindAllStringSubmatch(readWorkflow(t, wf), -1) {
			ref := m[1]
			// A local reusable workflow is this repository's own file and
			// travels with the commit that calls it.
			if strings.HasPrefix(ref, "./") {
				continue
			}
			at := strings.LastIndex(ref, "@")
			if at < 0 || !sha.MatchString(ref[at+1:]) {
				t.Errorf("Scorecard Pinned-Dependencies: .github/workflows/%s runs %q, which is not "+
					"pinned to a commit SHA.", wf, ref)
				continue
			}
			pinnedCount++
		}
	}
	if pinnedCount < 20 {
		t.Fatalf("Scorecard Pinned-Dependencies: only %d pinned action references found across the "+
			"workflows; the scan is broken and would pass vacuously", pinnedCount)
	}
	t.Logf("Scorecard Pinned-Dependencies: %d action references, all pinned by commit", pinnedCount)
}

// TestScorecard_BuildToolsResolveThroughAHash is the other half of
// Pinned-Dependencies, and the half that cost this repository a point at 1.0.0.
//
// An exact version is not a pin. `pip install ruff==0.16.3` asks PyPI for a name
// and installs whatever bytes come back, so a republished artifact or an account
// takeover executes in CI under a version string that never changed.
// unlockedNPM matches an npm invocation that resolves against the registry. The
// leading boundary keeps it off `pnpm install`, which is the lockfile-driven
// call this gate exists to protect.
var unlockedNPM = regexp.MustCompile(`(^|[^a-zA-Z])(npm install|npm i |npx )`)

func TestScorecard_BuildToolsResolveThroughAHash(t *testing.T) {
	root := repoRoot(t)

	requirements, err := os.ReadFile(filepath.Join(root, ".github", "requirements-lint.txt"))
	if err != nil {
		t.Fatalf("Scorecard Pinned-Dependencies: .github/requirements-lint.txt is missing, so the "+
			"lint job's Python dependencies resolve by name again: %v", err)
	}
	hashes := strings.Count(string(requirements), "--hash=sha256:")
	if hashes < 10 {
		t.Errorf("Scorecard Pinned-Dependencies: .github/requirements-lint.txt carries only %d "+
			"hashes. --require-hashes needs one for every artifact of every resolved package, "+
			"transitive ones included, so a file this short means the pins were hand-edited "+
			"rather than regenerated.", hashes)
	}

	ci := readWorkflow(t, "ci.yml")
	if !strings.Contains(ci, "--require-hashes") {
		t.Error("Scorecard Pinned-Dependencies: the lint job installs Python packages without " +
			"--require-hashes, which makes the hashes in requirements-lint.txt decorative")
	}
	// Comment lines are skipped on purpose: the workflow explains why this
	// stopped being an `npm install`, and matching the explanation would make
	// the gate fire on its own rationale.
	for _, line := range strings.Split(ci, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if unlockedNPM.MatchString(trimmed) {
			t.Errorf("Scorecard Pinned-Dependencies: ci.yml runs %q, which resolves against the "+
				"registry rather than against pnpm-lock.yaml's integrity hashes", trimmed)
		}
	}
}

// TestScorecard_StaticAnalysisAndFuzzingRun covers SAST and Fuzzing.
func TestScorecard_StaticAnalysisAndFuzzingRun(t *testing.T) {
	nightly := readWorkflow(t, "nightly-security.yml")
	for _, tool := range []string{"gosec", "govulncheck", "trivy"} {
		if !strings.Contains(strings.ToLower(nightly), tool) {
			t.Errorf("Scorecard SAST: %s no longer runs in nightly-security.yml", tool)
		}
	}

	ci := readWorkflow(t, "ci.yml")
	if !strings.Contains(ci, "golangci") {
		t.Error("Scorecard SAST: golangci-lint no longer runs on pull requests")
	}

	// Fuzzing scores on user-defined fuzz functions in the repository, so the
	// evidence is the targets rather than a workflow.
	targetCount := 0
	fuzzDir := filepath.Join(repoRoot(t), "tests", "fuzz")
	entries, err := os.ReadDir(fuzzDir)
	if err != nil {
		t.Fatalf("Scorecard Fuzzing: tests/fuzz is missing: %v", err)
	}
	fuzzFunc := regexp.MustCompile(`(?m)^func Fuzz[A-Za-z0-9_]*\(`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(fuzzDir, e.Name()))
		if readErr != nil {
			continue
		}
		targetCount += len(fuzzFunc.FindAllString(string(raw), -1))
	}
	if targetCount < 5 {
		t.Errorf("Scorecard Fuzzing: only %d fuzz targets found under tests/fuzz; the check scores "+
			"on user-defined fuzz functions and the register claims a fuzzed project", targetCount)
	}
	t.Logf("Scorecard Fuzzing: %d fuzz targets", targetCount)
}

// TestScorecard_ReleasesAreSigned covers Signed-Releases.
//
// The check reads the artifacts of published releases, which this suite cannot
// do offline, so it asserts what produces them.
func TestScorecard_ReleasesAreSigned(t *testing.T) {
	release := readWorkflow(t, "release.yml")
	for _, want := range []struct{ token, why string }{
		{"sigstore/cosign-installer@", "keyless signing needs cosign on the runner"},
		{"cosign sign --yes", "the images and the chart are signed by digest"},
		{"attest-build-provenance", "the provenance attestation is what ties an artifact to the workflow run that produced it"},
	} {
		if !strings.Contains(release, want.token) {
			t.Errorf("Scorecard Signed-Releases: .github/workflows/release.yml no longer contains "+
				"%q -- %s", want.token, want.why)
		}
	}

	goreleaser := readProductionSource(t, ".goreleaser.yaml")
	if !strings.Contains(goreleaser, "signs:") {
		t.Error("Scorecard Signed-Releases: .goreleaser.yaml no longer signs the checksum file, " +
			"so the binary archives have nothing verifying them")
	}
}

// TestScorecard_SbomIsProduced covers SBOM.
func TestScorecard_SbomIsProduced(t *testing.T) {
	release := readWorkflow(t, "release.yml")
	if !strings.Contains(release, "sbom-action/download-syft") {
		t.Error("Scorecard SBOM: syft is no longer installed in the release workflow")
	}
	if !strings.Contains(release, "sbom: true") {
		t.Error("Scorecard SBOM: the image build no longer attaches an SBOM")
	}
	if !strings.Contains(readProductionSource(t, ".goreleaser.yaml"), "sboms:") {
		t.Error("Scorecard SBOM: .goreleaser.yaml no longer emits SBOMs for the release archives")
	}
}

// TestScorecard_GovernanceFilesExist covers License, Security-Policy and
// Binary-Artifacts.
func TestScorecard_GovernanceFilesExist(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []struct{ path, check string }{
		{"LICENSE", "License"},
		{"SECURITY.md", "Security-Policy"},
	} {
		if _, err := os.Stat(filepath.Join(root, f.path)); err != nil {
			t.Errorf("Scorecard %s: %s is missing: %v", f.check, f.path, err)
		}
	}
}

// TestScorecard_TheReleaseHistoryIsRecorded covers Maintained.
//
// The check measures commit and issue activity, which no test can assert
// without asserting that the repository has recently been committed to -- a
// circular claim. What can be asserted is the artifact maintenance is supposed
// to leave behind: a version, and a changelog entry that names it. A release
// nobody wrote down is indistinguishable from one that did not happen.
func TestScorecard_TheReleaseHistoryIsRecorded(t *testing.T) {
	version := strings.TrimSpace(readProductionSource(t, "VERSION"))
	if version == "" {
		t.Fatal("Scorecard Maintained: VERSION is empty")
	}

	changelog := readProductionSource(t, "CHANGELOG.md")
	if !strings.Contains(changelog, version) {
		t.Errorf("Scorecard Maintained: CHANGELOG.md has no entry for %s. The version the tree "+
			"claims and the version the history records are the same fact, and a release with no "+
			"entry is a release nobody can read the shape of.", version)
	}

	// A changelog with one entry is a template, not a history.
	headings := regexp.MustCompile(`(?m)^## `).FindAllString(changelog, -1)
	if len(headings) < 5 {
		t.Errorf("Scorecard Maintained: CHANGELOG.md has %d entries; the scan is reading the "+
			"wrong file or the history has been truncated", len(headings))
	}
}

// TestScorecard_TheOnlyOpenAdvisoryIsTheOneTheRegisterNames covers
// Vulnerabilities.
//
// The check reads OSV, which needs the network, so what is asserted here is the
// claim the register makes about the one advisory it accepts: GO-2026-5932
// marks golang.org/x/crypto/openpgp unmaintained with no fix, x/crypto is a
// direct dependency for argon2id and HKDF, and nothing in either module imports
// openpgp. The first two make the finding unavoidable; the third is what makes
// it harmless, and it is the one a future import could quietly undo.
// openpgpImportPath is the quoted import path the scan below compares against,
// in the form an *ast.ImportSpec carries it.
const openpgpImportPath = `"golang.org/x/crypto/openpgp"`

func TestScorecard_TheOnlyOpenAdvisoryIsTheOneTheRegisterNames(t *testing.T) {
	root := repoRoot(t)

	gomod := readProductionSource(t, "go.mod")
	if !strings.Contains(gomod, "golang.org/x/crypto v") {
		t.Error("Scorecard Vulnerabilities: golang.org/x/crypto is no longer a dependency, which " +
			"means CR-37 has closed and the accepted risk should be retired rather than carried")
	}

	// The import graph is read from the AST rather than from the file bytes.
	// Reading the bytes inside a WalkDir callback is the symlink-TOCTOU shape
	// gosec's G122 reports, and the parser gives a more precise answer anyway:
	// a package named in a comment or in this test's own error message is not
	// an import.
	scannedCount := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "tmp", "dist", "coverage", "bin", "obj", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		scannedCount++
		for _, imp := range parsed.Imports {
			if imp.Path == nil || imp.Path.Value != openpgpImportPath {
				continue
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			t.Errorf("Scorecard Vulnerabilities: %s imports %s. GO-2026-5932 marks that package "+
				"unmaintained and unsafe by design with no patched version; CR-37 accepts the "+
				"advisory only because no code reaches it.", rel, openpgpImportPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Scorecard Vulnerabilities: walking the tree failed: %v", err)
	}
	if scannedCount < 100 {
		t.Fatalf("Scorecard Vulnerabilities: only %d Go files parsed; the walk is broken and the "+
			"assertion above would pass vacuously", scannedCount)
	}
	t.Logf("Scorecard Vulnerabilities: %d Go files parsed, no openpgp import", scannedCount)
}

// TestScorecard_RegisterMatchesTheCheckSet is the drift gate. Scorecard's check
// set is fixed by the tool, not by this project, so a register that names
// nineteen of twenty checks has quietly dropped one rather than answered it.
func TestScorecard_RegisterMatchesTheCheckSet(t *testing.T) {
	reg := loadRegister(t)

	declared := map[string]struct{}{}
	for _, r := range reg.Requirements {
		if r.Standard == "OpenSSF Scorecard" {
			declared[r.RequirementID] = struct{}{}
		}
	}
	if len(declared) == 0 {
		t.Fatal("the register declares no OpenSSF Scorecard rows at all; this gate is vacuous")
	}

	for _, check := range scorecardChecks {
		if _, ok := declared[check]; !ok {
			t.Errorf("Scorecard: the check %q is scored on every run and the register does not "+
				"classify it. An unanswered check is not a passing one.", check)
		}
	}
	for id := range declared {
		if !contains(scorecardChecks, id) {
			t.Errorf("the register classifies %q as an OpenSSF Scorecard check and Scorecard "+
				"v5.5.0 has no such check", id)
		}
	}
}

// scorecardChecks is the check set of Scorecard v5.5.0, taken from
// docs/checks.md in ossf/scorecard.
var scorecardChecks = []string{
	"Binary-Artifacts",
	"Branch-Protection",
	"CI-Tests",
	"CII-Best-Practices",
	"Code-Review",
	"Contributors",
	"Dangerous-Workflow",
	"Dependency-Update-Tool",
	"Fuzzing",
	"License",
	"Maintained",
	"Packaging",
	"Pinned-Dependencies",
	"SAST",
	"SBOM",
	"Security-Policy",
	"Signed-Releases",
	"Token-Permissions",
	"Vulnerabilities",
	"Webhooks",
}

// workflowFiles lists every workflow in the repository, so a gate over "all
// workflows" keeps covering one added after it was written.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	if len(names) < 3 {
		t.Fatalf("only %d workflows found; the scan is broken and every assertion over it would "+
			"pass vacuously", len(names))
	}
	return names
}
