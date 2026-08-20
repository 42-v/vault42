package compliance

import (
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
