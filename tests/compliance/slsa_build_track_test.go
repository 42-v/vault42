package compliance

import (
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// SLSA v1.1 — Build Track
//
// The Build Track splits responsibility. Three requirements belong to the
// producer, which is this project: choose a platform capable of the level you
// want, build consistently enough that a verifier can form expectations, and
// distribute the provenance. Five belong to the build platform, which is GitHub
// Actions, and a producer satisfies those by selecting a platform that makes
// the guarantee rather than by writing code.
//
// That split is why this file asserts what it does. It cannot test GitHub's
// runner isolation, and pretending to would be worse than not trying. What it
// can test is every choice on this side of the line: that the release is built
// on the hosted platform rather than somebody's laptop, that every published
// artifact class carries an attestation, that the signing is keyless against
// the workflow's own identity, and that nothing reintroduces a shared build
// cache between runs.
//
// vault42 claims Build L2 in full. The L3 clause it does not claim is
// "provenance is unforgeable", accepted as CR-38: attest-build-provenance takes
// the subject digest as an input from the job, so a compromised build step
// could ask for an attestation over a digest it did not produce. The signing
// key is genuinely out of reach -- Sigstore issues a short-lived certificate
// against the workflow's OIDC identity and no long-lived key is ever on the
// runner -- but "every field generated in a trusted control plane" is not true
// of the subject, and the register says so rather than rounding up.
// =============================================================================

// slsaAttestedArtifacts are the artifact classes a release publishes. Each has
// to be attested, because provenance covering three of four is provenance a
// consumer cannot rely on without knowing which one is missing.
var slsaAttestedArtifacts = []struct {
	subject string
	why     string
}{
	{"ghcr.io/42-v/vault42", "the server image"},
	{"ghcr.io/42-v/vault42-admin-gateway", "the admin gateway image"},
	{"ghcr.io/42-v/vault42-bridge", "the honeypot bridge image"},
	{"ghcr.io/42-v/charts/vault-auth", "the Helm chart"},
}

// TestSLSA_ProvenanceExistsForEveryPublishedArtifact covers Provenance Exists
// (L1) and Distribute provenance (producer).
func TestSLSA_ProvenanceExistsForEveryPublishedArtifact(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	attestations := strings.Count(release, "actions/attest-build-provenance@")
	if attestations < len(slsaAttestedArtifacts) {
		t.Errorf("SLSA Provenance Exists: %d attest-build-provenance steps for %d published "+
			"artifact classes. A release that attests some of what it publishes leaves a "+
			"consumer unable to tell which artifact the missing provenance belongs to.",
			attestations, len(slsaAttestedArtifacts))
	}

	for _, artifact := range slsaAttestedArtifacts {
		if !strings.Contains(release, "subject-name: "+artifact.subject) {
			t.Errorf("SLSA Provenance Exists: nothing attests %q (%s)", artifact.subject, artifact.why)
		}
	}

	// The release archives are attested by path rather than by image digest,
	// and they are the artifact a consumer downloads by hand.
	if !strings.Contains(release, "subject-path:") {
		t.Error("SLSA Provenance Exists: the release archives carry no attestation; only the " +
			"images and the chart would be verifiable")
	}

	// BuildKit's own provenance and SBOM ride with the image rather than with
	// the attestation store, so a consumer pulling the image gets them without
	// asking GitHub anything.
	for _, want := range []string{"provenance: true", "sbom: true"} {
		if !strings.Contains(release, want) {
			t.Errorf("SLSA Provenance Exists: the image build no longer sets %q", want)
		}
	}
}

// TestSLSA_ProvenanceIsAuthentic covers Provenance is Authentic (L2).
//
// Authenticity here is keyless: Sigstore issues a short-lived certificate
// against the workflow's OIDC identity, so the thing a verifier trusts is the
// workflow that ran, not a key somebody has to keep. That only works if the
// job is allowed to request the token.
func TestSLSA_ProvenanceIsAuthentic(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	for _, want := range []struct{ token, why string }{
		{"id-token: write", "without the OIDC token there is no identity to sign against and the signing step is inert"},
		{"attestations: write", "the attestation cannot be recorded without it"},
		{"sigstore/cosign-installer@", "cosign is what signs the images and the chart by digest"},
		{"cosign sign --yes", "the signature is over the digest, so it cannot be moved to another artifact"},
	} {
		if !strings.Contains(release, want.token) {
			t.Errorf("SLSA Provenance is Authentic: release.yml no longer contains %q -- %s",
				want.token, want.why)
		}
	}

	// The archives are covered by one signature over the checksum file, which
	// is what lets a consumer verify all of them with one verification.
	goreleaser := readProductionSource(t, ".goreleaser.yaml")
	if !strings.Contains(goreleaser, "signs:") || !strings.Contains(goreleaser, "artifacts: checksum") {
		t.Error("SLSA Provenance is Authentic: .goreleaser.yaml no longer signs the checksum file, " +
			"so the release archives have nothing authenticating them")
	}
}

// TestSLSA_BuildsRunOnTheHostedPlatform covers Hosted (L2) and the producer's
// obligation to choose an appropriate platform.
//
// The requirement is that no build step ran on an individual's workstation. A
// self-hosted runner is the way that happens by accident: it looks like CI in
// the workflow file and is somebody's machine in fact.
func TestSLSA_BuildsRunOnTheHostedPlatform(t *testing.T) {
	runsOn := regexp.MustCompile(`(?m)^\s*runs-on:\s*(.+)$`)

	checkedCount := 0
	for _, wf := range workflowFiles(t) {
		for _, m := range runsOn.FindAllStringSubmatch(readWorkflow(t, wf), -1) {
			target := strings.TrimSpace(m[1])
			checkedCount++
			if !strings.HasPrefix(target, "ubuntu-") && !strings.HasPrefix(target, "windows-") &&
				!strings.HasPrefix(target, "macos-") {
				t.Errorf("SLSA Hosted: .github/workflows/%s runs a job on %q. Anything that is not "+
					"a GitHub-hosted label is a machine somebody owns, and a release built on one "+
					"is a release built on a workstation.", wf, target)
			}
		}
	}
	if checkedCount < 10 {
		t.Fatalf("SLSA Hosted: only %d runs-on declarations found; the scan is broken and would "+
			"pass vacuously", checkedCount)
	}
	t.Logf("SLSA Hosted: %d jobs, all on GitHub-hosted runners", checkedCount)
}

// TestSLSA_NoSharedBuildCacheBetweenRuns covers the cache-poisoning clause of
// Isolated (L3).
//
// Most of Isolated is GitHub's guarantee and not testable here. This clause is
// the exception, because it is the one a workflow can break on its own: turning
// the Go module cache on shares state between runs, and the spec asks that the
// output be identical whether or not a cache was used.
func TestSLSA_NoSharedBuildCacheBetweenRuns(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	setupGoCount := strings.Count(release, "actions/setup-go@")
	cacheDisabled := strings.Count(release, "cache: false")
	if setupGoCount == 0 {
		t.Fatal("SLSA Isolated: no setup-go steps found in release.yml; the scan is broken")
	}
	if cacheDisabled < setupGoCount {
		t.Errorf("SLSA Isolated: release.yml has %d setup-go steps and %d of them disable the "+
			"cache. A shared module cache is state carried between runs, and the spec asks that "+
			"a build produce the same output whether or not the cache was used.",
			setupGoCount, cacheDisabled)
	}
}

// TestSLSA_TheBuildProcessIsConsistent covers Follow a consistent build process
// (producer).
//
// A verifier can only form expectations about a build if the same inputs
// produce the same release every time. The three guards below are what make
// that true here: the release is driven by a tag rather than by whatever is on
// main, the tag must name the commit being built, and the version in the tree
// must agree with the tag.
func TestSLSA_TheBuildProcessIsConsistent(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	for _, want := range []struct{ token, why string }{
		{"Release ref is the tag being published", "a run whose ref and version disagree builds something other than the tag it publishes"},
		{"Tag is an ancestor of main", "a tag on an unmerged branch would publish code main does not have, under a version main will later reuse"},
		{"scripts/release-check.sh --version-only", "the tag and the version in the tree must name the same release"},
	} {
		if !strings.Contains(release, want.token) {
			t.Errorf("SLSA consistent build process: release.yml no longer has the %q guard -- %s",
				want.token, want.why)
		}
	}

	// Tag-driven, not commit-subject-driven. The subject-driven trigger is what
	// lost 0.8.6 and then 1.0.0: a release that depends on someone editing a
	// squash message is a release that is skipped the first time they forget.
	if !strings.Contains(release, "tags:") {
		t.Error("SLSA consistent build process: release.yml is no longer triggered by a tag")
	}
}
