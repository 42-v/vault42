# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vault42, **please report it responsibly**. Do not open a public GitHub issue.

**Email:** <vault@42-v.com>

Hosted on Tuta (end-to-end encrypted). If you prefer, you can encrypt your report — reach out for a public key.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgment:** within 48 hours
- **Assessment:** within 7 days
- **Fix or mitigation:** as soon as reasonably possible

### What qualifies

- Authentication or authorization bypasses
- Token forgery or manipulation
- Cryptographic weaknesses
- Injection vulnerabilities (SQL, XSS, command)
- Information disclosure (user enumeration, timing leaks)
- Privilege escalation

### What does not qualify

- Denial of service (this is a single-origin service, not a public API)
- Issues in dependencies — report those upstream, but feel free to let me know
- Vulnerabilities that require physical access to the server
- Social engineering

## How a security fix ships

Reports are handled privately; fixes are not.

1. **Fix privately.** Work happens off the public tracker until a release is ready. No issue, no
   branch name, no commit message describes the vulnerability before the fix is published.
2. **Publish a release.** Fixes ship in a normal release, not as a patch attached to an email.
   The version bump follows the policy below.
3. **Say so in the changelog.** Every release that contains a security fix carries a
   `### Security` section in [CHANGELOG.md](CHANGELOG.md) describing what was wrong, what an
   attacker could do, and what changed. That section is the signal that a release is a security
   release. Read it before deciding whether an upgrade is urgent.
4. **Advisory when it affects deployed users.** Vulnerabilities that a deployed instance is
   exposed to are published as a
   [GitHub Security Advisory](https://github.com/42-v/vault42/security/advisories) on the
   repository, which is also how a CVE is requested. Findings that require a configuration a
   deployment cannot reach, or that only affect the development tree, are documented in the
   changelog without an advisory.
5. **Credit.** Reporters are credited by name in the changelog and the advisory unless they ask
   not to be. There is no bounty.

Accepted risks -- things Vault42 deliberately does not defend against, with the reasoning -- are
enumerated in [docs/security.md](docs/security.md). Read that before reporting; a finding already
listed there is not a new vulnerability, though an argument that the acceptance is wrong is
welcome.

## Verifying releases

Every release is signed with keyless cosign (Sigstore, OIDC identity, no long-lived key), and
every published artifact additionally carries a SLSA provenance attestation assembled and signed
by GitHub's attestation service and logged to Rekor. Nothing is trustworthy that you have not
checked, so check it. Five artifact classes ship:

| Artifact | Where | Signature |
|---|---|---|
| `vault42`, `vault42-admin-gateway`, `vault42-bridge` images | `ghcr.io/42-v/…:<version>` | cosign keyless, plus a signed provenance attestation stored beside the image in GHCR |
| Helm chart `vault-auth` | `oci://ghcr.io/42-v/charts/vault-auth` | cosign keyless over the chart digest, plus a signed provenance attestation stored beside it |
| Release archives | GitHub release assets | listed in the checksum file, plus a signed provenance attestation whose offline bundle ships as `vault42_<version>.intoto.jsonl` |
| Per-archive SBOMs, SPDX and CycloneDX | GitHub release assets | each SPDX document carries its own attestation naming the archive it describes |
| `vault42_<version>_SHA256SUMS` | GitHub release assets | cosign keyless, as a Sigstore bundle (`.bundle`) carrying the signature, the certificate chain and the Rekor inclusion proof |

```bash
VERSION=1.0.4
IDENTITY='^https://github\.com/42-v/vault42/\.github/workflows/release\.yml@refs/tags/v.+$'
ISSUER=https://token.actions.githubusercontent.com

# Images. Tags carry no leading "v".
for img in vault42 vault42-admin-gateway vault42-bridge; do
  cosign verify --certificate-identity-regexp "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" "ghcr.io/42-v/$img:$VERSION"
done

# Helm chart.
cosign verify --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" "ghcr.io/42-v/charts/vault-auth:$VERSION"

# Binaries: verify the checksum file's signature, then the binaries against it.
cosign verify-blob "vault42_${VERSION}_SHA256SUMS" \
  --bundle "vault42_${VERSION}_SHA256SUMS.bundle" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
sha256sum -c "vault42_${VERSION}_SHA256SUMS" --ignore-missing

# SLSA provenance: which workflow, at which commit, built this.
gh attestation verify "oci://ghcr.io/42-v/vault42:$VERSION" --repo 42-v/vault42
gh attestation verify "vault42_${VERSION}_linux_amd64.tar.gz" --repo 42-v/vault42

# The same check offline, from the archive and the shipped bundle alone.
gh attestation verify "vault42_${VERSION}_linux_amd64.tar.gz" \
  --bundle "vault42_${VERSION}.intoto.jsonl" --repo 42-v/vault42

# BuildKit also embeds its own provenance predicate and SBOM in each image index.
docker buildx imagetools inspect "ghcr.io/42-v/vault42:$VERSION" --format '{{ json .SBOM }}'
docker buildx imagetools inspect "ghcr.io/42-v/vault42:$VERSION" --format '{{ json .Provenance }}'
```

Verify the checksum file's signature **before** trusting `sha256sum -c`: an attacker who can
replace a binary can replace an unsigned checksum file alongside it. Each release archive ships
two SBOMs next to it, `.spdx.sbom.json` and `.cdx.sbom.json`.

Prefer `gh attestation verify` over the `docker buildx imagetools` output. What BuildKit embeds
is an unsigned predicate produced by the same process that ran the build, with nothing
countersigning it and no transparency-log entry, so it describes a build without establishing
who performed it. The attestation `gh` reads is signed under the release workflow's OIDC
identity and logged to Rekor, which is the difference between reading a claim and checking one.

A `cosign verify` that fails, or a certificate identity that is not
`.github/workflows/release.yml` in this repository at a `v*` tag, means the artifact did not
come from this project. Do not run it. The verified output prints the signing certificate's
subject, so you can read the exact workflow and ref rather than trusting the regex above.

Building from source is the supported alternative. `go build ./cmd/vault` produces a working
server, but the SPA it embeds is the committed development placeholder
(`internal/frontend/dist/`); a real frontend requires building `web/` first, which
`scripts/build-all.sh` and the Dockerfile do.

## Supported Versions

Only the latest release is supported. There are no LTS branches and no backports: a security fix
ships in the next release from `main`, and upgrading to it is the mitigation.

## Versioning and compatibility

Vault42 follows [semantic versioning](https://semver.org/) from 1.0.0 onward. The version number
also encodes the statement-coverage figure, which is why 1.0.0 could only be cut once that
figure reached 100.00% of *reachable* statements. Raw statement coverage is lower, and
deliberately so: the statements outside the numerator are frozen one by one in
`.coverage-exclusions.json` with the source line and a justification, and the release gate
asserts `covered + excluded == total` so the set cannot grow or rot unnoticed. Read
[docs/test-coverage.md](docs/test-coverage.md) for the measured figure rather than inferring one
from the version.

**The public surface, where a breaking change costs a major bump:**

| Surface | Covered |
|---|---|
| HTTP API | Routes, request and response field names, error codes and HTTP status codes documented in [docs/api.md](docs/api.md). The root paths are v1; a major bump is the API version. |
| JWT claim set | The claims Vault42 issues and the values it accepts, as documented in [docs/spec.md](docs/spec.md). |
| Environment variables | Every variable in [docs/config.md](docs/config.md): removing one, renaming one, or changing its default is breaking. |
| Database schema | The migration sequence. Migrations are additive and forward-only; a destructive migration is a major bump. |
| Helm chart values | The `values.yaml` keys in `charts/vault`. |
| Client packages | `@vault42/vue`, `Vault42.AspNetCore`, `Vault42.Blazor`. |

**Not covered, and explicitly not stable:** every Go package lives under `internal/`, so there is
no importable Go API and none is promised. The honeypot bridge's scoring heuristics are tuning,
not contract.

`VAULT_DPOP_ENABLED` is covered by the environment-variable row above rather than carved out of
it: issuance stamps `cnf.jkt` and every authenticated route enforces it, so a deployment can
depend on the flag meaning what it says. What it does not reach is worth knowing before you
report it. Refresh tokens are not sender-bound, so redeeming a stolen one is not a DPoP bypass;
and there is no `DPoP-Nonce`, so proof freshness comes from the proof's own `iat` and the
single-use JTI cache, not from a value the server chose. Both are stated in
[README.md](README.md).

**Client package versions.** The release workflow packs both NuGet packages with the release
version, so `Vault42.AspNetCore` and `Vault42.Blazor` on nuget.org always match the server
version they were built from; the `<Version>` in each `.csproj` is a local-build fallback only.
`@vault42/vue` is built and tested in CI but is not published to npm, and its `package.json`
version does not track the server.

## Disclaimer

Vault42 is designed with security as a core principle, but **it is only as secure as the system it is deployed on**. No software can compensate for misconfigured infrastructure, leaked secrets, or unpatched systems. You are responsible for securing your own deployment.
