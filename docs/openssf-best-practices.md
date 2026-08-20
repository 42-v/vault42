# OpenSSF Best Practices — prepared answers

The OpenSSF Best Practices badge is earned by registering the project at
[bestpractices.dev](https://www.bestpractices.dev/) and self-certifying against
the passing-level criteria. It is the one thing in this repository's security
posture that a commit cannot deliver: it needs an account action against an
external service. That is why OpenSSF Scorecard scores `CII-Best-Practices` at
**0/10** here, and why the compliance register carries it as accepted risk
**CR-35** rather than as a gap nobody looked at.

This file is the part that *can* be prepared in the repository: an answer to
every passing-level criterion, with the evidence already in the tree. Registering
the project and pasting these is the remaining step.

**Criteria revision:** the 67 passing-level criteria (43 MUST, 10 SHOULD, 14
SUGGESTED) as published in
[`criteria/criteria.yml`](https://github.com/coreinfrastructure/best-practices-badge/blob/main/criteria/criteria.yml),
read on 2026-08-20.

> **This is a self-assessment, and the same rules apply to it as to
> [`COMPLIANCE.md`](COMPLIANCE.md).** Where an answer is weaker than "yes", it
> says so. Nothing here is answered "met" on the strength of a plan.

---

## Basics

| Criterion | Answer | Evidence |
|---|---|---|
| `description_good` (MUST) | Met | `README.md` opens with what the project is; the GitHub description reads "Production grade, minimal dependency RS256 JWT token service with JWKS and OAuth written in Go, with Vue SPA and extensions for .NET 10, Blazor and Vue". |
| `interact` (MUST) | Met | [`CONTRIBUTING.md`](../CONTRIBUTING.md), linked from the README. |
| `contribution` (MUST) | Met | [`CONTRIBUTING.md`](../CONTRIBUTING.md) — the commit convention, the pre-commit gates and what CI enforces. URL: `https://github.com/42-v/vault42/blob/main/CONTRIBUTING.md` |
| `contribution_requirements` (SHOULD) | Met | Same file: conventional-commit types, the gate list, and the documentation-sync table that says which docs a behaviour change must update. |
| `floss_license` (MUST) | Met | MIT. |
| `floss_license_osi` (SHOULD) | Met | MIT is OSI-approved. |
| `license_location` (MUST) | Met | [`LICENSE`](../LICENSE) at the repository root; GitHub reports the SPDX id as `MIT`. |
| `documentation_basics` (MUST) | Met | [`docs/`](.) — architecture, config, deployment guide, spec. |
| `documentation_interface` (MUST) | Met | [`docs/api.md`](api.md) documents every HTTP endpoint; [`docs/config.md`](config.md) every environment variable. |
| `sites_https` (MUST) | Met | Repository on github.com; project site at `https://vault.42-v.com`. |
| `discussion` (MUST) | Met | GitHub Issues is enabled on the repository. |
| `english` (SHOULD) | Met | All project documentation is in English. (The *product* ships 38 UI locales; that is a separate thing.) |
| `maintained` (MUST) | Met | Active: three releases merged in August 2026, and the nightly security workflow runs on a schedule. |

## Change Control

| Criterion | Answer | Evidence |
|---|---|---|
| `repo_public` (MUST) | Met | Public repository at `https://github.com/42-v/vault42`. |
| `repo_track` (MUST) | Met | git. |
| `repo_interim` (MUST) | Met | Work lands as pull requests against `main`; interim commits are public on the branch before the squash. |
| `repo_distributed` (SUGGESTED) | Met | git is distributed. |
| `version_unique` (MUST) | Met | One `VERSION` file is the source of truth, and `scripts/version-bump.sh` propagates it to every manifest that carries a copy. `scripts/release-check.sh --version-only` fails the build when any of them disagree. |
| `version_semver` (SUGGESTED) | Met | Semantic versioning; the release workflow refuses a tag that is not `vX.Y.Z[-suffix]`. |
| `version_tags` (SUGGESTED) | **Partially met — see note** | Releases through 0.9.9 are tagged `vX.Y.Z`. 1.0.0 and 1.0.1 were merged without their tags being pushed, so no artifact was published under either. The release workflow is tag-driven precisely so this is recoverable, and the gap is recorded in the changelog rather than hidden. Answer honestly as "unmet" until the tags exist. |
| `release_notes` (MUST) | Met | [`CHANGELOG.md`](../CHANGELOG.md), one section per version, and `scripts/release-check.sh` refuses a release whose version has no section. |
| `release_notes_vulns` (MUST) | Met | The changelog names the advisories a release closes by identifier (for example `GHSA-hfg8-hc9c-6c3h` in 1.0.1). |

## Reporting

| Criterion | Answer | Evidence |
|---|---|---|
| `report_process` (MUST) | Met | [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`SECURITY.md`](../SECURITY.md). |
| `report_tracker` (SHOULD) | Met | GitHub Issues. |
| `report_responses` (MUST) | Met | The project responds to reports; the issue tracker is public and its history is visible. |
| `enhancement_responses` (SUGGESTED) | Met | Same tracker. |
| `report_archive` (MUST) | Met | GitHub Issues is publicly readable, so the discussion archive is public. |
| `vulnerability_report_process` (MUST) | Met | [`SECURITY.md`](../SECURITY.md) states the reporting route and the supported versions. |
| `vulnerability_report_private` (MUST) | Met | GitHub private vulnerability reporting is **enabled** on the repository (2026-08-20), so a reporter has a private channel that does not require email. |
| `vulnerability_report_response` (MUST) | Met | [`SECURITY.md`](../SECURITY.md) commits to acknowledgment within 48 hours and assessment within 7 days. |

## Quality

| Criterion | Answer | Evidence |
|---|---|---|
| `build` (MUST) | Met | `scripts/build-all.sh` builds the Go binaries, the Vue SPA and the container images; `scripts/check.sh` is build + vet. |
| `build_common_tools` (SHOULD) | Met | The Go toolchain, pnpm and the .NET SDK. |
| `build_floss_tools` (SHOULD) | Met | All three are FLOSS and run on a FLOSS operating system. |
| `test` (MUST) | Met | Ten suites; see the Testing section of [`CLAUDE.md`](../CLAUDE.md) and [`docs/test-coverage.md`](test-coverage.md). |
| `test_invocation` (SHOULD) | Met | `scripts/t.sh` runs the Go suites, `pnpm test` the frontend, `scripts/dotnet-coverage.sh` the .NET SDKs. |
| `test_most` (SHOULD) | Met, and well past the bar | Go: 100.00% of reachable statements, with a reviewed 51-entry exclusion set and a CI gate asserting `covered + excluded == total`. Vue: 99.76%. C#: 100.00%. |
| `test_continuous_integration` (SUGGESTED) | Met | Every pull request runs the full suite plus both coverage gates; thirteen checks are required by branch protection. |
| `test_policy` (MUST) | Met | [`CONTRIBUTING.md`](../CONTRIBUTING.md) and the coverage gates: new code that is neither covered nor explicitly excluded fails the build, which is a test policy with teeth rather than a stated intention. |
| `tests_are_added` (MUST) | Met | Enforced rather than requested — see above. |
| `tests_documented_added` (SUGGESTED) | Met | [`CONTRIBUTING.md`](../CONTRIBUTING.md); the exclusion policy in `.coverage-exclusions.json` documents what may be left uncovered and why. |
| `warnings` (MUST) | Met | `golangci-lint` on Go, `-warnaserror` on the .NET solution, `ruff`/`yamllint`/`markdownlint`/`shellcheck` on the rest. |
| `warnings_fixed` (MUST) | Met | All of those are at zero, and CI fails on any finding. |
| `warnings_strict` (SUGGESTED) | Met | The .NET build treats every analyzer warning as an error; the Go linter set is broader than the default. |

## Security

| Criterion | Answer | Evidence |
|---|---|---|
| `know_secure_design` (MUST) | Met | The Security Invariants section of [`CLAUDE.md`](../CLAUDE.md), [`docs/security.md`](security.md) and a 424-requirement register across ten standards. |
| `know_common_errors` (MUST) | Met | The attack suite (`tests/attack/`, 60+ vector files) and the OWASP Top 10 / API Top 10 rows of the register. |
| `crypto_published` (MUST) | Met | RS256/ES256, Argon2id, AES-256-GCM, HMAC-SHA256, HKDF — all published algorithms. |
| `crypto_call` (SHOULD) | Met | Go's standard library and `golang.org/x/crypto`. The JWT implementation is hand-rolled but uses `crypto/rsa` and `crypto/sha256`; no cryptographic primitive is reimplemented. |
| `crypto_floss` (MUST) | Met | Go standard library and `x/crypto`. |
| `crypto_keylength` (MUST) | Met | RSA 2048 minimum, enforced — the JWKS reader rejects any key with a modulus under 256 bytes (CS-6), and the .NET SDK does the same. AES-256, SHA-256. |
| `crypto_working` (MUST) | Met | No broken primitives. SHA-1 appears only where RFC 6238 mandates it for TOTP, and that constraint is documented at `internal/crypto/totp.go`. |
| `crypto_weaknesses` (SHOULD) | Met | See above: the one SHA-1 use is protocol-mandated, not a default. |
| `crypto_pfs` (SHOULD) | Met | The server sets `MinVersion: tls.VersionTLS13` (`internal/server/server.go:232`). Every TLS 1.3 cipher suite is forward-secret by construction, so this is not a preference that can be negotiated away. |
| `crypto_password_storage` (MUST) | Met | Argon2id, 46 MiB / 1 iteration / 1 parallelism, per-user salt plus a server-side pepper. Never reversible, never logged. |
| `crypto_random` (MUST) | Met | `crypto/rand` throughout; the register's NIST SP 800-63B-4 §3.2.12 row covers the DRBG requirement with a test. |
| `delivery_mitm` (MUST) | Met | HTTPS from GitHub and GHCR, container images and the Helm chart signed keylessly with cosign by digest, release archives covered by a signature over `SHA256SUMS`, and build provenance attested. |
| `delivery_unsigned` (MUST) | Met | Nothing is delivered unsigned; see above. |
| `vulnerabilities_fixed_60_days` (MUST) | Met | Dependabot alerts are enabled and acted on. 1.0.1 closed the only open advisory the day it was raised. |
| `vulnerabilities_critical_fixed` (SUGGESTED) | Met | Same. |
| `no_leaked_credentials` (MUST) | Met | Secret scanning and push protection are enabled; no credential is committed. Every secret is loaded from a path named by a `_FILE` variable, with no default. |

## Analysis

| Criterion | Answer | Evidence |
|---|---|---|
| `static_analysis` (MUST) | Met | `gosec`, `staticcheck` via `golangci-lint`, CodeQL (6 languages, weekly), Trivy over source and images, and the .NET analyzer set at `-warnaserror`. |
| `static_analysis_common_vulnerabilities` (SUGGESTED) | Met | gosec and CodeQL both target the common vulnerability classes; Trivy covers dependency and image CVEs. |
| `static_analysis_fixed` (MUST) | Met | gosec is gated at zero HIGH/CRITICAL in production code, with a frozen per-rule baseline for test files that may only shrink. |
| `static_analysis_often` (SUGGESTED) | Met | Every pull request, plus a nightly scheduled run. |
| `dynamic_analysis` (SUGGESTED) | Met | 17 Go fuzz targets over the parsers that see attacker-controlled bytes, plus the attack suite and testcontainers-backed integration tests against a real Postgres. |
| `dynamic_analysis_unsafe` (SUGGESTED) | Met | Go is memory-safe and the tree imports `unsafe` nowhere. The race detector runs in CI over `./internal/...`, the attack suite and the end-to-end suites (`.github/workflows/ci.yml`); the coverage run itself is deliberately not `-race`, because the two instrumentations together make the DB-backed suites time out. |
| `dynamic_analysis_enable_assertions` (SUGGESTED) | Met | Tests run with assertions live; the compliance suite asserts invariants against a real database rather than a mock. |
| `dynamic_analysis_fixed` (MUST) | Met | Findings are fixed; the suites are green on every merge. |

---

## Summary

| | MUST | SHOULD | SUGGESTED | Total |
|---|---:|---:|---:|---:|
| Met | 43 | 10 | 14 | 67 |
| Unmet | 0 | 0 | 0 | 0 |

with **one qualification**: `version_tags` is answered "met" only once `v1.0.1`
and `v1.0.2` exist. Push the tags before submitting, or answer that one
criterion honestly as unmet and revisit it.

## What to do

1. Sign in at [bestpractices.dev](https://www.bestpractices.dev/) with the
   GitHub account that owns the repository.
2. Add `https://github.com/42-v/vault42`.
3. Work down the form using the table above; every answer has its evidence link
   in this file.
4. When the badge is awarded, add its URL to `README.md`, retire **CR-35** from
   `docs/compliance-register.json` into `retired_risks`, and move the
   `CII-Best-Practices` row from Accepted Risk to Met. The next weekly Scorecard
   run picks the badge up on its own.
