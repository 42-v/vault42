# Changelog

## 0.7.0 (2026-05-18)


### Bug Fixes

* bump the Go builder image to golang:1.26-alpine (Go 1.26.3), clearing 5 HIGH stdlib CVEs flagged nightly by the Trivy image scan (CVE-2026-33811, CVE-2026-33814, CVE-2026-39820, CVE-2026-39836, CVE-2026-42499)


### Tests

* add admin and user handler coverage tests; statement coverage 69.42% -> 70.69%

## 0.6.9 (2026-05-14)


### Security

* bump the Go toolchain to 1.26.3, clearing the stdlib CVEs reported by govulncheck


### Build

* add `scripts/release-check.sh` — a local pre-release gate that mirrors the nightly security workflow
* drop the custom `codeql.yml` workflow, which conflicted with the repository's default-setup CodeQL


### Tests

* raise statement coverage to 69.42%

## 0.6.7 (2026-05-14)


### Security

* SHA-pin all first-party GitHub Actions and add a CODEOWNERS file
* mask IP addresses in logs and resolve CodeQL findings (config secret logging, IP CRLF injection)


### Build

* bump fast-uri 3.1.0 -> 3.1.2
* pin pnpm to 10.18.0 (the lockfile is incompatible with pnpm 11's `--frozen-lockfile` check)


### Tests

* raise statement coverage to 67.69%


### Chore

* rebrand remaining stale `vault` references to `vault42`

## 0.4.2 (2026-04-30)

* Initial public release of Vault42 — JWT authentication server in Go, with an integrated Vue frontend, admin gateway, and honeypot mode.
