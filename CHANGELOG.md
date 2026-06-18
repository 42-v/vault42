# Changelog

## 0.8.9 (2026-06-19)

### Features

* **BeOn3 profile/user parity**: the encrypted identity blob gained `username`,
  `state`, `marketing_emails` and a namespaced opaque `dynamic` JSON area (forum/
  garage/etc.), with validation; `auth.users` gained account-state flags
  (`disabled`, `banned`, `ban_reason`, `last_login_at`, `deleted`) via migration 004.
  Login now rejects banned/disabled/deleted accounts and stamps `last_login_at`.
* **Custom roles catalog** (`auth.app_roles`, migration 005): admin-managed role
  catalog with `GET/POST/DELETE /admin/roles` (super_admin), reserved-role
  protection, and catalog-aware role validation at JWT issuance.
* **Account import + magic-link forced reset** (migration 006): `POST
  /admin/users/import` batch-creates passwordless `import_pending` accounts; their
  first login (any password) is intercepted, a one-time magic reset link is
  emailed, and completing it sets a new Argon2 password — legacy BeOn3 SHA-256
  hashes are never imported.
* **Generic OIDC / OAuth authority**: a configurable OpenID Connect provider
  (Okta, Auth0, Keycloak, Entra, …) via `VAULT_OIDC_PROVIDERS` — OIDC discovery,
  PKCE+nonce authorize, code exchange, JWKS-verified ID tokens (rejecting
  `alg=none`/HMAC/embedded-key headers/sub-2048-bit keys), and a callback that
  prefers the nonce-bound verified ID token.

### Security

* Fix nightly govulncheck: bump Go toolchain to 1.26.4 (+ `golang:1.26.4-alpine`
  builder) clearing stdlib CVEs GO-2026-5039 (net/textproto) and GO-2026-5037
  (crypto/x509); update all Go + frontend dependencies.
* Audit (workflow-driven, 2 HIGH + 7 MEDIUM + 7 LOW, adversarially verified): fix
  **H1** MFA email-OTP factor downgrade, **H2** missing per-account MFA lockout,
  **M1** challenge-token device-fingerprint binding, **M2** unrate-limited OAuth
  authorize, **M4/M5/M6** fail-closed production config validation, **M7** embedded-
  trust profile gate, **L1** opt-in strict session limit, **L2** RSA modulus upper
  bound, **L3** required origin, **L4** fail-closed auth rate limiters, **L5** opt-in
  secret-file consumption, **L6** structured admin audit target, **L7** lock-duration
  clamp. (**M3** OAuth-state browser binding tracked separately.)
* gosec G710 open-redirect guard on the OAuth authorize redirect.

### Tests

* Multi-replica end-to-end suite (`tests/e2e/multireplica`): two in-process
  replicas over shared Postgres + Redis assert cross-replica JWKS, refresh-replay,
  shared lockout, MFA A→B, rate-limit, session-count, key rotation, and one-time
  tokens across dev + production profiles; plus an in-memory-cache-not-shared check.
* 16-agent coverage campaign + per-feature TDD raised statement coverage toward the
  89% target (see docs/test-coverage.md).

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
