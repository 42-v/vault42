# Changelog

## 0.9.0 (2026-07-14)

### Fixed in review

Ten defects found by an adversarial review of this release's own changes, before merge:

* **The admin gateway encrypted imported consent with an all-zero key.** `NewIdentityService`
  retains the slice it is given, and `config.ZeroBytes(cfg.MasterKey)` wipes that backing
  array in place a few lines later. 32 zero bytes is still a valid AES-256 key, so `Encrypt`
  succeeded and wrote ciphertext no one could ever read. `cmd/vault` copies the key first;
  the gateway now does too.
* **Backup codes were not actually erased.** `BackupCodeRepo.DeleteAllForUser` is the
  *regeneration* path — it runs `UPDATE ... SET used=true`, leaving the hash and the user ID
  in the table. Erasure called it and reported success. Added `PurgeAllForUser`, and the
  integration test now asserts a **row count**, not that a mock method was called.
* **Consent could be laundered by a profile save.** `GET` returns the bare `marketing_emails`
  bool with no provenance, so any client that round-trips the form re-submits an imported
  (pre-ticked, never affirmed) `true` — which was then stamped `source=profile`, i.e.
  affirmative consent. A re-submitted value that has not changed is no longer treated as an
  act of consent, and the response now exposes the provenance so a client can tell the
  difference.
* **A profile save could destroy a withdrawal.** `PUT` is a full replace, so a client that
  omitted `marketing_emails` blanked the stored `ConsentRecord` — including a recorded
  unsubscribe — with no audit entry. Omitted now means "unchanged".
* **Erasure could leave a live account with no second factor.** The cascade spans nine stores
  with no transaction; the user row was scrubbed *last*, so a failure part-way left an account
  that still authenticated but whose TOTP secret, WebAuthn credentials and backup codes were
  already gone — the user locked out, and nothing erased. The account is now tombstoned
  first, and the cascade is idempotent so an interrupted erasure is finished by re-running it.
* Unsubscribe was a lock-free read-modify-write over a single encrypted blob: a concurrent
  profile write could drop the withdrawal, and the no-profile branch could replace a real
  profile with an empty one. It now uses a compare-and-set with retry.
* The audit retention sweeper ran on **every CLI subcommand** (it starts with an immediate
  sweep, and was started before the CLI dispatch), and in **every replica** with no
  coordination — each sweep takes an `ACCESS EXCLUSIVE` lock on the audit table and briefly
  disables the append-only trigger. It now starts only for the server, and serialises across
  replicas on a Postgres advisory lock.
* Import silently discarded every marketing flag when the identity service was not wired,
  while still reporting `consent_failed: 0`. It now counts and reports per row.
* The consent audit entry was written *before* the profile write, so a failed write still
  left a trail claiming consent had changed.

### Privacy / GDPR

* **Account erasure retained the MFA authenticators.** `DeleteAccount` cascaded the
  identity profile, blobs, devices, social links, password history and refresh tokens,
  but never removed the encrypted TOTP secret, the WebAuthn credentials or the
  backup-code hashes. The schema carries `ON DELETE CASCADE` on all three, so it looked
  correct — the cascade never fired, because erasure scrubs the user row with an `UPDATE`
  rather than deleting it. `docs/PRIVACY.md` §5.3 stated these were removed, so the
  published policy was wrong about what erasure did. They are now deleted explicitly, and
  refresh tokens are hard-deleted rather than revoked (a revoked row keeps its fingerprint
  hash and device reference). Regression test added — the omission had been untested.
* **Marketing consent is now a record, not a bare flag.** `marketing_emails` is stored with
  `granted` / `at` / `source` / `origin`, because Art. 7(1) requires the controller to
  *demonstrate* consent, which a boolean cannot. Only `registration` and `profile` sources
  are affirmative; `import` and `legacy` preserve the value but do not authorise sending —
  a migrated default-true flag, or a pre-ticked checkbox, is not consent (Recital 32;
  *Planet49*, C-673/17). `IdentityService.MarketingAllowed` is the sole send gate and fails
  closed. `POST /admin/users/import` now accepts `marketing_emails` so a migrating system's
  preferences survive the cutover with honest provenance.
* **`POST /user/marketing/unsubscribe`** — withdrawal in one call, no body, no confirmation
  step (Art. 7(3): withdrawal must be as easy as granting). Emits `consent_withdrawn`.
* **Audit retention is enforced** (`VAULT_AUDIT_RETENTION_DAYS`). Audit rows hold personal
  data and were the one store with no expiry: a manual `cleanup-audit` existed but nothing
  ran it. A sweeper now purges at startup and every 6h. Disabled by default — silently
  deleting security logs is not a safe default, so the horizon is an explicit operator
  choice.
* **`GET /user/social` + `DELETE /user/social/{id}`** — list and unlink federated identities.
  The provider's encrypted OAuth tokens previously could not be removed without erasing the
  entire account; `SocialAccountRepo.Delete` had been dead code with no route.
* `docs/COMPLIANCE.md` GDPR section re-audited against the code: **60% → 93%**, no open
  high-severity findings. The old figure both understated shipped work and asserted erasure
  guarantees the code did not implement.

### Security

* **Go toolchain bumped to 1.26.5**, clearing the three red nightly jobs. Both
  findings are stdlib-only and fixed in 1.26.5:
  * `GO-2026-5856` — Encrypted Client Hello privacy leak in `crypto/tls`,
    reachable from the OIDC user-info client, the Redis pool dialer and the
    server's TLS handshake (govulncheck symbol trace).
  * `CVE-2026-39822` (HIGH) — `os.Root` symlink-following in `os`, flagged by
    Trivy against the `stdlib` component compiled into the `vault` and
    `admin-gateway` images.
* Builder image pinned to `golang:1.26.5-alpine` by digest across `Dockerfile`,
  `Dockerfile.bridge` and `Dockerfile.admin-gateway`.

### Testing

* **Coverage raised to 90.42% across the full suite** (from 86.69%). Added real behavioural tests
  for previously-uncovered surfaces:
  * The GDPR work above, tested where it actually matters: the erasure cascade asserts the
    TOTP secret, WebAuthn credentials and backup codes are gone (against a real Postgres,
    since the bug was that the schema *looked* like it handled this); a failure in any of
    those deletes must abort the erasure rather than report a success that did not happen.
  * Consent provenance: an imported or legacy flag must never read as affirmative consent,
    a withdrawal must survive the encrypt/decrypt round-trip, and `MarketingAllowed` fails
    closed on a missing profile, a missing record, and a repository error.
  * The audit retention sweeper (disabled-by-default is inert, the cutoff is `now - horizon`,
    `Start` sweeps immediately rather than waiting hours for the first tick).
  * The offline recovery tool's reject paths (`cmd/recover` reads operator-supplied escrow
    files, so a truncated blob, a corrupt length prefix, a tampered AES payload and a
    non-RSA key must all fail cleanly).
  * The white-label email send path: `service.EmailOverrideStore` (branding +
    template lookups that degrade to the global template on error) and the
    `middleware.AppContext` tenant-slug resolver (`X-Vault-App` header, `?app=`
    fallback, invalid-slug rejection).
  * The account-erasure and session-management repository methods
    (`DeleteAllForUser`/`DeleteAllForPseudonym`, `SoftDeleteScrub`,
    `SetLastLogin`, `RevokeByDeviceID`, `RevokeAll`, `CountActiveFamilies`,
    blob ref-hash lookup/delete) plus the append-only `account_recovery` escrow
    repo and its no-UPDATE/no-DELETE trigger.
  * Admin/audit CLI commands (`seed`, `cleanup-audit`, `export-audit`) and their
    validation branches, `AdminConfig.List`, `AppRole.ListNames`,
    `Audit.Cleanup`, `AdminSession.RevokeAll`, the NIST AAL classifier
    (`AALForMethods`), and the offline recovery-tool RSA PEM loaders (PKCS#1
    fallback and error paths).

## 0.8.6 (2026-07-10)

### Features

* **KMS unwrap oracle** (`POST /kms/unwrap`). A vault42-held KEK envelope-unwrap
  oracle: a caller presents a wrapped-key envelope and vault42 returns the
  unwrapped key while holding the KEK itself and never releasing it. Backs the
  life42 data-root re-root.
  * `internal/kms`: per-kid KEKs derived from a KMS root secret
    (`KMS_ROOT_KEY_FILE`) via HKDF-SHA256 with a versioned, domain-separated
    info label, cryptographically separate from the master key. Wrap/Unwrap use
    the existing AES-256-GCM AEAD with the kid bound as AAD.
  * Oracle-resistant: every unwrap failure (malformed, tampered, wrong-KEK,
    empty kid, bad base64) collapses to a single opaque 400 `unwrap_failed` with
    a byte-identical body. Key material is never logged; KEKs and root are wiped.
  * Gated by an authenticated client-credential token carrying the `kms:unwrap`
    scope (`middleware.RequireScope`), per-IP rate limited with fail-closed
    behaviour on a cache outage, synchronous audit that never drops under load,
    and DPoP anti-replay when `VAULT_DPOP_ENABLED`. Mounted only when
    `KMS_ROOT_KEY_FILE` is configured.
  * `vault kms wrap` CLI produces envelopes the oracle accepts.

* **White-label auth emails.** Per-app branding and template overrides so each
  application served by vault42 sends auth emails (verification, password reset,
  email-OTP, account-locked) that look native to it.
  * `auth.email_branding` (migration 008): per-app display name, logo, accent
    colour, and From line. Setting just this re-skins every existing template
    for that app, with no template authoring required.
  * `auth.email_templates` (migration 008): per-app, per-type full HTML override
    for apps that need a completely custom body, reusing the existing template
    safety validation.
  * The tenant is selected by the `X-Vault-App` request header (or `?app=`),
    resolved into context by new middleware; a gateway/BFF in front of vault42
    sets it per tenant. An absent or unknown app falls back to the global
    branding (unchanged behaviour).
  * Per-app From line: the display name always applies; a per-app From *address*
    is honoured only when its domain is on `VAULT_EMAIL_FROM_ALLOWED_DOMAINS`.
  * Admin API: CRUD for branding + templates under `/admin/email-branding` and
    `/admin/email-templates` (RBAC `email:read`/`email:write`/`email:delete`),
    plus `POST /admin/email-templates/preview` to render without sending.
  * New config: `VAULT_EMAIL_FROM_NAME`, `VAULT_EMAIL_FROM_ALLOWED_DOMAINS`,
    `VAULT_MAX_EMAIL_TEMPLATE_SIZE`.

### Security

* **Fixed a data race on signing-key material.** `KeyStore.Refresh` reads the
  master key outside the mutex while `Stop` zeroed it under the lock; a refresh
  racing shutdown could read half-zeroed key bytes and fail to decrypt. `Stop`
  now joins the refresh loop (`sync.WaitGroup`) before wiping, and is idempotent
  (`sync.Once`) so the shutdown paths that call it twice no longer panic.
* **Log-injection hardening (CWE-117).** Untrusted values interpolated into log
  lines (operator secret-file paths, OAuth provider names, WebAuthn subjects and
  credential IDs) are now quoted so a crafted value cannot forge log records.
* Security scans are clean: `gosec` and `staticcheck` report zero findings
  across the module. Test helpers under `tests/e2e/multireplica` were renamed to
  `_test.go` so they are no longer scanned as production code.

### Testing

* Coverage is now measured across the **full suite** (unit + attack + fuzz +
  integration + compliance) as one canonical number, replacing the previous
  split between a unit-only floor and a separate `coverage-full.sh`. The shared
  plumbing lives in `scripts/lib/coverage-env.sh`, so `docs/test-coverage.md`,
  `docs/badges.json`, and the README badge can no longer disagree. The coverage
  gate now also fails on a build error (a non-compiling package silently read as
  0%), not just on a failing test.
* New tests for the KMS oracle, the DB-backed keystore lifecycle
  (rotate/revoke/refresh/cleanup, wrong-master-key fail-closed, multi-pod
  refresh), the white-label email admin handlers, and the admin-user,
  admin-session, and email branding/template repositories.

## 0.8.0 (2026-06-20)

### Features

* **the legacy platform profile/user parity**: the encrypted identity blob gained `username`,
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
  emailed, and completing it sets a new Argon2 password — legacy the legacy platform SHA-256
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
  clamp, and **M3** OAuth-state browser binding (4-part signed state + a
  `__Host-` CSRF cookie compared at the callback, defeating login-CSRF/session
  fixation).
* gosec G710 open-redirect guard on the OAuth authorize redirect.
* Adversarial review of the new 0.8.0 code closed further fail-open gaps: OAuth
  callback now fails closed when the MFA-status check errors (was silently issuing
  full tokens); token refresh re-checks account state and revokes the family for
  banned/disabled/deleted users (a ban no longer leaves a refreshable session);
  rate limiting defaults on and is required in non-dev profiles; the pepper must
  be ≥32 bytes; and a failed import-claim now fails closed rather than leaving the
  account stuck `import_pending`.
* A second review pass (feature-interaction lens) closed two account-state
  bypasses on the **OAuth callback**: a banned/disabled/deleted account with a
  linked social login could obtain tokens via OAuth (the gate existed on password
  login + refresh but not OAuth), and an `import_pending` account was not handled.
  The callback now enforces the same account-state gate and claims an imported
  account via the OAuth-verified email.

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
