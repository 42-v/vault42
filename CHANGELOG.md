# Changelog

## 0.9.9 (2026-07-31)

Coverage **96.67% → 99.42%** (8178 of 8226 statements), which is where the version
comes from. 99.69 is not reachable here and was not reachable at any point during the
release: one statement is 0.0122 points at this count, so the total steps 99.68 → 99.70 and
skips it. The frontend moved further than the backend: `@vault42/vue` went from 25.43% to
100% of statements, functions and lines, and the SPA from 24.38% to 99.52%.

The release started as "the nightly security scan has been red for nine days" and became a
security review, because taking the frontend from a quarter covered to fully covered kept
finding real defects in the code the new tests were covering. Thirty-seven findings were
raised across the review; four survived three-lens adversarial verification, and a
completeness pass over the surfaces no reviewer had opened found eight more. Everything
below was verified against the source before it was fixed, and several plausible findings
were discarded on the way: the SMTP transport was reported as falling back to cleartext,
which is simply wrong, because `net/smtp.SendMail` negotiates STARTTLS and returns the
error rather than continuing.

### Security

* **Every synced passkey was permanently unusable after registration.** Nothing persisted
  the WebAuthn credential flags: `model.WebAuthnCredential` had no field, the table had no
  column, and `modelCredsToWebAuthn` rebuilt every credential with `BackupEligible=false`
  on every login. go-webauthn compares that stored flag against the assertion and rejects a
  mismatch unconditionally, so a credential registered from iCloud Keychain, Google Password
  Manager, Windows Hello or 1Password (all of which set BE=1) enrolled successfully, flipped
  `RequiresMFA` to true, and then failed every single verification. A user whose only second
  factor was a synced passkey, holding no backup codes, could not get back into their
  account at all: `emailOTPAllowed` deliberately refuses email OTP once a strong factor is
  enrolled, and deleting the credential needs an access token they cannot obtain. The suites
  never saw it because they only ever construct BE=0 credentials. Flags are now stored,
  rehydrated and re-stored on each assertion, and a credential enrolled before this release
  adopts its flags from the first assertion that verifies rather than being bricked.
  Adoption is not a downgrade: the signature is checked against the stored public key before
  anything is written, so only the credential holder can influence the adopted value, and
  they can already authenticate.
* **The SDK kept a bearer token armed through an incomplete authentication.**
  `VaultClient.login` stores any `access_token` it is handed and `useAuth.login` took the
  `requires_2fa` early return without clearing it, so a server answering the password step
  with both fields left a usable token on every subsequent request while the UI correctly
  showed the user as signed out. `complete2FAVerification` had the mirror of the same bug:
  it guarded the token assignment but cleared the second-factor gate unconditionally, so a
  200 with no token dismissed the 2FA screen with nobody signed in and left the challenge
  token standing as the bearer.
* **The append-only audit log could be erased by the application role.**
  `audit.cleanup_old_entries` is `SECURITY DEFINER` and owned by the role that runs the
  migrations, nothing revoked `EXECUTE` from `PUBLIC`, and it trusted its argument, so
  `SELECT audit.cleanup_old_entries(interval '0 seconds')` deleted the entire log. `vault_app`
  is refused a direct `DELETE` on that table precisely to make it append-only, and then
  reached the same result through the function. `EXECUTE` is now revoked from `PUBLIC` and
  granted only to the role that runs the sweeper, the function refuses a horizon under one
  day, and it has an explicit `search_path`, which it lacked (CVE-2018-1058).
* **Four admin-gateway surfaces were dead in production for want of a grant, and one of
  them half-erased accounts.** Every table added after migration 001 has to be granted to
  `vault_admin` explicitly. `auth.app_roles` never was, so all three `/admin/roles` endpoints
  returned 500. `POST /admin/users/import` had no `INSERT` on `auth.users`.
  `DELETE /admin/config/{key}` had no `DELETE`, under a comment reserving it for the admin
  gateway. Worst, the erasure cascade behind `DELETE /admin/users/{id}` was granted `DELETE`
  on five tables but `SELECT` on none of them, and PostgreSQL requires both for
  `DELETE ... WHERE user_id = $1`, so erasure tombstoned the account and then failed
  partway through with 42501, leaving a half-erased user. The integration suite cannot see
  any of this: `stripRoleGrants()` removes every `GRANT` and `REVOKE` before the migrations
  are applied, so the privilege model is never exercised. The new grants are column-level
  where they can be, so the admin role still cannot read the encrypted TOTP secrets,
  WebAuthn public keys, backup-code hashes or password history it is allowed to delete.
* **A revoked signing key came back to life on the next restart.** The keystore's import
  upsert had no `WHERE`, so re-importing a PEM whose kid already existed set
  `status='active'` and cleared `retired_at` regardless of what the row said. The kid is
  derived from the modulus, so a re-import always collides, and the chart keeps
  `SIGNING_KEY_FILE` mounted after a migration to database-backed rotation, which makes the
  dangerous precondition the default state rather than an exotic one. Revoking the only
  active key also never reached the token service, because the change callback was gated on
  the new key being non-nil, so it kept minting with a kid the verification path had already
  dropped. Revocation is now terminal and propagates, and token issuance fails closed
  instead of signing with a revoked key.
* **The honeypot inherited the production database.** A Kubernetes `podSelector` is a subset
  match, and the base NetworkPolicy selected on name and instance only. The honeypot and
  bridge pods carry those same two labels, so the policy selected them too and the
  production PostgreSQL ingress accepted them. The entire point of the separate
  `honeypot-postgres` was void: code execution in the deliberately attackable pod reached
  the real database. The main deployment now carries an explicit component label and every
  policy names it.
* **`X-Forwarded-For` was used without being parsed.** In the embedded profile `ClientIP`
  returned the whole comma-joined header value as if it were an address, so it became the
  rate-limit bucket key, the fingerprint component and the audit `ip` column, and varying
  the spoofed prefix per request minted unlimited buckets. The second code path was wrong in
  the same way: it returned an entry that did not parse, and an existing test asserted that
  behaviour. Both paths now split, trim, validate with `net.ParseIP`, and fall back to
  `RemoteAddr`.
* **White-label tenant selection was unauthenticated.** `X-Vault-App` and `?app=` were read
  from any caller, and the slug was checked for shape but never for membership, so an
  outside caller could make a genuine password-reset or verification email arrive wearing
  another tenant's name, logo and colours. The header is now honoured only when the request
  arrived through a trusted proxy, and the query-parameter fallback is removed: a proxy
  forwards the client's query string verbatim, so it can never be an operator-controlled
  channel.

### Privacy

* **Plaintext blob names were written to the audit log.** `docs/PRIVACY.md` states as a
  guarantee that the reference name of a named blob never reaches the database and that only
  its HMAC is stored, and the service honours it. All three named-blob handlers then put the
  raw name into audit metadata, where `scrubMetadata` did not drop it, so it landed in the
  same database the encryption exists to protect, keyed to the user, and outlived the
  erasure of the account it belonged to. The handlers now log the blob ID, `name` is on the
  scrub list as a backstop, and the charset `docs/spec.md` already claimed is now enforced.
* **The recovery escrow kept erased users' addresses forever, and no document mentioned it.**
  Every erasure with a recovery key configured appends the subject's real email, creation
  date, roles and display name, encrypted to an offline operator key. The table had no expiry
  column, append-only triggers block `UPDATE` and `DELETE`, and both application roles have
  those revoked, so there was no supported way to ever remove a row. It appeared in none of
  the four logical stores `docs/PRIVACY.md` enumerates, had no entry in the Art. 30
  inventory, and no retention horizon while every other store had one. It is now documented
  in all four places and bounded by `VAULT_RECOVERY_RETENTION_DAYS`, disabled by default in
  the same way the audit sweeper is, because deleting data has to be an operator's choice.
* **The Art. 15 export truncated in silence.** It caps audit events and said nothing about
  it, so a long-lived account received a partial export presented as complete. The cap
  stays; the response now carries the total and a truncation marker, and `docs/PRIVACY.md`
  describes what actually happens.

### Fixed

* **The nightly security scan, red every night since 2026-07-22.** `golang.org/x/text` 0.38.0
  carries CVE-2026-56852, and although it is an indirect dependency govulncheck reports it as
  reachable through `pgx.Connect`, so it failed the source scan, both image scans and the
  vulnerability check. postcss 8.5.15 carries GHSA-r28c-9q8g-f849; the pnpm override was
  pinned at `>=8.5.10`, which resolved happily to the vulnerable version, so raising the
  direct dependency alone would not have held.
* **The pre-commit gate could not see a test run that never finished.** `cov_run`
  deliberately swallows `go test`'s exit code and `cov_check_failures` exists to gate on it,
  and the gate called the first and never the second. Its only failure signal was a grep for
  `--- FAIL`, and a run killed by the 30-minute timeout or the OOM killer emits
  `FAIL pkg 1800s` with no such line, so the verdict read OK and the badge,
  `docs/badges.json` and `docs/test-coverage.md` were regenerated from a truncated profile.
  A suite that never completed was published as a coverage regression.
* **A data race in the new entropy tests.** They drove failures by assigning to
  `crypto/rand.Reader` and restoring it in `t.Cleanup`, which raced the goroutine
  `Register` spawns to finish its verification email. CI runs `./internal/...` with `-race`.
  The global is now written once before any test starts and the source behind it is swapped
  atomically.
* **The login page never offered registration.** `showRegisterLink` was declared as a
  type-only boolean prop, so Vue cast the absent prop to `false` and the guard never passed.
* **Unmapped server errors were rendered to the user verbatim.** Both auth forms fell
  through to displaying the raw code, so an overloaded server showed the literal string
  `server_busy`. Every code the handlers emit now has copy in all 38 locales and the
  fallback is generic, since a server-controlled string in the DOM is also an injection
  surface. The register form also carried a message confirming that an address was already
  registered, which the handler deliberately never sends; it is gone rather than left
  waiting for a proxy to surface it.

### Tests

The suite grew from 2968 to 3115. Go gained 42 files and about 7,400 lines, and the
frontend went from 182 tests to 1,160.

The redirect validator was rebuilt as a fail-closed allowlist and is pinned by a table of
hostile inputs. It rejects dot segments rather than normalising them, because vue-router
resolves `/..//evil.com` verbatim while `new URL()` collapses it to `//evil.com`, and a
validator whose idea of the final path disagrees with the router's is one that can be talked
around.

Covering the WebAuthn handler needed a software FIDO2 authenticator, so the test file now
contains one: a P-256 key, a CTAP2-shaped COSE encoder and real ES256 signatures over
`authData || SHA-256(clientDataJSON)`. It produces exactly what a browser posts, so
go-webauthn's real verifier runs against it, and no dependency was added.

Coverage thresholds are declared in both frontend packages and CI now runs `test:coverage`
rather than `test`, which exits 0 regardless. The frontend half of the suite was previously
gated only on whichever tests happened to exist.

Forty-eight statements remain uncovered and are documented as unreachable rather than
chased: guarded-then-rechecked errors that cannot fire (`Encrypt` validates the key length
before handing it to `aes.NewCipher`, so the cipher and GCM branches below are dead by
construction), `json.Marshal` of structs with no unmarshalable field, `flate` writes to a
`bytes.Buffer`, and mid-stream `rows.Err()` paths that need a real connection to drop
between `Query` and `Next`. An honest figure was preferred to a manufactured one.

### Breaking

* SDK client-side validation failures and malformed response bodies now reject with
  `VaultAPIError` rather than a bare `Error`, `SyntaxError` or `TypeError`. Messages are
  unchanged and `VaultAPIError` is still an `Error`, so matching on message or on
  `instanceof Error` is unaffected; matching on `instanceof SyntaxError` is not.
* The binary blob methods now auto-refresh on 401 like every other endpoint, so an expired
  token costs a round trip instead of failing, and they can emit `session_expired`.
* `?app=` no longer selects a white-label tenant, and `X-Vault-App` is honoured only from a
  peer in `TRUSTED_PROXIES`. With `TRUSTED_PROXIES` unset, all auth email uses the global
  branding.
* Revoking a signing key is terminal. A restart with a revoked `SIGNING_KEY_FILE` now fails
  loudly instead of silently reactivating the key. Rotate before revoking.

## 0.9.6 (2026-07-16)

Coverage **94.67% → 96.67%** (7812 of 8081 statements), which is where the version comes
from. Same story as last release, one rung up: 96.69 is not reachable at this statement
count -- one statement is 0.0124 points, so the total steps 96.68 → 96.70 and skips it.
96.67 is the nearest reachable figure on the scheme, and it lands exactly.

### Compliance

The suite gained its first privacy standard. `docs/COMPLIANCE.md` has claimed 93% GDPR
coverage since 0.8.x and `docs/PRIVACY.md` promises it clause by clause, yet
`tests/compliance/` contained zero GDPR tests -- the marquee posture of the whole project
was the one thing the compliance suite never asserted.

* **GDPR Art. 17, proven with row counts.** `gdpr_erasure_test.go` assembles the real
  `ErasureService` against a real Postgres (all migrations, grants stripped), seeds a user
  into every user-linked store, erases, and counts rows: zero everywhere except the two
  stores that are *supposed* to survive -- the tombstoned account row (referential
  integrity) and the audit trail (Art. 17(3)(b)/(e)). A mock records that a method was
  called; only a row count proves the data is gone. Idempotency, tombstone-first ordering,
  purge-not-mark on backup codes, and the recovery escrow are pinned in the same suite.
* **GDPR Art. 7 consent provenance.** `gdpr_consent_test.go` turns the consent invariants
  from CLAUDE.md prose into clause-numbered regressions: `import` and `legacy` are not
  consent (Recital 32; *Planet49*), `MarketingAllowed` fails closed on absent profiles and
  repo errors, an unchanged round-trip cannot launder imported provenance into
  `source=profile`, and unsubscribe is one call with no confirmation step (Art. 7(3)).
* **Art. 5(1)(e) retention + 5(1)(c) minimization.** `gdpr_retention_test.go` pins the
  disabled-by-default sweeper (deleting security logs must be an operator choice) and the
  audit-metadata scrubbing of password/secret/token keys.
* **RFC 9700 (OAuth 2.0 Security BCP).** `rfc9700_oauth_bcp_test.go` closes the other
  claim gap: COMPLIANCE.md counts 50 met OAuth-family requirements, and the compliance
  suite held exactly one Google-only PKCE test. Now clause-numbered: S256 on every
  provider, HMAC state integrity, OIDC nonce binding, tokens out of URLs by reflection,
  DPoP htm/htu/ath rejection, refresh rotation replay.

### Fixed

* **Email templates could silently not exist.** The path-traversal guard in
  `NewTemplateRenderer` used `continue` on trip, skipping the whole loop iteration instead
  of just the override read. With `VAULT_EMAIL_TEMPLATES_DIR=.` the renderer registered
  zero templates and returned success: every verification, password-reset, OTP and lockout
  email rendered as a bare "Notification" stub with no token URL, and nothing anywhere
  reported a problem. Fail-closed restructure: a tripped guard now skips only the override
  file; the embedded default always registers. A test plants a hijack template in the
  working directory and asserts it is ignored while the default renders.
* **.NET handler accepted tokens with no `token_type` at all** (audit CS-4). The check was
  `is not null && != "Bearer"` -- a claim that was simply absent passed. The Go issuer
  always emits `token_type=Bearer`, so the handler now requires it, with regression tests
  in both directions.
* **A-7: the anti-enumeration dummy hash now rotates hourly.** One salt per process
  lifetime meant a deterministic Argon2id memory-access pattern. The naive fix (reassign
  the exported var from a timer) would race three packages that read it unsynchronized;
  instead the exported sentinel never changes and `VerifyPassword` substitutes a rotating
  hash held in an `atomic.Value`. Regeneration failure keeps the previous valid hash, so
  the constant-time burn never degrades.
* **OAuth state width** in the Blazor client raised from 16 to 32 bytes to match the PKCE
  verifier (CS-12). CS-14 resolved as no-change: `/auth/logout` is an authed route that
  revokes by `claims.Subject`, so the Authorization header is required by design.

### Testing

The 0.9.4 theme continues -- the failures that matter are the silent ones -- with a twist:
this round also hunted the tests themselves for silent failure.

* **Migrations that fail at COMMIT.** A deferred-constraint migration passes every
  `tx.Exec` and dies inside `tx.Commit`; a plpgsql view masquerading as the tracking table
  fails mid-iteration after a clean `Query`. Both error paths now assert rollback with row
  counts, alongside the canceled-context, malformed-tracking-table, NULL-version,
  unreadable-file and duplicate-version branches. `internal/migrate` sits at its 39/40
  reachable ceiling.
* **Redis pool handshake failures.** AUTH/SELECT/health-check write and read errors on
  dead connections, pinned with `net.Pipe` so they are deterministic instead of racing a
  kernel buffer. One of these branches was the suite's known coverage flake; it no longer
  is.
* **Signing keys that stop signing.** Keystore decrypt/parse failures after a healthy
  startup, CAS races on identity upserts, scan errors across thirteen list loops, CLI
  entropy failures, HIBP body-read failures, WebAuthn finish paths, KMS wrap with an
  empty kid -- every one asserts the exact wrapped error, not just "an error".
* **Tests that could not fail, fixed.** A pre-existing MFA status test accepted both 200
  and 500; a goroutine tail ran past test end and made its coverage timing-dependent; a
  compliance subtest depended on a sibling having run first. All three are now
  deterministic -- a test that passes either way is a coverage number wearing a trench
  coat.

### Docs

`docs/security.md` gains AR-11 (the unmaintained `openpgp` package inside `x/crypto`:
module-level advisory, never imported, unfixable by upgrade, guarded by the
three-direct-deps rule). COMPLIANCE.md cross-references the new suites; TODO items A-7,
CS-4, CS-12 and CS-14 are closed.

## 0.9.4 (2026-07-14)

Coverage **92.42% → 94.67%** (7641 of 8071 statements), which is where the version comes
from. Nothing was deleted to reach it: every point is a test that did not exist.

94.69% is not reachable at this statement count — one statement is 0.0124 points, so the
total steps 94.68 → 94.70 and skips it. 94.67 is the nearest reachable figure on the scheme.

### Testing

The theme is unchanged from 0.9.2 and it is the only theme worth having here: **the
failures that matter are the silent ones.** Almost every branch below returns a zero value
that is indistinguishable from a legitimate answer, so nothing anywhere reports a problem —
the feature simply stops working, and the first person to find out is the attacker.

* **A decompression bomb.** Blobs are deflate-compressed *before* they are encrypted, so
  the database — and the upload limit, and the per-user quota — only ever see the compressed
  size. The test builds the real thing: **11,222 bytes stored, expanding to 11,534,336**, a
  thousandfold amplification that every upstream check waves through. It also asserts the
  download *fails* rather than returning a truncated 10 MB prefix, which is what a
  `LimitReader` hands back if nobody checks whether it hit the limit.
* **Refresh-token replay.** `MarkUsed` is the atomic compare-and-set that decides whether a
  refresh token has already been spent — that single bool is the entire replay defence. On a
  database failure it must not return `(true, nil)`.
* **HTTP response splitting.** A blob label is user-supplied and is echoed into a response
  header on download. A label carrying CR or LF ends the header and begins another one: the
  attacker writes their own headers into a response the victim's browser trusts.
* **An open redirect in the OAuth authorize flow.** The authorize URL comes from the
  provider and is reflected straight back to the browser. `javascript:`, `data:` and
  off-site URLs are all refused — now with a test that says so.
* **HIBP k-anonymity.** Only the first five characters of the password's SHA-1 may leave the
  process. The test fails if the hash suffix or the plaintext is ever sent upstream;
  without it, every registration could quietly be handing a crackable credential to a third
  party. The documented fail-open on an HIBP outage is pinned too.
* **The Argon2 overload guard.** Each hash costs ~46 MB, which is what makes Argon2id a good
  password hash and also a denial-of-service primitive aimed at yourself. The semaphore is
  what turns "the process is OOM-killed" into "the server answers 503", and its rejection
  path had no test — a `("", nil)` from `HashPassword` would have stored an empty password
  hash.
* **The 2FA challenge device binding.** A challenge token is bound to the device that
  triggered it. Without the check, an attacker who lifts the challenge out of a victim's
  browser mid-flow finishes the second factor from their own machine and walks away with a
  full session, having never touched the victim's authenticator.
* **Backup-code brute force.** A backup code is 16 hex characters. A per-IP limit costs an
  attacker rotating addresses nothing, so the shared per-account lockout is the only thing
  protecting them. A locked account is now refused *before the codes are even fetched*, and
  a wrong guess consumes nothing — otherwise an attacker could burn a victim's codes simply
  by guessing at them.
* **The admin lockout counter fallback.** If the counter write fails, the handler falls back
  to the count it already holds in memory. That fallback is what stops an attacker buying
  unlimited guesses at the break-glass admin by knocking the counter over.
* **`EnsureFirstAdmin` on a failed count.** It decides at boot whether to mint a bootstrap
  admin. A swallowed error reads as "zero admins exist" — so a database blip would create a
  fresh privileged account, and print its password to the logs, on a vault that already has
  admins.
* **Key rotation and revocation, against a real Postgres.** The success paths are
  unreachable from a unit test with a dead keystore, so they had never run. The test asserts
  the key *actually moves* — a new kid comes back, the revoked one stops being active —
  rather than that the endpoint answered 200. A rotate that reports success while the old
  key keeps signing is the exact failure this surface exists to prevent.
* **The erasure endpoint exists only when a recovery *store* is wired.** The gate is
  `d.Recovery`, the repository — not `VAULT_RECOVERY_PUBLIC_KEY_FILE`, and `cmd/vault`
  always wires the repository, so on a real deployment the endpoint is always mounted.
  Without a recovery key the escrow is simply skipped and erasure proceeds unrecoverably;
  the fail-closed behaviour is inside the service, which refuses to erase if a *configured*
  escrow cannot be written. What the test asserts is the wiring, and that is what it now
  says.
* **The consent compare-and-set returns 409.** The CAS added in 0.9.0 stops a profile update
  silently reverting an unsubscribe — but its *HTTP mapping* was never tested. A 200 there
  is the same defect the CAS exists to prevent, moved one layer up.
* **Redis, both ways it dies**; **Postgres repositories against a dead pool** (a silent
  `IncrementFailedLogin` means the lockout counter never advances — brute force with no
  ceiling and no error in the logs); **the Art. 15 export never returns a partial**; and the
  erasure cascade fails closed at every one of its nine stores.

Not covered, deliberately: the rate-limiter eviction loop. Reaching it needs a production
refactor that would move the statement count, and destabilising the number to chase nine
statements is a bad trade.

## 0.9.2 (2026-07-14)

Coverage lands at **92.42%** (from 90.12%), which is where the version number comes
from. 0.9.1 was never cut: the work below started as a coverage bump and turned up a
defect that made the coverage number itself untrustworthy, and the honest total after
fixing it was past the range 0.9.1 could occupy.

### Fixed

* **The suite's own coverage total was nondeterministic.** Two tests in `internal/audit`
  raced, and the total moved by a statement between identical runs — so the number CI
  published could disagree with the number in `docs/badges.json` and the README, with
  nothing to indicate which was right. That is the same class of defect as 0.9.0's false
  90.42% claim, one layer down: a measurement that cannot be reproduced is not a
  measurement.

  The root cause was `Retention.Stop()`. It closed `stopCh` and returned immediately —
  it only ever *asked* the sweep loop to finish. `TestRetention_StopsOnContextCancel`
  then cancelled the context *and* called `Stop`, leaving the loop's `select` with two
  ready cases; Go chooses among ready cases at random, so which `return` the profile
  recorded was a coin flip. Both retention tests also returned without waiting for the
  loop to exit at all, so the goroutine could miss its scheduling window entirely.

* **`Retention.Stop()` could return while a sweep was still running.** The same bug, seen
  as a shutdown defect rather than a test one. Its only caller is
  `defer auditRetention.Stop()` in `cmd/vault/main.go`, which returns straight into the
  deferred close of the database pool — so `Stop` could return with the sweeper still
  inside its `DELETE`, and the pool would be torn out from under it. The test asserting
  this ("otherwise the sweeper outlives shutdown and keeps issuing deletes against a
  closing pool") asserted nothing at all: it called `Stop` and returned.

  `Stop` now blocks until the loop has exited, is idempotent, and is safe on a sweeper
  that was never started; `Done()` makes the exit observable. This is the pattern
  `keystore.Stop()` already used (`stopOnce` + `wg.Wait()`), which is why keystore's
  shutdown was never flaky and retention's was.

* **Erasure filed a fabricated email address in its own audit record.** On a retry of an
  interrupted erasure the user row already holds the tombstone, so `maskEmail(user.Email)`
  masked `deleted-<id>@deleted.invalid` and recorded *that* as the erased address — a
  value that never belonged to anyone, in the one record an investigator would trust. The
  retry path now records `retry: true` and states that the address was captured by the
  original attempt.

### Testing

Coverage raised to **92.42%** (7459 of 8071 statements). The theme is that the codebase's
fail-closed guarantees were asserted in comments and prose but not in tests — most of
what follows covers an error branch whose failure mode is *silence*.

* **The erasure cascade, step by step.** It spans nine stores with no transaction to roll
  back with, so every step must surface its own failure. Each of the seven steps is now
  failed in turn, asserting the error surfaces, names the step, and stops the cascade. A
  swallowed error here means `DeleteAccount` returns nil, the audit log records an
  erasure, and the data is still in the database — while `docs/PRIVACY.md` §5.3 says
  otherwise, and under Art. 17 that is a statement a regulator relies on.
* **The keystore against a dead database.** A `Rotate` that reported success without
  writing would leave an operator believing a compromised signing key had been retired; a
  `Revoke` doing the same leaves a stolen key signing valid tokens; an `EnsureKey` that
  swallowed its error at boot brings the process up "healthy" with no active signing key.
  Same for the admin endpoints that drive them.
* **Redis, both ways it dies.** The dial-failure and the command-failure paths are
  separate branches, and only the second one is taken when Redis dies underneath a live
  pooled connection (a restart, a failover, an idle proxy timeout). The zero values here
  are all indistinguishable from success: `Set` returning nil means an OTP looks stored
  and then vanishes; `SetNX` returning `(true, nil)` means the single-use guarantee
  behind OTP redemption silently disappears and a code becomes replayable; `Incr`
  returning `(0, nil)` means every request looks like the first in its window and the
  rate limiter stops limiting.
* **The user, blob and audit repositories against a dead database.** `IncrementFailedLogin`
  quietly doing nothing means the lockout counter never advances — brute force with no
  ceiling and no error in the logs. `SoftDeleteScrub` doing nothing means an account
  reported as erased with its real email still in the table.
* **HIBP k-anonymity is now asserted, not assumed.** Only the first five characters of the
  password's SHA-1 may leave the process. The test fails if the hash suffix or the
  plaintext is ever sent upstream — without it, every registration could be handing a
  crackable credential to a third party and nothing would say so. The documented
  fail-open on an HIBP outage is pinned too, as is the requirement that a *disabled*
  check does not still leak prefixes.
* **Refresh rejects accounts that changed since login.** Banned was covered; **disabled**
  and **the user row is gone** were not — the two an operator actually reaches for, since
  disabling is the routine response to a compromised user and a vanished row is what
  erasure leaves behind. Both must revoke the entire token family, or a sibling refresh
  token mints a fresh pair a second later.

## 0.9.0 (2026-07-14)

### Fixed in second review

A second, independent review of the fixes below found six more — including two that
predate this release and were never caught because the test suite cannot see them:

* **Account erasure had never worked in a real deployment.** `SoftDeleteScrub` writes
  `auth.users.email`, and `vault_app` was never granted `UPDATE` on that column;
  Postgres rejects the entire statement if a single target column is denied, so every
  erasure request failed with `42501`. The admin gateway was worse — `vault_admin` held
  `SELECT` and nothing else on the user tables, so admin-initiated erasure could not
  touch a single row. Migration `009_erasure_grants.sql` grants exactly what the cascade
  needs and nothing more.
* **The suite could not have caught it.** `tests/integration` connects as the container
  owner (a superuser) *and* `stripRoleGrants()` deletes every `GRANT`/`REVOKE` before
  applying the migrations — the privilege model is removed from the fixture. Added
  `TestErasureUnderVaultAppRole`, which re-applies the grants verbatim and connects as
  the **real `vault_app` role**. It fails without migration 009 and passes with it.
* **Three more services were holding the zeroed master key.** The fix below copied the
  key for the identity service but missed `keystore.New`, `NewAuthHandler` and
  `NewHandler` in the gateway, and `keystore.New` + `NewAuthService` in `cmd/vault`. The
  keystore encrypts the **JWT signing keys** at rest — under an all-zero key a database
  dump yields forgeable tokens — and the auth service HMACs email-OTP codes. Both
  binaries now take the copies at the top of `main`, before any consumer.
* **`PUT /user/identity` swallowed a failed consent read** (`err == nil && existing != nil`),
  so a transient DB error re-opened both bugs it was meant to close: an omitted field
  blanked a stored withdrawal, and an echoed imported flag was stamped affirmative. It
  now fails the request instead of guessing.
* **`PUT` still raced unsubscribe.** It read the prior consent and then wrote blind, so a
  withdrawal committed in between was silently reverted. The read, the reconciliation and
  the write now happen inside one compare-and-set (`IdentityService.PutProfile`).
* The compare-and-set had no honest test — every mock returned "won the race"
  unconditionally, so inverting the CAS semantics passed the suite. Added a mock that
  actually loses races.

### Fixed in first review

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

* **Coverage raised to 90.12% across the full suite** (from 86.69%). The 0.9.0 release notes
  and its commit subject said 90.42%: that was the number before the two rounds of review
  fixes, and the prose was not updated when the fixes moved it. `docs/badges.json`, the
  README badge and `docs/test-coverage.md` all carried the correct 90.12%. Corrected here
  rather than left to rot — a document that asserts something the artifacts contradict is
  the exact defect class this release exists to fix.
  Added real behavioural tests for previously-uncovered surfaces:
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
