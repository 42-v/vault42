# Changelog

## 1.0.0 (2026-08-18)

The version number is the coverage figure, so 1.0.0 could only ever mean a fully covered
tree. It turned out not to be honestly reachable, and saying why is most of what this
release is about.

Of the 48 statements uncovered at 0.9.9, six were reachable by tests nobody had written and
seven needed a production seam whose only consumer would have been a test. Six were not
defensive at all but dead, and are deleted: the `Nil` branch in the redis exec path, the
`crypto/rand.Read` error checks in `crypto/argon2.go` and `crypto/recovery.go`, which cannot
fail on the Go 1.26 toolchain because it terminates the process instead, and the duplicate
template compile in `email/preview.go`. The rest are defensive branches that cannot execute
given inputs the surrounding code has already validated, and each is recorded in a reviewed
exclusion set with the source line frozen and a justification a reviewer can check. The
hardening work in this release added statements of its own, so that set stands at 50 entries
rather than the 39 it started from. So the claim is **100.00% of reachable statements**,
CI-gated on `covered + excluded == total`, with the entry count held as a ratchet in
`scripts/cov-gaps.py` that a 51st entry fails on its own.

1.0.0 is also the semver commitment, which made this the last cheap moment to fix the API
shape. Everything under Public API below is breaking-after-1.0.0 and free before it.

### Security

* **No maximum session lifetime existed.** Refresh rotation issued a fresh full TTL every
  time and `auth.refresh_tokens` had no family-creation column, so a client that kept
  refreshing held a session forever. Migration 013 adds `family_created_at`, backfilled per
  family from its oldest token; the origin is read back inside the `INSERT` rather than
  accepted from the caller, so a rotation cannot move it. `VAULT_MAX_SESSION_LIFETIME`
  (default 720h) bounds total family age independently of activity, and the reissued expiry
  is clamped to the deadline so the last rotation before it cannot walk out with a full
  window.
* **`GET /admin/clients/{id}` returned the argon2id client secret hash.** It serialized
  `*model.Client` directly. Tests already proved the session-token and password hashes did
  not leak; nobody had written the equivalent for clients. All 22 serialized model structs now
  carry JSON tags, with credential material and the device fingerprint hash marked `json:"-"`
  so accidental serialization cannot put them on the wire at all.
* **The import-claim login path was an unauthenticated oracle.** A `202
  import_claim_required` disclosed both that an address was registered and that it was an
  unclaimed import, fired an email to the victim on demand, and, because each send
  invalidated the previous claim token, let an attacker block a legitimate user's claim link
  indefinitely. It now burns the same dummy Argon2id verification and returns the same
  `401 invalid_credentials` as a wrong password, with the shared bookkeeping extracted so the
  two paths cannot drift into distinguishable side effects.
* **The login lockout was an account-existence oracle.** The per-user lockout counter only
  advances for an address that exists, so a locked account answered `403 account_locked` while
  an unknown one answered `401`, and rotating the probe IP slipped past the per-IP limit. Both
  lock branches now burn the same dummy Argon2 and return `401 invalid_credentials`, and
  advance the per-IP failure counter like every other failure path, so neither the immediate
  response nor the IP-lockout progression distinguishes a locked account from an unregistered
  one. The lockout still holds and the audit row keeps the true reason.
* **The banned and disabled login checks were the last two of the same oracle.** Both ran
  before the password was verified, so a real banned or disabled address answered `403` while
  an unknown one answered `401`. They now run only after a successful `VerifyPassword`: a wrong
  password or an unknown address stays masked as `401`, and only a caller who proves the
  password learns the account is banned or disabled. With the locked and import-claim paths
  this closes all four outcomes of ASVS V6.3.8 (accepted risk CR-19 in the compliance
  register), now Met above the assessed L2 baseline.
* **The OAuth callback leaked which addresses were registered.** A provider that cannot prove
  the caller owns the address (Facebook publishes no per-address verification signal; an OIDC
  issuer can answer `email_verified:false`) let an attacker assert a victim's address. A
  registered one returned `409 email_already_registered`; an unknown one created an account,
  mailed the victim a verification link, and returned a success redirect -- an enumeration
  oracle, a mailbox-squat and an unsolicited-send primitive at once. A first-time sign-in from
  a provider that cannot prove ownership now returns one neutral `#error=verification_required`
  redirect before any lookup, identical either way, creating nothing and mailing nothing.
  Takeover was already blocked by the both-sides-verified link rule; verified providers and
  already-linked identities are unaffected.
* the concurrent-session cap now applies to OAuth logins, which wrote a refresh-token family
  without it. Client credentials remain exempt because that path discards its refresh token
  and creates no family, which is a structural exemption rather than a gap.
* the RSA private key rotated out of the token service is now zeroed, and the decrypted
  signing-key PEM in the keystore is wiped on both the success and the parse-failure paths.
  Signing also holds the read lock for the whole of `SignToken`, so acquiring the write lock
  drains in-flight signers first. That is ordering hygiene rather than what makes the wipe
  sound: the wipe clears exported fields signing does not read, which is also why a retired
  key stays usable afterwards.
* **Refresh reuse detection did not burn the family.** Two requests presenting one stolen
  refresh token both passed every check on the row they read. The loser called
  `RevokeFamily`, which updates the rows a family has at that instant, and the winner then
  inserted a successor no revocation had touched. The loser got `replay_detected`, the
  winner kept a rotating session for the rest of the absolute session lifetime, and the
  audit log said the family had died. The fix locks rather than reads: the rotation insert
  is conditional on the family carrying no revoked row and takes `FOR UPDATE`, and
  `RevokeFamily` pre-locks in a statement of its own. A re-read does not work, because a
  snapshot read and a snapshot `UPDATE` can be mutually invisible, and the tests show it:
  dropping only the `FOR UPDATE` leaves the end-to-end race test green.
* **`vault_app` could publish its own verification key into JWKS.** `Refresh` loaded every
  row's public key but decrypted the private half only for the active one, so an `INSERT`
  with a garbage `private_key`, `status='retired'` and a null `expires_at` put an attacker's
  key in `/.well-known/jwks.json` within one refresh interval: a signing oracle for any
  subject, without the master key or any vault42 private key. Two variants had to be closed
  separately. Requiring the private half to decrypt is not enough, because `UPDATE` can swap
  `public_key` on a genuine row, so the published key is now compared against the public half
  of what decrypted. Making revocation irreversible is not enough either, because a revoked
  row's `kid` can be renamed to free the identifier, so migration 017 freezes revoked rows
  entirely, `DELETE` included.
* **Seeded users could never log in.** `cmd/vault` called `seed.Run` without the pepper while
  the CLI and the admin gateway passed it, so the server stored `Argon2id(password)` and
  login checked `Argon2id(HMAC(pepper, password))`. The pepper is mandatory in production and
  `docs/config.md` recommends exactly the sealed-deployment configuration that triggers it,
  so this was a certainty rather than an edge case. The pepper is a positional parameter now,
  so omitting it cannot compile.
* **An account lock did not stop a social login.** The OAuth callback checked deleted, banned
  and disabled and never read `locked_until`, under a comment claiming parity with password
  login. The documented response to a takeover closed every route except the one an attacker
  with a linked identity already had. The same callback's unique-violation path also linked an
  identity with no verified-email check, and `internal/oauth2/facebook.go` derived that flag
  from `info.Email != ""`, so for Facebook "verified" meant "non-empty".
* **The unverified-email login path was a password oracle.** The error was identical; the side
  effects were not. A wrong guess advanced the lockout counter to a 403 while the correct
  password answered 401 forever, so six attempts confirmed a real password.
* **`keystore.Stop` zeroed the master key every other service was still using.** One slice was
  shared with the identity, blob and TOTP paths, so a request draining through shutdown
  encrypted against 32 zero bytes and wrote a permanently undecryptable row.
* **The geo fence trusted whoever it was fencing.** The country header was read straight off
  the request while every other caller-supplied signal is trusted-proxy gated, and omitting
  the header skipped the check entirely.
* **Lockout stopped holding during a cache outage.** The durable `failed_login_count` fallback
  existed but was reached only when the cache was nil, never when a read errored.
* **The audit log could lose a batch silently, and the loss was unobservable.** `Flush` emptied
  the buffer under the lock and inserted outside it, so a transient database error destroyed
  the entries it held with the error discarded. A batch the database refuses outright is now
  requeued at the front of the buffer; a partially accepted batch has its refused rows
  quarantined and dropped, because requeueing them would wedge the pipeline on one unwritable
  row forever. Two counters reach `/metrics`: meeting a full buffer is a tuning problem, while
  a batch the database rejected means entries already reported as written are gone. Summed
  they could not distinguish the two, which is why they are separate series.
* **Four audit-worthy events had no emission site.** MFA enrollment, removal, verification and
  session revocation were never recorded, so an attacker who enrolled their own factor and
  revoked the owner's sessions left no trace. Three constants cover them: removal is filed
  under the enrollment event with `action=removed`, because the vocabulary in `internal/audit`
  has no removal constant and inventing one per authenticator type would not have helped a
  reader of the log.
* **The audit retention guard validated a different value than it applied.**
  `audit.cleanup_old_entries` is the only path that can delete an audit row, since the
  append-only trigger blocks every other one and this function disables it for one `DELETE`.
  It compared the caller's `INTERVAL` against a one-day minimum and then subtracted that
  interval from `NOW()` to build the predicate. Comparison canonicalizes a month to 30 days;
  subtraction uses the real calendar month. `INTERVAL '1 mon -29 days'` compares as one day
  and passes, and in February subtracts to a cutoff in the future, so the `DELETE` takes the
  whole table while the guard reports the horizon was respected. Neither Go caller can reach
  it, since both build a seconds-only interval from a `time.Duration`; the exposure is a
  compromised `vault_app`, which holds `EXECUTE`. Migration 018 computes the cutoff once,
  guards that variable, and deletes on it.
* **A blocked role escalation left no trace.** Both escalation guards recorded the attempt by
  inserting into `audit.audit_log` inside a `BEGIN`/`EXCEPTION` block and then raising. The
  row never survived: the `RAISE` aborts the statement that fired the trigger and rolls the
  insert back with it. The swallowed exception is what made it last, since the write was
  already being discarded on purpose and nothing distinguished never writing a row from
  writing one that was rolled back. Migration 019 emits `RAISE WARNING`, which is a log
  message rather than a row and survives the abort.
* **`POST /admin/users/{id}/lock` panicked.** `refreshTokenRepo` was built, used elsewhere, and
  `nil` passed to `adminapi.NewHandler`. The lock committed, the nil dereference became a 500,
  and the operator saw "lock failed" on an account that was locked, with sessions still alive
  and no audit row written.
* **`vault kms wrap` sealed nothing and reported success.** No length check ran between reading
  the input and sealing it, so an empty or truncated input produced a well-formed envelope and
  exit 0. This is a deploy-pipeline tool, so a failed earlier step yielded a valid looking
  artifact that unwrapped to zero bytes, surfacing much later as an empty secret in a running
  service. The guard rejects the input without trimming the payload, because a key legitimately
  carries a trailing newline and trimming would seal it a byte short. It sits in
  `kms.Service.Wrap` rather than only in the CLI, since `Service.Wrap` is exported and any
  caller reaches it; the CLI adds a stricter check of its own that also refuses input which is
  whitespace alone. `POST /kms/unwrap` still opens a zero-byte envelope on purpose:
  unwrap has to stay the exact inverse of every wrap that ever ran, and refusing one returns
  `unwrap_failed`, byte-identical to a tampered artifact, so the operator chases corruption
  instead. `vault kms wrap` also refuses a `--kid` outside `^[A-Za-z0-9][A-Za-z0-9._@-]*$`,
  because a kid carrying a space or a control byte produces an artifact that only opens under
  a string nobody can read back off a terminal.
* **`POST /mint` issued tokens for a `ttl_seconds` the contract refuses.** The seconds were
  multiplied into a `time.Duration` with no bound. `time.Second` is `2^9 * 1953125` and the
  odd factor is invertible modulo a power of two, so the nanosecond product repeats with
  period `2^55` in the seconds operand and every in-range lifetime has absurd preimages.
  `ttl_seconds=36028797018964568` wrapped to exactly 600s and was answered with 200 and a
  real signed token instead of `400 invalid_ttl`. The lifetime was never longer than the
  ceiling, since `exp` derives from the same wrapped value the ceiling check tests, so this
  is a contract violation rather than a privilege one. The seconds are bounded before the
  multiply now.
* **An OAuth signup with an unverified provider email created an account that could never
  become verified.** No mail was sent on that path, there is no resend route, and
  `GET /auth/verify-email` consumes a token rather than issuing one. `users.VerifyEmail` has
  exactly one caller, so there was no second path to the flag. The account was not
  unreachable, because a repeat login through the same provider still works, but the address
  was burned: password login is gated on the flag and any second provider is refused with
  409. The callback refuses the signup outright now, before any lookup or create, and answers
  the neutral `#error=verification_required` redirect: an address a provider will not vouch
  for should not become an account at all, rather than become one that needs rescuing. An
  account created from a vouched provider is verified on creation and needs no mail. The
  three exits that produce no mail are audited on the password signup path, which is the
  remaining caller.
* **Two secrets were passed through argv.** The chart ran redis with
  `--requirepass $(REDIS_PASSWORD)` and cloudflared with `--token $(TUNNEL_TOKEN)`, both
  sourced from Secrets. The kubelet substitutes `$(VAR)` before exec, so both cleartext
  values sat in `/proc/<pid>/cmdline` for the life of the pod, readable by anything in that
  PID namespace, by a debug container attached later, and by anything collecting a process
  listing off the node. Redis reads its password from a 0600 file in a memory-backed volume
  now, mounted with an `items` list for that one key so the container is not also handed the
  master key, HMAC secret and pepper. cloudflared reads its token from the environment.
* **The default chart install could not start.** The shipped values set `profile: production`
  with `tls.enabled: false` and `forceSecureCookies: false`, while the refresh cookie is
  `__Host-refresh_token`, which a browser discards without `Secure`. `Config.Validate`
  already refused that pair, so the default install was a CrashLoopBackOff with the reason
  one line deep in the pod logs rather than a silently dropped cookie. Secure cookies are the
  default now, and the chart refuses to render the combination outside dev.
* **Attacker-chosen values reached logs unescaped.** `SafeLogValue` replaced only NUL, tab, CR
  and LF, so ESC, the C1 range, VT, FF, BS, BEL, DEL and the Unicode line separators passed
  through. `net/url` accepts a percent-encoded ESC in the request line, and the resulting path is
  written by the access logger on every request, so an operator tailing logs during a scan had
  the sequence executed rather than displayed: `\x1b[2J\x1b[1;1H` clears the screen and homes
  the cursor, letting records already printed be overpainted with forged ones. Around twenty call
  sites carried a `#nosec` annotation resting on that guarantee. The bridge logged a decoy hit's
  raw path under an annotation claiming the path came from a known set, when decoy matching is by
  prefix and everything after it is attacker-chosen.
* **Every unrouted scan probe was logged as `GET /`.** The SPA fallback rewrote `r.URL.Path` in
  place before passing the request on, and both the access logger and the honeypot logger read
  that field after the handler returns. The honeypot profile serves the SPA specifically to look
  like a real app, which made the profile that exists to collect probe paths the one that
  destroyed them. Rewritten on a copy of the request.
* **`RedirectPath` was weaker than its own client-side mirror.** It accepted control characters
  and dot segments, which the WHATWG URL parser strips or collapses before resolving, so
  `/\n//evil.com` resolves protocol-relative and off-origin. Not an open redirect, because the
  client-side validator rejects them, but the server-side check was the weaker of the two.
* **`Email` accepted the full RFC 5322 mailbox grammar while the caller stored the whole
  string.** Registering as `admin <attacker@evil.com>` put a display name in the address column
  and split the uniqueness check, since `admin <a@b.com>` and `a@b.com` compared as different
  rows.
* **Every security boolean silently meant `false` on an unrecognized spelling, and two parsers
  disagreed about which spellings existed.** `envBool` accepted `true|1|yes`; the profile
  defaults used `strconv.ParseBool`. So `VAULT_MFA_REQUIRED=True` produced a password-only
  deployment that advertised `mfa_required:false`, `VAULT_DPOP_ENABLED=True` never mounted the
  DPoP middleware, `VAULT_HIBP_CHECK=True` accepted breached passwords, and `VAULT_AUTO_MIGRATE=no`
  ran migrations against a database the operator had refused. One parser now serves all three
  helpers and an unrecognized value refuses to start. `VAULT_PROFILE` was a free string where an
  unknown value became production silently, so `VAULT_PROFILE=Honeypot` gave a deception
  deployment whose trap accounts notified nobody. A geo blocklist with no `GEO_IP_HEADER` refused
  nobody and an allowlist denied everybody, with nothing checking either. `VAULT_PASSWORD_MIN_LENGTH`
  had no floor, so `0` accepted an empty password in production. Malformed entries in the proxy
  and IP lists were dropped with only a log line.
* **`recover -h` printed the production database password.** The `--dsn` flag defaulted to
  `os.Getenv("DATABASE_URL")`, and `flag.PrintDefaults` appends any non-empty string default to
  the usage text, so asking the offline recovery tool for help disclosed the credential to the
  terminal and to shell scrollback. The tool also had no output option, so the only way to keep a
  recovered record was a shell redirect at the operator's umask, writing every erased user's email
  and display name world-readable; `--out` now opens it `0600` with `O_EXCL`. Reaching `--limit`
  was silent, so a truncated compliance dataset looked complete, and calling the recovery-retention
  sweeper's `Start` twice panicked the process from a deferred close in a background goroutine.
* **A DPoP proof could be replayed after its replay entry expired.** The spent-jti entry lived
  `DPoPMaxAge + 30s` while the proof stayed acceptable across `iat ± DPoPMaxAge`, so a proof
  minted with a future `iat` outlived the memory of itself by about four minutes and the
  `dpop_proof_reused` rejection never fired. The entry now covers the whole acceptance window.
* **A social login could create a second verified account for a taken mailbox.** The OAuth
  callback looked the provider's email up without folding case, while the repository matches
  exactly. An IdP asserting a verified `Victim@Example.com` missed the existing
  `victim@example.com`, so the linking gate was skipped rather than failed, and a new account was
  created with `email_verified` true for a mailbox the attacker does not own. The address was also
  never validated, so a CRLF-bearing value was written to the row. Both closed by normalizing once
  before any lookup. An empty provider subject was likewise usable as an identity join key, where
  `UNIQUE(provider, provider_user_id)` made the first claimant permanent.
* **OIDC discovery accepted plaintext endpoints, including `jwks_uri`.** A self-hosted issuer
  behind a proxy with the wrong `X-Forwarded-Proto` advertises `http://` endpoints, and vault42
  fetched the signing keys over cleartext, which lets an on-path attacker substitute the JWKS and
  forge an `id_token` for any subject. Provider profile responses were also read unbounded, unlike
  every token exchange in the same package.
* **`vault_app` could grant itself the capability scopes it is fenced off from.** It holds
  `INSERT` on `auth.clients` and `scopes` is a plain `TEXT[]`, so one insert produced a working
  client credential carrying `mint:token` and `kms:unwrap`: the ability to assert any subject to
  every relying party and to open every KMS envelope, which is the entire trust model of those
  two routes. `VAULT_MINT_SCOPES` does not reach it, because that allow-list governs what a
  minted token may carry, not what a client row may hold. Migration 023 refuses any insert or
  update naming a privileged scope unless the writer holds `vault_admin`. There is deliberately
  no first-boot carve-out: `auth.clients` has no equivalent of the guarantee that
  `auth.admin_users` stops being empty, so "empty means first boot" would leave the escalation
  permanently open on any deployment that seeds no clients, and `vault_app` can read the table
  to know when that window is open.
* **`vault_app` could flip privileged account state.** Migration 024 revokes `UPDATE` on
  `banned`, `ban_reason` and `disabled` outright, since no application path writes them, and
  narrows the two that are written to their legitimate direction: `email_verified` may only go
  false to true, `import_pending` only true to false. `locked_until` was left open in 024 on the
  grounds that the CLI wrote it; `vault lock-user` and `vault unlock-user` are retired stubs
  now (see Public API), the web server's failed-login lockout is cache-backed and writes only
  `failed_login_count`, and the sole runtime writer is the admin gateway under `vault_admin`.
  Migration 029 revokes `UPDATE (locked_until)` from `vault_app`, which otherwise left the
  web-facing role able to clear a lock the admin plane had imposed for containment, with no
  audit trail of the clearing. Stated plainly rather than glossed: `vault_app` keeps
  `UPDATE (password_hash)` and always will, so takeover through a compromised application role
  is not closed and cannot be. What 024 removes is what password control does not reach, namely
  lifting a ban and mass account disablement.
* **A logout could leave a rotating session alive.** `RevokeAllForUser`, `RevokeByDeviceID`
  and `RevokeAll` were single `UPDATE`s, so a rotation in flight inserted its successor after the
  revocation had already chosen its rows, so a logout concurrent with a rotation could leave a
  live token behind. The fix is a deterministic lock order,
  ascending primary key, applied per row rather than per family, because the rotation path holds
  several rows of one family and waits for the next. The order also binds statements that never
  say `FOR UPDATE`, since `DELETE` locks each row as its scan reaches it, which is how the first
  attempt deadlocked against the expiry reaper. The two widest paths take a table lock instead.
  `DeleteAllForUser` does so because `vault_admin` holds `DELETE` but deliberately not `UPDATE`,
  and `SELECT ... FOR UPDATE` requires it; `RevokeAll` does so because locking every row
  individually before updating the whole table buys nothing over locking the table once.
* **A refresh in flight survived the erasure it raced.** The rotation insert refuses a family
  that carries a revoked row, and erasure is the one revocation that removes the rows instead of
  marking them: a family `DeleteAllForUser` has emptied carries nothing, so the guard was
  satisfied by an empty set and the successor landed anyway. The table lock erasure takes did not
  help, because it only orders the two and the insert runs second. The surviving row is a
  fingerprint hash, a device reference and a user id belonging to an account the cascade reported
  it had cleared, and it is neither used nor revoked, so `DeleteExpired` never collects it
  either. The erasure stayed one row short for good (Art. 17). `Create` now also asks whether the
  account survives. The cascade tombstones the user row before it touches this table, so the
  check closes the whole window rather than the width of one statement. A ban, a lock or a
  disable is deliberately not part of it: those leave the rows in place, so the family stays
  revocable and the next refresh ends it.
* **A stolen security key plus a password was enough.** `webauthn.Config` was built without
  `AuthenticatorSelection`, so `UserVerification` was the zero value and the user-verification
  check compared it against `VerificationRequired`, which is false on every assertion. A
  credential enrolled with a PIN could be asserted with CTAP2 `uv=false` and a single touch,
  and vault42 issued tokens. The sign-count path then wrote the UV-less flags over the stored
  ones, clearing the record that the credential had ever been enrolled with verification.
  Refused now, before any counter or flag write, and only for credentials actually recorded as
  user-verified, so PIN-less keys are unaffected.
* **Clone-detection containment could silently not happen.** A WebAuthn signature-counter
  regression is the strongest compromise signal this service has, and the response to it,
  revoking every active refresh-token family, discarded its error. The assertion was still
  refused, so the request was fail-closed, but on a transient database error every
  pre-detection session stayed alive and the trail was identical to the case where containment
  worked. The revoke stays non-blocking and now reaches the log, and the attempt is recorded as
  a `token_revoke` audit row whether it succeeded or failed. That event type is in the critical
  set, so the row is written synchronously rather than through a buffer a burst can drop, which
  is exactly the condition this signal shows up under.
* **The WebAuthn ceremony deadline was not enforced by the server.** `Timeouts.*.Enforce`
  defaulted to false, so the library stamped no expiry on the session and its own expiry check
  never ran; the challenge was retired only by its cache entry's TTL. Both now derive from one
  constant, so the enforced deadline cannot drift from the cache lifetime.
* **`sign_count` could not hold the whole `uint32` range.** The column was `INTEGER`, which
  stops at half the WebAuthn counter's maximum. Since the counter write is fail-closed and the
  stored value never advances on failure, an authenticator past 2^31 would stop working
  permanently rather than transiently. Widened to `BIGINT`; the Go side already holds the range
  on both shipped architectures.
* **A credential id could be registered twice.** WebAuthn level 2 requires refusing a
  credential id already registered, and the column had no unique constraint. Attestation is
  `none`, so the id comes from the authenticator, and `verify/begin` hands out the victim's
  ids in `allowCredentials`. Nothing authenticates by credential id alone today, so this was a
  trap rather than a bypass; it springs when a passkey login path resolves a credential with
  no user in hand. The handler refuses duplicates and migration 021 adds the index, since the
  handler check reads then writes.
* **A typo in `CACHE_BACKEND` silently became a per-process cache.** Any unrecognized value
  fell through to in-memory with no error, and the production guard only fires on the exact
  string `redis`, so `CACHE_BACKEND=Redis` skipped it while `/readyz` reported healthy. At
  four replicas the lockout threshold becomes 20 rather than 5, one captured TOTP code is
  redeemable on each pod inside its window, and one 2FA challenge token mints four session
  families. An unrecognized backend is an error now.
* **The DPoP replay key was the one cache key an attacker sized.** The jti from a self-signed
  proof was concatenated raw, and on the Postgres backend a key past the btree index limit
  errors the replay check rather than answering it, which the middleware logs and allows for a
  token that is not DPoP-bound. Hashed now, so the key is a fixed width.
* **A seed file naming an admin role that does not exist now fails validation.** The seed
  validator carried its own hand-written list of role names, a third source of truth alongside
  `rbac.ValidRoles` and `auth.admin_roles`, and it accepted `admin`, for which rbac defines no
  tier. It failed closed downstream at the foreign key, so the effect was an opaque insert
  error at boot instead of a validation message naming the role and the valid tiers. It now
  validates through `rbac.IsValidRole`. Relatedly, the seeder no longer derives an admin's
  privilege rank from a role's index in the exported `rbac.ValidRoles` slice: an importer
  sorting that slice in place would have inverted the ranking migration 016 enforces, at
  runtime and with the source unchanged, so the rank is now read from a private map gated
  against the ranks migration 001 seeds.
* **`ES256` verified against a key on any curve.** `VerifyES256` derived the expected raw
  signature length from whatever curve the presented key carried and never compared that curve
  against the one `alg` names, though RFC 7518 assigns exactly P-256 to `ES256`. A proof
  labeled `ES256` carrying a P-384 JWK, signed over SHA-256 and emitting 96 bytes of raw
  `r||s`, verified end to end through `ValidateDPoPProof`. That matters now that issuance binds
  `cnf.jkt`: the RFC 7638 thumbprint covers `crv`, so vault42 would have confirmed proofs no
  conforming relying party accepts, and bound tokens to them. The test that appeared to cover this
  labeled its proof `ES384`, which the algorithm allowlist rejects before any key is read, so
  it passed with the curve check deleted.
* **One signature had unlimited spellings.** `encoding/base64` skips `\r` and `\n` anywhere
  and, without `.Strict()`, ignores the unused low bits of the final character. A 256-byte
  RS256 signature is 342 base64 characters holding 2052 bits, so 4 bits are unreachable: 15
  alternate final characters verify, plus unlimited newline splices in the signature segment,
  which the signing string does not cover. Nothing keys on the token string today, but the
  compact serialization is what the DPoP `ath` binding hashes.
* **An `exp` of zero read as "no expiry".** `MapClaims` returned nil for a numeric zero, and a
  nil `exp` means none was claimed, so the most expired timestamp a token can carry validated
  as never expiring while `RegisteredClaims` parsing the same payload called it expired.
* **Retired signing keys accumulated forever.** `keystore.CleanupExpired` had no production
  caller, and no role held `DELETE` on `auth.signing_keys`, so it could not have reaped
  anything if something had called it. Migration 020 grants `vault_app` that `DELETE` and
  narrows it with a `BEFORE DELETE` trigger, since PostgreSQL has no row scope for a
  privilege and the bare grant would also cover the active key and every retired key still
  verifying live tokens. The trigger says nothing about a revoked row on purpose: same-event
  triggers fire in name order and `signing_keys_reap_scope` sorts ahead of
  `signing_keys_revocation_terminal`, so excluding revoked rows is what leaves migration 017
  the only guard that answers for a revoked key. The reap and the published set are disjoint
  by construction, because `Refresh` loads `expires_at IS NULL OR expires_at > NOW()` and the
  reap deletes `expires_at IS NOT NULL AND expires_at < NOW()` off the same transaction
  clock. `cmd/vault` now warns at startup when `VAULT_KEY_RETENTION_PERIOD` is shorter than
  the access-token TTL, a pre-existing way to strand live tokens that reaping removes the
  recourse for.
* **The honeypot bridge aimed its own decoy at the operator.** `/admin` was a decoy prefix and
  matching is by prefix, while vault42 serves its admin SPA and roughly thirty documented API
  routes under `/admin/`. An operator opening the console through a bridge was flagged for the
  full flag TTL and then served fabricated key, user, session and audit data. Bridge webhook
  dispatch also moved off the request path, since it blocked the very request that had just
  been flagged and let a scanner measure its own detection, and then behind a bounded worker
  pool, since a goroutine per event let one cheap request open one connection to the operator's
  alerting endpoint.
* **The password-reset request was an inverted enumeration oracle.** `POST /auth/password/reset`
  burned a dummy Argon2id verification only when the address mapped to no user, while the found
  path generated a token with no Argon2id at all, so a known address answered in about a
  millisecond and an unknown one in about fifty: the reverse of the constant-time intent the
  comment claimed, since a reset request verifies no password. Every request now spends the same
  dominant work before the lookup, one Argon2id verification and one token generation, so the
  response timing no longer depends on whether the account exists. A deleted, banned or disabled
  account no longer has a reset token stored or mailed either, where before the row's existence
  alone was enough, and the 200 stays indistinguishable in every case. A locked-out account is
  still eligible, since resetting the password is a legitimate way out of a failed-login lockout.
* **A second factor could mint a session for a subject that no longer resolved.**
  `CompleteMFALogin` read the user with the error discarded and gated account state behind a nil
  check, so a transient `GetByID` fault, or a subject deleted inside the challenge window, fell
  through to a default-role session that hid the account's banned or disabled state. It fails
  closed now on either a read error or a nil user, the way `Refresh` already does, so no token
  issues for a subject that cannot be resolved to a live account. Separately, the password-login
  `Deleted` branch masked a soft delete as `invalid_credentials` but skipped the dummy Argon2id
  the `user==nil` and import-pending paths burn, so a soft-deleted address answered about fifty
  milliseconds faster and was enumerable; it burns the same dummy hash now, so the masked error
  is masked in timing too.
* **DPoP now binds the token to the key.** `VAULT_DPOP_ENABLED` mounted middleware that
  checked a proof's structure, method, URI, `iat` freshness and single-use `jti`, and then
  compared the proof's thumbprint against a `cnf.jkt` claim no issuance path ever set. The
  comparison never ran, so a well-formed proof for any key passed, and a request carrying no
  proof passed as well. Issuance writes the proven thumbprint into `cnf.jkt` on the access
  token and the 2FA challenge token, and a token carrying one is refused unless the request
  presents a proof over the matching key under the `DPoP` authorization scheme rather than
  `Bearer`. The middleware sits inside the auth middleware on every authenticated route, not
  only on the token endpoints, because one route that treats a bound token as an ordinary
  bearer token is where a stolen token gets replayed instead. Two limits remain and are
  stated rather than carried as a risk: refresh tokens are not sender-bound, and there is no
  `DPoP-Nonce`, so freshness rests on the proof's own `iat` and the replay cache.
* **The admin gateway's mTLS gate answered only one question.** `RequireAndVerifyClientCert`
  established that a certificate chained to the configured CA and nothing looked at the peer
  afterwards, so every certificate that CA had ever issued reached `POST /admin/login` and,
  from there, the effectively global per-IP limiter of AR-8: a decommissioned operator's
  certificate, a service certificate, one minted for a different component.
  `ADMIN_GW_CLIENT_CN_ALLOWLIST` pins the accepted identities by exact match against the CN
  and the DNS, email and URI SANs, and `ADMIN_GW_CLIENT_CRL_FILE` checks revocation on every
  handshake against a list whose signature is verified against the gateway's own CA first.
  Both fail closed once set. Neither is mandatory, because refusing to start without them
  would break every deployment on upgrade; an unset allowlist logs a warning naming exactly
  what it costs.
* **Whole client addresses reached the process log.** `httputil.ObfuscatedIP` existed and the
  compliance suite asserted under ASVS V16.4.1 that a source address is pseudonymised before
  it is logged, but the assertion checked the helper rather than the call sites. Thirteen
  lines across the middleware, the admin gateway and the bridge wrote the address in full.
  Every one masks to a network now, IPv4 to /24 and IPv6 to /64. `cmd/bridge` is stdlib-only
  and carries its own copy of the helper for the same reason it carries its own log
  sanitiser.
* **The Prometheus collector shared the API mux**, so every counter in the process was one
  route away from the public listener. It binds its own listener now, `VAULT_METRICS_ADDR`,
  defaulting to `127.0.0.1:9090`. A metrics bind failure stays non-fatal, and that ran
  backwards while the metrics listener started first: pointing `VAULT_METRICS_ADDR` at the
  API port meant the collector won the race and the API's own bind failed fatally, so for the
  width of the crash loop the port the Ingress routes to answered an unauthenticated read of
  every counter. The API listener binds first, and a contended metrics port is refused by
  name.
* **Nothing rotated the signing key.** `VAULT_KEY_REFRESH_INTERVAL` is how often a pod
  re-reads the store and `VAULT_KEY_RETENTION_PERIOD` is how long a retired key lingers;
  neither rotates anything, so a default install signed every token it ever issued under one
  private key. `VAULT_KEY_ROTATION_INTERVAL` (default 720h) rotates on the stored key's own
  age rather than on process uptime, serialised across replicas by a session advisory lock so
  a rolling restart does not rotate once per pod. A non-positive value disables the scheduler
  and says so at startup. Separately, migrations 026, 027 and 035 make retire, revoke and
  reactivate terminal: a retired key could previously be walked back to active, a retired row
  could carry no expiry so the reaper never collected it, and a rotated-out key could be
  revived by re-importing its material.
* **First-boot credentials were written to the process log and passed through argv.** The
  first-boot `super_admin` password, the admin CLI token and each seeded client secret are
  minted exactly once with no second chance to show them, and all three went to stdout or
  stderr on a long-running process, which is a log shipper's input and a process listing.
  They go to a configured sink opened `O_APPEND` with the symlink and permission checks made
  explicitly rather than assumed, the CLI authenticates from `ADMIN_TOKEN_FILE`, and the
  scripts stop echoing live tokens into captured output.
* **Outbound SMTP would send unencrypted.** A server that did not offer STARTTLS got the mail
  anyway, putting verification and reset links on the wire in cleartext. STARTTLS is required
  with a TLS 1.2 floor unless `VAULT_SMTP_ALLOW_PLAINTEXT` says otherwise, which is itself
  refused outside the dev profile and loopback. `DB_SSLMODE=disable` had the same shape and
  the same fix: outside dev it refuses to start, because it moved the database credential and
  every row in cleartext without comment.
* **`POST /client/token` authenticated from the query string.** `client_id` and
  `client_secret` in the request URI is what RFC 6749 §2.3.1 forbids, because a URI reaches
  access logs, proxies and referrers. Credentials are read from the POST body only, and a
  bearer rejection now carries the RFC 6750 §3 `WWW-Authenticate` challenge it owed a
  conforming client.
* **The first-admin bootstrap reopened whenever `auth.admin_users` was empty**, so deleting
  every admin re-armed it. It fires once per deployment.
* **Lockout counted per account only**, so an attacker spreading guesses across accounts from
  one source never met it. It is keyed on the source as well, with a delay that grows with
  the failure count. And enrolling or removing a second factor left every existing session
  alive, so an attacker who added their own factor kept the sessions the change was meant to
  invalidate; an MFA change revokes the subject's refresh-token families.
* **A `/mint` request refused for a missing scope left no audit row.** The scope middleware
  rejected it before the handler, and the handler owned the audit call, so the probes that
  never reached it were exactly the ones nobody could see. The scope gate records every
  refusal it makes, on a context of its own so a caller who hangs up cannot cancel their own
  record.
* **`POST /admin/sessions/revoke-all` did not revoke user tokens**, though four documents said
  it did. It does. Revoking admin sessions deliberately has no route: that is a different
  blast radius and wants its own permission at `super_admin` tier.
* **The two planes could disagree about `HMAC_SECRET`.** Both derive the erasure tombstone
  from it independently, so a deployment whose planes hold different values produces
  tombstones the other plane cannot recognise. The admin gateway verifies agreement at
  startup and refuses to serve otherwise.
* **A login from a country the account had never used produced no signal to its owner.**
  `auth.login_countries` records the set of countries seen, a first-seen country sends a
  notice, and anonymising infrastructure raises the rate-limit scrutiny weight for the
  credential-guessing buckets. The country is resolved from an embedded table with no
  outbound request, and the table stores a two-letter code and a first-seen timestamp with
  deliberately no IP column. Migration 030 erases it with the account.
* **Erasure missed two classes of data.** `auth.login_countries` was not reached, and neither
  was any `auth.users` column added after the tombstone function was written, because the
  function names its columns rather than scrubbing the row. The `ON DELETE CASCADE` on those
  tables never fires either, since erasure tombstones the user row instead of deleting it, so
  every removal is an explicit step. Migrations 025, 030 and 031 close the set, the tombstone
  address can no longer be re-registered, and a test now requires every subject-linked table
  to declare an erasure story.
* **Nothing bounded the consumable resources.** No `statement_timeout` or `lock_timeout` on
  the pool, no `ReadHeaderTimeout` on the server, an unbounded in-memory cache, argon2 callers
  queueing five seconds behind a full semaphore, a goroutine per deferred email and per
  deferred audit write, and an audit purge that deleted the whole horizon in one statement.
  Each is bounded, deferred work runs on a pool that shutdown drains, and both the argon2
  queue depth and the fail-open HIBP count reach `/metrics` so the shed is observable before
  logins start being refused.
* **Limiter counters shared one key space**, so traffic to one endpoint consumed another's
  budget; the fallback map was unbounded; the social-login callback had no budget of its own;
  and the client-secret guessing surface failed open on a cache outage. Each limiter now
  namespaces its own keys, and the auth-sensitive ones fail closed.
* **The served Content-Security-Policy declared no `object-src` or `base-uri`** and was weaker
  than the policy the nginx image shipped, whose `connect-src` carried a wildcard. Both
  policies spell out `object-src`, `base-uri` and `form-action` rather than leaving them to
  `default-src`, which does not cover `base-uri` at all.
* **A `crit` header was ignored** on JWTs, on DPoP proofs and on verified `id_token`s, which
  RFC 7515 §4.1.11 requires a verifier to reject when it does not understand the extension,
  and a DPoP proof carrying private key material in its `jwk` header was accepted.
* **The bridge trusted headers a client could author**, resolved the client address from the
  wrong hop, let a `Connection` header strip the headers it relied on, and served a trap whose
  responses told a scanner it was a trap.
* **The chart shipped workloads the restricted Pod Security Standard rejects.** Every workload
  renders under it now, with probes, a disruption budget and a network policy on by default;
  seed credentials moved out of a ConfigMap into a Secret; the honeypot no longer mounts the
  production Secret; the admin gateway is off the host network; cloudflared declines its
  service account token; and mailpit and the nginx base are pinned by digest.

### Public API

* **Minted tokens carry a `minted_by` claim** naming the client that requested the assertion.
  `POST /mint` signs a subject vault42 never authenticated, and a relying party could tell
  *that* a token was minted, from `token_type: "mint"` and a distinct audience, but not by
  whom: the attribution existed only in a `token_minted` audit row that lives in vault42's
  database and no relying party can read. The claim is deliberately not named `client_id`,
  because the service document store treats that claim's presence as proof of an
  authenticated service caller and uses it as the ownership axis, so a minted token carrying
  it would be admitted as the minting client. `docs/security.md` AR-16 records the residual:
  nothing binds a client to the subjects it may assert, so `mint:token` means the holder may
  impersonate any subject the estate honors, and the four conditions under which that is
  reachable are written out there.
* **DPoP is no longer advertised in the discovery document.** It claimed RS256 and ES256
  support unconditionally, which was false in the OFF position and would still have been
  imprecise in the ON one. The key is removed rather than gated, because absent-then-added is
  compatible where advertised-then-retracted is breaking. The `DPoP` authorization scheme is
  rejected unless the flag is set, instead of silently degrading to Bearer. Binding itself
  landed after this entry was written; see **DPoP now binds the token to the key** under
  Security.
* **The OIDC provider claim is retracted.** The discovery document advertised an
  authorization endpoint, a `token_endpoint` pointing at a JSON email/password handler that
  ignores `grant_type`, and a `registration_endpoint` pointing at end-user signup. It now
  publishes only what is true: `issuer`, `jwks_uri`, and the access-token signing algorithm.
* `GET /admin/audit` emitted Go field names (`ID`, `FingerprintHash`, `RiskScore`) into an
  otherwise snake_case API, leaked a cross-account correlatable fingerprint hash, and echoed
  an internal repository filter struct. It now returns a snake_case projection without the
  fingerprint. As a side effect the admin SPA's audit table, which has been reading
  snake_case keys against a PascalCase API, renders again.
* list envelopes unified on `total`; `available_methods` and `mfa_methods` standardised on
  `mfa_*` with the old key kept as a documented alias; nil slices serialize as `[]`;
  timestamps use one encoding; `avatar_url` is readable on `GET /user/profile`;
  `GET /admin/metrics` returns 501 rather than a 200-OK stub documented as real.
* **Five `vault` CLI commands moved off the application role.** `lock-user`, `unlock-user`,
  `revoke-client` and `rotate-client-secret` are now retired stubs: each prints a pointer to the
  admin gateway and issues no database write. They ran under `vault_app`, whose grants this
  release narrows (migrations 023, 024 and 029), so the equivalent operations now go through the
  authenticated admin gateway instead. `cleanup-audit` is the fifth, and it has no admin-plane
  equivalent by design: audit retention is set with `VAULT_AUDIT_RETENTION_DAYS` and swept at
  startup and every six hours, and no admin tier holds an audit-delete permission. A script
  invoking any of the five must be repointed or dropped.
* **`GET /user/sessions` is keyed on the refresh-token family, not the device.** A family
  carrying no device was invisible in the list and therefore unrevocable, and two families
  sharing one fingerprint collapsed into a single row an owner could not tell apart, which is
  the opposite of what a session list is for. `SessionInfo.ID` is the family id and
  `DELETE /user/sessions/{id}` addresses it, establishing ownership from the caller's own
  active families rather than from the path value. The device id moved to `device_id`, and
  `created_at` and `expires_at` were added. A device id is still accepted for one release.
* **Access tokens carry `acr`, `amr` and `auth_time`.** A relying party could not tell a
  password-only login from one that completed a second factor, because the token said nothing
  about how the subject authenticated. The assurance level is derived from the authenticator's
  own user-verification result rather than from the fact that a method was configured, and
  `acr` is rendered as `urn:vault42:aal:N`, deliberately not one of the idmanagement.gov URLs,
  which belong to a federal assurance program vault42 has not been assessed under.

### Features

* **`POST /mint`** signs a token for a subject the calling service authenticated elsewhere,
  so a service owning its own user identifiers can obtain a vault42-signed token without
  proxying an end-user credential. Off by default and not mounted unless configured. A
  minted token is structurally rejected by vault42 itself: its `token_type` is outside the
  accepted set and its audience must differ from the issuer, which the config refuses to
  start without. Without that second control a mint credential would be account takeover for
  every vault42 user rather than a delegation mechanism.
* **A service-scoped JSON document store** lets a registered service hold arbitrary JSON
  against a subject, private to the writing service by default and optionally readable by
  all services. Encrypted with AES-GCM, bounded at 64 KiB per document, 32 documents and
  1 MiB per subject, and validated by a token walk for depth and duplicate keys before any
  unmarshal. Off by default. Erasure reaches these documents across every owning service,
  and the data export returns them decrypted, including private ones: a service's privacy
  from other services is not privacy from the data subject.
* **The frontend was not usable without a mouse or a working colour eye.** The palette did
  not meet WCAG AA for text or controls, the three modals trapped no focus and restored none
  on close, authentication failures were rendered without being announced to a screen reader,
  and the document never declared its active locale despite shipping 38 of them.

### Compliance

The report was the liability. 242 requirements were claimed Met, enumerated nowhere, behind
a "94.2% weighted coverage" figure with no published weighting model. Five of the fifteen
Partial findings were factually wrong, and four were filed under IDs whose actual
requirement text is about something else.

* `docs/compliance-register.json` enumerates every requirement with its verbatim text, its
  `file:line` evidence and the name of the test that proves it. Statuses are Met, Accepted
  Risk or N/A, with nothing unclassified and no percentages. CI fails if a Met row names a
  test that does not exist.
* re-baselined onto OWASP ASVS 5.0.0, NIST SP 800-63B-4 and OWASP Top 10:2025. The NIST
  citations were the urgent ones: the document used the withdrawn title while the tests cited
  Rev 3 section numbers against a Rev 4 URL.
* NIST 800-53 Rev 5 and the Top 10 had no test carrying any control ID between them, so 67
  of the claimed 242 rested on nothing executable. They now have suites.
* three standards were added, each only where the code already satisfies it and a test can
  prove every row: the OWASP API Security Top 10 (2023), NIST SP 800-218 SSDF 1.1, and the
  Kubernetes Pod Security Standards restricted profile, which is the workload-scoped standard
  a Helm chart can honestly be held to. The register carries 404 requirements across nine
  standards.
* **`docs/security.md` and `docs/PRIVACY.md` each claimed a control that does not exist.**
  AR-5 described a service with no admin UI, no role-management API and no RBAC consumers,
  written before roughly 30 RBAC-gated endpoints shipped. PRIVACY §7.1 asserted breach
  detection via elevated risk scores; every `risk_score` reference is a write or a read-back
  for display, with no threshold and no alert anywhere. Both rewritten to describe what the
  code does.

### Documentation

* **`docs/UPGRADING.md` is new, and an upgrade should be read out of it rather than
  reconstructed.** Nothing in the tree said what `helm rollback` does and does not restore.
  It restores the chart; it cannot restore the schema, so the previous binary runs against a
  database up to 23 migrations ahead of it, and at least one of those breaks it outright
  (029 revokes `UPDATE (locked_until)` from `vault_app`, which is the role 0.9.9's
  `lock-user` runs as). The document says which shapes of migration are reversible and which
  only look it, states plainly that the schema's rollback path is the backup rather than a
  script this repo can ship, and carries the orphan-delete recovery for a `helm upgrade` that
  fails on an immutable field. Every procedure in it was executed against a live k3s cluster.
* `docs/spec.md` claimed authority "as of 2026-03-02" while three commits had edited its body
  since, making it a partially-updated hybrid rather than cleanly stale. It is rewritten
  around the real route surface, which the sentinel-delimited inventory now enumerates in
  full at 103 rows, with a normative section 0 stating the stability
  contract: the semver major is the API version, root paths are v1 permanently, and the
  asymmetry that clients must ignore unknown response fields while the server rejects unknown
  request fields is written down, because it means clients cannot feature-probe.
* a route-drift test parses the real registrations with `go/ast` and fails when a route
  exists in source but not in the docs, or the reverse. It caught the five routes this
  release added while they were still undocumented.
* 20 environment variables were missing from `docs/config.md`, three of which disable a
  fail-closed guarantee. They now have a prominent section of their own.
* godoc on every exported identifier in the security-critical packages, with the invariant
  documented at the code that enforces it. Three doc comments actively described behaviour
  the code does not have, including one claiming unconditional OIDC nonce validation that is
  skipped on an empty nonce.
* `docs/localhost-profile.md` is not published. It documents a specific workstation.

### Release engineering

* **releases are tag-driven.** `release.yml` fired only on a head commit starting with a bare
  version while commitlint rejected exactly that title, so a PR that passed CI produced a
  commit that never triggered a release. That silently swallowed 0.8.6, which has no tag, no
  release, and a NuGet gap between 0.8.0 and 0.9.0.
* **the Helm chart never installed.** `appVersion` was pinned at `0.1.0`, a tag that has
  never existed, and `image.tag` defaults to it, so every default `helm install` has been an
  ImagePullBackOff since 0.4.2. The bridge image the chart references is now actually
  published.
* `.golangci.yml` and `eslint.config.mjs` were invoked nowhere; both now run, blocking on new
  findings and reporting the backlog. There was no Go coverage gate at all.
* release artifacts, checksums and an SBOM are attached to the release, and `SECURITY.md`
  documents how to verify the cosign signatures that were already being produced.
* **a cosign signature says who published an artifact and nothing about what produced it.**
  Every image, the chart and the release archives now carry a SLSA provenance attestation
  assembled and signed by GitHub's attestation service under the release workflow's OIDC
  identity and recorded in Rekor, pushed beside the artifact in the registry so verification
  does not depend on the GitHub API staying reachable. The archives additionally ship their
  bundle as a release asset, so `gh attestation verify --bundle` works offline. Each archive
  carries SBOMs in both SPDX and CycloneDX form, and each SPDX document is attested to the
  archive it describes rather than to whichever one a glob matched first. BuildKit's own
  predicate still rides along on the images; it is unsigned and in no transparency log, and
  the release body says so rather than letting a reader take it for the same thing.
* the release binaries are reproducible, gosec scans the test files under a ratchet rather
  than skipping them, Trivy scans configuration and secrets as well as dependencies, the
  checkout token no longer persists in `.git/config`, and each release job holds only the
  token scopes it uses.
* `packages/dotnet` had 82% of its XML documentation written and shipped none of it: three
  separate switches suppressed it.
* **the Go toolchain moved to 1.26.6**, clearing seven standard-library advisories in one bump:
  GO-2026-6218 (`net/url`), 6091 (`html/template`), 6090 (`crypto/tls`), 6089 and 5026
  (`net/http`), 6088 (`encoding/xml`) and 5972 (`encoding/asn1`). `go.mod` pins
  `toolchain go1.26.6`; the three Dockerfiles, the browser-test module and the README badge move
  with it, so the tree that ships and the version it advertises no longer disagree.

## 0.9.9-B (2026-08-09)

The nightly security scan went red on 2026-08-08 against a tree that had not changed since
0.9.9 shipped: CVE-2026-67213 was published against `nanoid`, which reaches this repository
only as a transitive dependency of `postcss`. The vulnerable function is never called —
`postcss` imports `nanoid/non-secure` and uses the plain generator for source-map input ids,
not `customAlphabet` — but the Trivy source scan gates on the lockfile rather than on
reachability, and `exit-code: 1` makes it a hard gate rather than a report.

Fixing that took one line of `pnpm.overrides`, so the release became the compliance pass the
red nightly kept pointing at: nothing was watching the dependency floors between scans, and
pulling that thread found that Access Control had no compliance coverage at all. Coverage is
unchanged at 99.42% — see the note under Tests for why it could not move — which is why this
is a second cut of 0.9.9 and not a new rung.

### Security

* raise `nanoid` to 3.3.18 through a `pnpm.overrides` floor, clearing CVE-2026-67213 (HIGH,
  an unbounded loop in `customAlphabet`). The floor is bounded to `<4` deliberately: nanoid 5
  and 6 are ESM-only and expose no CommonJS entry point, while `postcss@8.5.25` reaches its
  generator through `require('nanoid/non-secure')` and asks for the `^3.3.16` line. An
  unbounded `>=3.3.17` would have resolved to 6.0.1 and broken the frontend build.

### Compliance

ASVS coverage goes from 70 checks to 76, opening two chapters the suite had never touched.

* **V4 (Access Control) was entirely absent.** `internal/rbac` and `internal/middleware` both
  sat at 100% statement coverage the whole time, which is exactly why the gap survived: line
  coverage records that a permission table was read, not that it grants the right things.
  Five checks now assert the properties instead of the lines. `viewer` may hold only `list`
  and `read` verbs, so a state-changing permission added to the read-only role fails the
  build rather than the next review. Roles must strictly widen from viewer through operator
  to super_admin. An unrecognized role — empty, `root`, `SUPER_ADMIN`, or one with stray
  whitespace — is granted nothing. `RequireScope`, which gates the KMS unwrap oracle, matches
  scopes exactly: neither `kms` nor `kms:unwrap:readonly` opens `kms:unwrap`.
* **Admin routes are now checked against the permissions they are wired to.** Every mutating
  route in the admin gateway must be gated by a permission `viewer` does not hold. This is
  the failure the RBAC tests structurally cannot see: the permission table stays perfectly
  correct while an endpoint enforces the wrong entry, and `POST /admin/keys/rotate` wired to
  `keys:list` reads as a normal line of router code. The check parses `router.go` with
  `go/ast` rather than matching text, and validates each constant against the real permission
  vocabulary so a rename fails loudly instead of silently resolving to nothing.
* **V14.2 (Dependency)** — `TestASVS_V14_2_1_PnpmOverrideFloors` reads every `>=` floor
  declared in `pnpm.overrides` and asserts each version resolved in `pnpm-lock.yaml` is at or
  above it. Parent-scoped overrides (`eslint>ajv`) are excluded, because they exist precisely
  to hold one consumer below the root floor. Until now a lockfile regenerated without the
  overrides stayed invisible until the next 3 AM scan; the floors are enforced on every CI run.

### Tests

* statement coverage is unchanged at 99.42% and could not have moved: `internal/rbac` and
  `internal/middleware` were already fully covered before these tests were written. Of the 48
  statements still uncovered across `internal/`, effectively all are defensive branches that
  cannot be reached with validated inputs — `aes.NewCipher` failing after a 32-byte key check,
  `hkdf.Key` failing in `kms.Wrap`/`kms.Unwrap` at a fixed output length — or need fault
  injection and a Redis container the coverage suite does not run. They were left alone rather
  than reached for by restructuring production code around the metric.

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
