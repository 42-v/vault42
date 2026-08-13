# Vault42 -- Security Decisions & Accepted Risks

> Complements [Spec section 13](spec.md#13-security-mitigations) and the
> [standards mapping](COMPLIANCE.md). Documents deliberate security tradeoffs and platform
> limitations that have been reviewed and accepted.

---

## Accepted Risks

### AR-1: Email/Password Reset Tokens Transmitted in URL Query Parameters

**Severity:** Medium (mitigated) | **Source:** SB-M2/M3

Email verification and password reset flows transmit single-use tokens as URL query parameters (e.g., `?token=...`). While URL parameters can appear in server logs, browser history, and referrer headers, the following mitigations reduce risk to an acceptable level:

- **Single-use:** Tokens are consumed atomically on first use via `GetAndDelete` (cache-level atomic get+delete). A token intercepted after use is worthless.
- **Short-lived:** Token TTL is configurable -- verification links default to 24 hours, password reset links to 1 hour.
- **Referrer suppressed:** `Referrer-Policy: no-referrer` is set on all responses (see spec section 13.3), preventing token leakage via HTTP referer headers to third-party origins.
- **HTTPS-only:** All traffic is TLS-encrypted. Tokens are never transmitted in plaintext.
- **Hashed storage:** Tokens are stored hashed in the cache backend, not in plaintext.

This is the standard approach used by the vast majority of authentication services. Alternative approaches (POST-based token submission, fragment identifiers) introduce UX or compatibility tradeoffs that outweigh the residual risk.

---

### AR-3: Email Template Symlink TOCTOU Race at Startup

**Severity:** Low | **Source:** SB-L7

The email template override directory (`VAULT_EMAIL_TEMPLATE_DIR`) is validated at startup for symlinks and forbidden content patterns. A TOCTOU (time-of-check-time-of-use) race condition exists: an attacker could replace a validated template file with a symlink between the validation check and the actual file read.

**Why this is accepted:**

- **Startup-only:** Template validation and loading occur once during application initialization, not at runtime. The race window is measured in microseconds.
- **Requires filesystem access:** Exploiting this race requires the ability to write to the template directory on the host filesystem at the exact moment of startup.
- **Filesystem access implies larger compromise:** An attacker with write access to the application's template directory already has sufficient access to modify the application binary, configuration files, or secret files -- all of which represent a more severe compromise than template injection.
- **Templates are re-validated:** Even if the race is won, the loaded template content is scanned for forbidden patterns (script tags, event handlers, etc.) before use.

No code change is planned. If the threat model changes to include untrusted filesystem mounts, consider loading templates into memory and re-validating after read.

---

### AR-4: Go String Immutability Prevents Complete Secret Zeroing

**Severity:** Medium (platform limitation) | **Source:** M-13/M-14

Secret files are overwritten with zeros and deleted after reading (`internal/config/secrets.go`). However, Go's immutable `string` type means that `ZeroString()` can only clear the slice header -- the original bytes survive in heap memory until garbage collected. On copy-on-write filesystems (ZFS, Docker overlayfs), file overwriting may not erase the original blocks.

**Why this is accepted:**

- **Go language limitation:** There is no safe way to zero an immutable Go string's backing memory without `unsafe`. Using `unsafe` introduces memory corruption risk that outweighs the zeroing benefit.
- **[]byte where possible:** All secret material that can be represented as `[]byte` (master key, HMAC secret, pepper) uses `ZeroBytes()` for explicit zeroing.
- **Process-scoped lifetime:** Secrets persist only for the lifetime of the process. Pod restarts (Kubernetes liveness/readiness probes) clear all process memory.
- **File zeroing is defense-in-depth:** The file overwrite + delete still protects against casual filesystem inspection. The CoW limitation requires snapshot-level access, which implies infrastructure compromise.

No code change is planned. This is a fundamental Go runtime constraint.

---

### AR-5: User Roles in an Access Token Are a Snapshot, and the Role Catalog Fails Open

**Severity:** Medium (architectural decision) | **Source:** M-6, revised for the 2026-08-09 RBAC work

Vault42 runs two independent authorization planes. This risk covers the user plane only; the
admin plane is described below because the two are routinely confused.

**User plane (JWT roles).** This risk covers the three end-user issuance paths: login, refresh
and MFA completion. Any other issuance path enforces its own configured role allow-list rather
than inheriting this behaviour.

Roles are read from the user row at token issuance and passed through
`AuthService.effectiveRoles`, which is called from all three paths in
`internal/service/auth.go`. It strips the admin-reserved names `admin` and `super_admin`
(`seed.ReservedAdminRoles`, applied by `seed.FilterUserRoles`), then keeps only roles present
in the `auth.app_roles` catalog (`RoleCatalog.Filter`), falling back to `["user"]` when nothing
survives. The resulting list is embedded in the access token
(`TokenService.IssueTokenPair`). Nothing re-reads the database on a per-request basis.

Two consequences are accepted:

1. **Revocation is not immediate.** A role removed from a user row stays effective in any
   already-issued access token until that token expires.
2. **The catalog cache fails open.** `RoleCatalog` refreshes on a TTL (default 60 s) and, when
   the catalog has never loaded and a refresh errors, returns its input unchanged
   (`RoleCatalog.current` and `RoleCatalog.Filter`, `internal/service/role_catalog.go`).

**Why this is accepted:**

- **Bounded staleness.** Access tokens live 5-15 minutes, and refresh re-reads the user row on
  every rotation (`AuthService.Refresh`), which also revokes the whole family if the account has
  since been deleted, banned or disabled. The window is one access-token TTL, not the refresh
  family lifetime.
- **Privilege escalation is still closed on the fail-open path.** The catalog filter narrows;
  it never adds. `seed.FilterUserRoles` runs upstream of it and is unconditional, so a catalog
  outage cannot let `admin` or `super_admin` reach a JWT even if a row is poked directly by SQL.
- **The alternative is a database round-trip per request** on the hot authenticated path, for a
  claim that is advisory to relying parties rather than load-bearing inside Vault42: no vault42
  route authorizes on `claims.Roles`. Machine authorization uses scopes
  (`middleware.RequireScope`, `internal/middleware/auth.go`), not roles.
- **Operators who need immediate revocation have a mechanism.** Locking the account
  (`POST /admin/users/{id}/lock`) revokes every refresh token the user holds and makes
  `Refresh` reject the account for as long as the lock stands, so exposure is capped at the
  remaining access-token TTL. Ban, disable and delete are gated the same way.

  Until 1.0.0 this paragraph was false in the way that matters. Locking wrote `locked_until`
  and revoked nothing, and `Refresh` never read the column, so an attacker holding a refresh
  token kept rotating it and the session survived for the absolute session lifetime (720h by
  default, unbounded when `VAULT_MAX_SESSION_LIFETIME` is 0). Locking stopped only the logins
  that had not happened yet, which is the opposite of what a containment action is for.
  `TestAtk_AdminLockDoesNotStopRefresh` and `TestAtk_LockedAccountRefreshChainSurvives` hold
  the fix down.

  Note that `POST /admin/sessions/revoke-all` is **global**: it revokes every user's sessions,
  not one user's. It is a break-glass control, not the per-user tool this paragraph used to
  imply.

**Not covered by this risk: the admin plane.** The admin gateway does not use JWT roles. Its
authorization model is `internal/rbac`: three strictly hierarchical `Role` constants and 29
`Permission` constants, hardcoded in Go so a SQL injection cannot mint one. 37 admin endpoints
are permission-gated in `adminapi.NewRouter` (`internal/adminapi/router.go`), including a
role-catalog management API (`GET`/`POST`/`DELETE /admin/roles`), admin user management
(`/admin/admins`) and an HTML dashboard. Every check re-reads the admin row from the database
inside the request (`adminapi.SessionAuth`) before `adminapi.RBACCheck` evaluates it, so an
admin role change or revocation takes effect on the next request. See
[Admin Gateway](admin-gateway.md#rbac-model).

No code change is planned for 1.0.0.

---

### AR-6: Admin Gateway Session Timing Oracle

**Severity:** Low (mitigated) | **Source:** Admin gateway security review C2

When `GetByTokenHash` returns nil (invalid session), the `SessionAuth` middleware returns immediately. Valid sessions continue with a DB lookup for the admin user, creating a measurable timing difference.

**Why this is accepted:**

- **mTLS + loopback-only:** An attacker must be on the same node with a valid client certificate signed by the dedicated admin CA.
- **SSH tunnel latency:** The gateway is accessed via SSH tunnel, adding network jitter that dwarfs sub-millisecond timing differences.
- **DB query dominates:** The `GetByTokenHash` call itself always performs a DB query (even for misses), which dominates the timing regardless of hit/miss.
- **6-layer enforcement:** Exploiting this requires bypassing hostNetwork, NetworkPolicy, mTLS, LocalOnly middleware, and RejectProxyHeaders -- all before timing becomes relevant.

---

### AR-7: Admin Session Token in sessionStorage

**Severity:** Medium (mitigated) | **Source:** Admin gateway security review M1

Admin session tokens are stored in `sessionStorage`, accessible to any JavaScript in the same origin.

**Why this is accepted:**

- **Strong CSP:** `script-src 'self'` prevents inline scripts and external script loading. XSS would require compromising the go:embed binary.
- **No user-generated content:** The admin dashboard renders server-side data only. No user-controlled HTML is injected.
- **sessionStorage clears on tab close:** Tokens do not persist across browser sessions.
- **HttpOnly cookies incompatible:** The dashboard uses `fetch` with `Authorization: Bearer` headers. HttpOnly cookies cannot be read by JavaScript for this pattern.
- **6-layer enforcement:** mTLS + loopback-only means XSS exploitation requires node-level access.

---

### AR-8: Admin Login Rate Limit Is Global Per-IP

**Severity:** Low (by design) | **Source:** Admin gateway security review M2

`LoginRateLimit` is IP-based. Since the gateway is loopback-only, all connections share `127.0.0.1`, making the rate limit effectively global (10 attempts/minute for all users combined).

**Why this is accepted:**

- **More restrictive, not less:** A single attacker's attempts consume the global budget, protecting all accounts.
- **Per-account lockout:** The 5-attempt account lockout provides the per-account defense layer independently.
- **Anti-enumeration:** Per-username rate limiting would leak username existence through rate-limit response differences.
- **Two keys max:** Loopback-only means the map contains at most `127.0.0.1` and `::1` -- no memory growth concern.

---

### AR-9: Admin Client Certificate CN Not Validated

**Severity:** Low (by design) | **Source:** Admin gateway security review M3

TLS config uses `RequireAndVerifyClientCert` with the CA pool but does not check the client certificate's Common Name or SANs. Any cert signed by the CA is accepted.

**Why this is accepted:**

- **Single-purpose CA:** The CA is generated by `generate-admin-certs.sh` exclusively for admin gateway use. Only explicitly generated client certs are signed by this CA.
- **CA is the trust boundary:** Certificate revocation and issuance are controlled by the CA operator, not by CN matching.
- **Multi-operator flexibility:** CN validation would complicate setups with multiple operators, each needing their own client cert.

---

### AR-10: KMS Unwrap Oracle Authorizes on a Bearer Token That Is Not Sender-Constrained

**Severity:** Low (by design) | **Source:** KMS unwrap review (0.8.6), revised for 1.0.0

`POST /kms/unwrap` is a key-release endpoint. It authorizes on a plain Bearer
client-credential token carrying the `kms:unwrap` scope, so a captured token could be replayed
within its (short) TTL to re-release the plaintext.

**DPoP does not currently close this.** Sender-constraining a token requires the access token
to carry a `cnf.jkt` confirmation claim (RFC 9449 §6.1), and no vault42 issuance path sets one
(see the `middleware.DPoP` doc comment, `internal/middleware/dpop.go`). With
`VAULT_DPOP_ENABLED=true` a presented proof is
still checked for structure, method, URI, `iat` freshness, access-token hash and JTI single-use,
but it is never compared against a thumbprint the token committed to, and a request presenting
no proof at all is passed through. Treat `VAULT_DPOP_ENABLED` as experimental. Do not count it
as a mitigation for this risk.

**Why this is accepted:**

- **Defense in depth already applied:** the endpoint is scope-gated (`kms:unwrap`), per-IP rate
  limited with fail-closed behaviour, mounted only when `KMS_ROOT_KEY_FILE` is set, and every
  attempt is synchronously audited.
- **Oracle-resistant by construction:** all post-authorization failures collapse to one opaque
  `400 unwrap_failed`, so the endpoint leaks only success vs failure, never why an envelope was
  rejected, and never the KEK.
- **Replay costs the attacker nothing new:** an attacker who can capture the token can also
  capture the request body, and unwrapping the same envelope twice yields the same plaintext.
  The exposure is the plaintext already released to the legitimate caller, bounded by the
  access-token TTL, TLS and the per-IP limit.
- **The KEK never leaves the process:** unwrap releases a wrapped data key, not the
  Key-Encryption-Key, and per-kid KEKs are HKDF-derived from a root secret that is never
  returned in or derivable from any response (see the `internal/kms` package doc).

---

### AR-11: Unmaintained `openpgp` Package Inside the `x/crypto` Module

**Severity:** Informational | **Source:** govulncheck GO-2026-5932 (0.9.6 release scan)

govulncheck flags `golang.org/x/crypto@v0.53.0` because the module contains `golang.org/x/crypto/openpgp`, which upstream declares unmaintained and unsafe by design. The advisory has no fixed version (`Fixed in: N/A`) -- the package is frozen, not patched, so the finding persists for every version of the module.

**Why this is accepted:**

- **Never called:** Vault42 imports only `argon2` and `hkdf` from `x/crypto`. govulncheck symbol analysis confirms 0 vulnerabilities in called code; the advisory is module-level only.
- **Unfixable by upgrade:** No `x/crypto` release removes the package, so bumping the dependency can never clear the finding.
- **Guarded against regression:** `openpgp` would have to be imported deliberately for the risk to materialize; the minimal-dependency rule (three direct deps, reviewed in every PR) is the control.

---

### AR-12: `vault_app` Can Still Purge Audit Entries Past the Retention Horizon

**Severity:** Low | **Source:** privilege review of `audit.cleanup_old_entries()` (0.9.8)

The audit log is append-only at the database level: a trigger refuses DELETE and UPDATE, and 001 revokes both from `vault_app`. The retention sweeper is the one sanctioned exception, and it runs in-process in `cmd/vault` under `vault_app` -- so that role must hold EXECUTE on `audit.cleanup_old_entries()`, a SECURITY DEFINER function owned by `vault_mig` that disables the trigger to delete. Anything that reaches the database as `vault_app` can therefore still remove entries older than the horizon it passes.

**Why this is accepted:**

- **Bounded, not unbounded.** Migration 012 makes the function refuse any horizon shorter than a day (the setting is configured in whole days), so the freshest entries -- including the record of the intrusion doing the calling -- cannot be destroyed. Before 012 a zero or negative interval wiped the entire table.
- **No wider than it has to be.** EXECUTE is revoked from `PUBLIC` and granted to `vault_app` alone. `vault_admin` and every other role in the cluster are refused, and the function carries an explicit `search_path` (CVE-2018-1058).
- **The alternative costs more than it buys.** Closing it fully means moving the sweeper out of the API process into a separately-credentialed job, which trades one narrow purge path for another deployment unit, another secret and another failure mode.
- **Guarded against regression.** `TestAuditPurgeFunctionPrivileges` connects as the real roles with the real grants and asserts the whole model: PUBLIC denied, `vault_admin` denied, degenerate horizons rejected with the log intact, and the trigger re-enabled after a legitimate sweep.

---

### AR-13: A Rotated-Out RSA Signing Key Is Not Actually Erased From Memory

**Severity:** Low | **Source:** empirical check of `zeroPrivateKey` against the Go 1.26 toolchain (1.0.0)

Key rotation calls `TokenService.UpdateSigningKey`, which clears the exported secret fields of the key it replaces: `D`, the primes, and the three CRT values. That reads as an erase, and until 1.0.0 the surrounding comment described it as one.

It is not one. Since Go 1.24 `crypto/rsa` derives an unexported representation of a private key on first use and signs from that, so the fields cleared here are copies the signing path no longer consults. A key that has been through `zeroPrivateKey` still signs, and the signature is byte for byte identical to the one it produced before the clear. The secret components remain resident in memory the process cannot address.

**Why this is accepted:**

- **It is not reachable from outside the standard library.** The cached representation is unexported and has no accessor. There is no `unsafe`-free way to clear it, and reaching into it with `unsafe` would risk corrupting live key state on every rotation in order to erase a copy an attacker can only read with the process memory access that already loses them the active key outright.
- **The threat it would defend against already implies process compromise.** An adversary able to read heap memory can read the active key, which is by definition present, so erasing the retired one changes the outcome only for a key that has already been rotated away from.
- **The clear still runs, and still helps.** Zeroing the reachable fields costs nothing, removes the copies a heap dump surfaces most readily, and becomes a real control again unmodified the day the standard library stops caching.
- **The limit is executable, not documentary.** `TestZeroPrivateKeyLeavesTheKeyUsable` asserts that a wiped key still produces the same valid signature. If a future toolchain makes the wipe effective, that test fails, and this entry is deleted rather than quietly outliving its truth.

Related: AR-4 covers the same class of limitation for string-typed secrets, and AR-25 in `docs/COMPLIANCE.md` covers the decrypted signing-key PEM buffer in the keystore.

---

### AR-14: The Admin Role-Escalation Triggers Are Not a Boundary Against SQL That Reaches the Database

**Severity:** Low | **Source:** red-team review of `auth.deny_role_escalation` (1.0.0)

`auth.admin_users` carries two triggers. `auth.deny_role_escalation` (BEFORE UPDATE, migration 001) refuses to raise an existing admin's role. `auth.deny_role_escalation_on_insert` (BEFORE INSERT, migration 016) refuses to create an admin outranking the creator named in `created_by`, and refuses an admin with no creator at all once the first one exists.

Until 016 there was no INSERT half, and the gap was not theoretical: `vault_admin` holds full INSERT on the table, so a statement running as that role could write a brand-new `super_admin` row, with a password hash of its choosing, next to the row the UPDATE trigger was watching. Migration 001 advertised the UPDATE trigger as the injection backstop -- "even if SQL injection reaches the DB, a lower-ranked admin cannot promote themselves to a higher rank" -- and `docs/admin-gateway.md` repeated it. That claim has been removed from both.

**Why the residue is accepted:**

- **The INSERT ceiling is forgeable and says so.** The UPDATE trigger compares against `OLD.role`, which comes from the row, so a caller cannot choose it. On an INSERT every value comes from the statement, and `vault_admin` also holds SELECT on `auth.admin_users`, so a caller can read a genuine `super_admin` id and name it in `created_by`. The guard raises the cost from one statement to two. It does not stop anyone.
- **A real ceiling needs credentials the deployment does not have.** Making this a boundary means one database login per admin rank, so the rank is carried by the connection rather than by the statement. Every admin tier shares the single `vault_admin` login by design, and splitting it means three secrets, three pools and a rank-to-credential mapping in the gateway -- a larger attack surface than the one it closes.
- **No injection sink is reachable.** Every admin-plane query is parameterised (`internal/adminapi`, `internal/repository/postgres`), and that, not the trigger, is what actually closes injection here. `tests/attack/sql_injection_test.go` and the parameterisation of the admin repositories are the controls under review.
- **What the guard does buy is worth keeping.** It enforces a stateable invariant -- no admin row outranks its recorded creator, and no admin row after the first lacks one -- so an RBAC regression in Go that let a viewer-ranked session mint a `super_admin` fails at the database instead of shipping quietly, and existing rows can be audited against it.
- **Guarded against regression.** `TestAdminEscalationTriggerIgnoresInsert` connects as the real `vault_admin` role with the real grants and asserts all four paths: UPDATE promotion, `ON CONFLICT DO UPDATE`, `session_replication_role`, and the plain INSERT that used to succeed.

---

### AR-15: What Keeps a Forged Signing Key Out of JWKS Is the Master Key, Not the Grant

**Severity:** Low | **Source:** red-team review of `KeyStore.Refresh` and `auth.signing_keys` (post-1.0.0)

Migration 001 grants `vault_app` SELECT, INSERT and UPDATE on `auth.signing_keys`, because the vault rotates its own keys. Until this change, `Refresh` published every loaded row's `public_key` and decrypted `private_key` only when the row's status was `active`, so a row the process could not open was published as a verification key anyway. Anyone able to issue SQL as `vault_app` could INSERT a key of their own as `retired` with a NULL `expires_at`, wait one `VAULT_KEY_REFRESH_INTERVAL`, and then mint tokens for any subject that validated here and in every service polling this issuer. Revocation had the matching hole: the guard that stopped a revoked kid from coming back was a `WHERE` clause inside `Import`'s upsert, which a raw UPDATE never runs.

Both are closed. `Refresh` now opens every row before publishing any of it, and publishes only a row whose `private_key` decrypts under the master key with the kid as AAD and whose `public_key` column is the public half of what decrypted. Migration 017 freezes revoked rows against UPDATE and DELETE. What remains is worth stating exactly, because the grant itself has not moved.

**Why the residue is accepted:**

- **The control is a key, not a privilege.** A forged row is rejected because the AES-256-GCM tag over the kid does not verify, which needs the master key, not a database privilege. That is the right place for it: the same rule holds for every role, for the migration role, and for anything with direct psql access, none of which a grant on one table can constrain.
- **Denial of service through this table is still available, and cheap.** SQL as `vault_app` can corrupt the active row and freeze every pod's key set at whatever it last loaded, or corrupt retired rows and drop their kids from JWKS, invalidating tokens still in flight. Failing the whole refresh on a bad non-active row instead of skipping it would make this worse rather than better: one hostile row would then break the next pod to boot, since `EnsureKey` will not start without a successful refresh. Availability of the key set is not defended here; forgery is.
- **The trigger is not a boundary against the owner.** `ALTER TABLE ... DISABLE TRIGGER`, `session_replication_role = replica` and TRUNCATE all bypass row triggers, and the migration role holds them. 017 closes the path available to the two least-privilege roles the services connect as, which is the threat model 001 states for this table. The same limitation is argued in AR-14 for the admin tables.
- **Opening every row widens AR-13 slightly.** A retired key's private material is now briefly resident on each refresh instead of never. The decrypted PEM buffer is wiped; the parsed key cannot be, for the reason AR-13 gives. The exposure needs heap access to a process that already holds the active key.
- **Guarded against regression.** `TestSigningKeyInjectionAsVaultApp` connects as the real `vault_app` role with the real grants and runs all three writes: the forged INSERT, the `public_key` swap by UPDATE, and the un-revoking UPDATE, checking each against both the published key set and a token forged under it. `TestSigningKeyRevocationIsTerminalInTheDatabase` pins 017's trigger and, as importantly, that rotation, revocation and cleanup still work.

---

### AR-16: A `mint:token` Holder Can Assert Any Subject the Estate Honors

**Severity:** High (by design, off by default) | **Source:** 1.0.0 review of `POST /mint`

`POST /mint` signs an assertion about a subject vault42 never authenticated. Nothing binds a
calling client to the subjects it is allowed to name. Any client holding `mint:token` can assert
any subject, and the token it gets back is signed with the same key, published under the same
JWKS, and shaped like a token issued after a real login. In an estate where more than one
tenant's service holds a mint credential, one tenant's minting client can speak as any of
another tenant's subjects to every relying party that accepts a vault42-issued token.

That is what the endpoint is for. It is not a bug in it, and 1.0.0 ships no client-to-subject
policy. What follows is the exact set of conditions under which the exposure is reachable, so an
operator can decide whether to enable it.

**All four must hold:**

1. `VAULT_MINT_ENABLED=true`, and `VAULT_MINT_AUDIENCE` set to a value other than
   `VAULT_ORIGIN`. `POST /mint` is not mounted otherwise, and the server refuses to start if the
   two are equal. Both default to off and unset.
2. A service client record carries `mint:token` in its scope list, granted through `POST
   /admin/clients` by a `super_admin` and recorded in an `admin:client_create` audit row. Since
   migration 023 that is the only writer: the seed file and `vault add-client` run under
   `vault_app`, which the database now refuses for any capability scope (AR-17). Nothing grants
   it implicitly, and no user-token issuance path can produce it.
3. The caller holds that client's secret and exchanges it at `POST /client/token`. A user
   session cannot reach the route: the handler refuses any token with no `client_id` claim,
   ahead of the scope check.
4. A relying party accepts tokens carrying `aud: VAULT_MINT_AUDIENCE` and does not reject
   `token_type: "mint"`.

Condition 4 is where the exposure lands, and vault42 cannot enforce it. Nothing in this service
constrains what a relying party chooses to trust. An RP that checks the signature and the issuer
and stops there treats a minted assertion and a real login as the same fact.

**What a mint holder gets, and what it does not:**

- **Any subject, unrestricted.** The subject is caller-supplied, is never looked up, and does
  not have to exist in vault42. The only constraint is a charset and length limit
  (`^[A-Za-z0-9][A-Za-z0-9._@-]*$`, 128 bytes) that keeps control characters out of a signed
  claim and an audit row. It is not an authorization check.
- **Not vault42 itself.** A minted token carries `token_type: "mint"`, which vault42's own auth
  middleware rejects, and an audience that is not vault42's own; either alone stops it at the
  door. Minted roles and scopes come from allow-lists that are empty by default, and
  `mint:token`, `kms:unwrap`, the `svcdoc:` scopes and the admin scopes can never be minted. The
  blast radius is the downstream estate, not this service.
- **Nothing revocable.** vault42 keeps no record of a minted token beyond the audit event.
  Rotating or deleting the client credential does not invalidate assertions already signed. The
  only bound is the token lifetime: 5 minutes by default, 15 minutes at the hard ceiling.

**Why this is accepted for 1.0.0:**

- **Per-client subject policy is a feature, not a fix.** Constraining which subjects a client may
  assert needs a schema for the binding, an admin surface to manage it, and a migration for
  existing clients. It is out of scope for 1.0.0, and no configuration knob approximates it,
  because a half-expressive one would read as a boundary without being one.
- **The endpoint has no alternative shape.** Eleven legacy services hold foreign-key copies of
  the platform's own user ids, so the token subject has to remain that id rather than a
  vault42-native one. The alternative is rewriting every one of those tables.
- **Reaching it takes four deliberate acts.** None of the conditions above is a default, and a
  stock deployment has no mint at all.
- **Use is attributable.** Every mint, accepted or refused, writes a `token_minted` audit event
  naming the asserted subject, the calling client and the jti. Since 1.0.0 the token carries the
  same attribution itself, in a `minted_by` claim holding the minting client's id, so a relying
  party can attribute an assertion without reading vault42's database, which it cannot. The
  claim is deliberately not named `client_id`: that claim marks an authenticated service caller
  and is read as one by the service document store.
- **Guarded against regression.** `TestMintHandler_AMintedTokenNamesTheClientThatRequestedIt`
  and `TestMintHandler_AMintedTokenCarriesNoClientIDClaim` pin both halves against the token on
  the wire, and `tests/spec/mint_claim_collision_test.go` fails the build if the minted claim set
  ever sets `ClientID` or drops `MintedBy`.

**Revisit when** a second tenant's service is granted `mint:token` in the same deployment. At
that point the missing binding stops being an accepted risk and becomes a defect.

---

### AR-17: What Stops `vault_app` Issuing Itself a Capability Credential Is a Trigger, Not the Grant

**Severity:** Low | **Source:** red-team review of `auth.clients` and the seed path (post-1.0.0)

Migration 001 grants `vault_app` SELECT and INSERT on `auth.clients` so `cmd/vault` can seed
clients at startup, and `scopes` is a plain `TEXT[]` with no constraint and no catalog. Until
this change the grant therefore read "may write any authorization this service recognizes": a
statement reaching the database as the application role could insert a client row carrying
`mint:token` and `kms:unwrap` with a `secret_hash` it chose, then present that secret at `POST
/client/token` and receive a token carrying the scopes verbatim. `RequireScope` compares whole
strings, so the token opened `POST /mint` and `POST /kms/unwrap`. That is the step from "can
write application tables" to "can assert any subject to every relying party in the estate, and
can open every envelope the KMS oracle will decrypt", and it is also the step that turns a
defect with no network reach into a bearer credential usable from outside the database.

`VAULT_MINT_SCOPES` never covered this. That allow-list and `service.mintDeniedScopes` behind it
bound what a *minted token* may carry; nothing read them on the way into a *client row*.

Migration 023 closes it with `clients_capability_scope_guard`, a `BEFORE INSERT OR UPDATE`
trigger that refuses any row whose `scopes` overlap `auth.capability_scopes()` unless the writer
holds `vault_admin`. `POST /admin/clients` is now the only writer of a privileged client, gated
on `clients:create` (`super_admin` only) and audited.

**Why the residue is accepted:**

- **The grant has not moved, and could not.** PostgreSQL has column-level INSERT, but the
  privilege is checked against the columns a statement *names*, not the values it writes.
  `ClientRepo.Create` lists `scopes` in every INSERT including the ordinary ones, so `REVOKE
  INSERT (scopes)` would refuse plain seeding too. Migration 015 could take `email` out of the
  statement before revoking the column; here the column is the point of the statement.
- **The guard has to ask who is writing.** Every other trigger in this tree states a rule about a
  row. This one cannot: a client row carrying `mint:token` is legitimate from the admin plane and
  an escalation from the application role, so the membership test on `vault_admin` is load-bearing
  and is the part to review if the role model ever changes.
- **It is not a boundary against the owner.** `ALTER TABLE ... DISABLE TRIGGER`,
  `session_replication_role = replica` and TRUNCATE all bypass row triggers, and the migration
  role holds them. Same limitation as AR-14 and AR-15, and the same threat model: the two
  least-privilege roles the services connect as.
- **Two copies of one list.** The capability scopes are named in Go and in SQL and neither can be
  derived from the other, so `tests/spec/capability_scope_parity_test.go` fails the build when
  they disagree, and a second test fails it when the migration spells a scope anywhere but inside
  `auth.capability_scopes()`.
- **A documented convenience is gone.** A `VAULT_SEED_FILE` or a `vault add-client` naming a
  capability scope now aborts. That is intended: a seed file names a capability and no authority
  for it, and the process reading it is the one this model treats as semi-hostile. The sibling
  commands show where client management already lived -- `vault revoke-client` and `vault
  rotate-client-secret` are UPDATE statements on a table `vault_app` has never held UPDATE on,
  so both have failed with 42501 in every deployment since 001.
- **Guarded against regression.**
  `TestVaultAppCannotGrantItselfACapabilityScopeThroughAClientRow` connects as the real
  `vault_app` and `vault_admin` roles with the real grants and asserts the whole model: ordinary
  seeding still works, each capability scope is refused, a capability scope hidden in a mixed list
  is refused, the admin plane can still create a privileged client, and UPDATE stays denied.

---

### AR-18: `vault_app` Can Still Release an Account Lock, and Owns Every Password Hash

**Severity:** Low | **Source:** red-team review of the `auth.users` account-state columns (post-1.0.0)

Migration 004 granted `vault_app` UPDATE on the account-state columns in one line, and 006 added
`import_pending`. Nobody asked which of those writes the running server makes. Until this change
the application role could ban or disable any account or every account, lift a ban, rewrite a
recorded ban reason, un-confirm a verified address, and put a claimed account back into
`import_pending`. None of those is a statement any code path issues.

Migration 024 splits them by whether a writer exists. `banned`, `ban_reason` and `disabled` have
none -- they are set once at INSERT by the import path, under `vault_admin` -- so the privilege is
revoked outright. `email_verified` and `import_pending` keep theirs, because `UserRepo.VerifyEmail`
and `UserRepo.ClearImportPending` are `vault_app`'s own statements, and
`users_account_state_transitions` narrows each to the direction its writer moves in.

**Why the residue is accepted:**

- **`locked_until` could not be narrowed without breaking a working command.** The intended rule
  was that `vault_app` may set a lock and may clear one only once it has expired. `vault
  lock-user` and `vault unlock-user` call `UserRepo.LockUntil` and `UserRepo.Unlock`, they live in
  `cmd/vault`, and `cmd/vault` opens its pool with `cfg.DatabaseURL("app")`, so releasing a live
  lock is something `vault_app` does on an operator's command. The database cannot tell that
  invocation from the web-facing process. Pointing the two subcommands at the admin DSN, or
  removing them in favour of `POST /admin/users/{id}/lock` and `/unlock`, which already do this
  under `vault_admin`, is a change in Go; the column can be narrowed after it.
- **Account takeover through this role is not closed and cannot be.** `vault_app` keeps `UPDATE
  (password_hash)` because password change and reset are its job, so anything reaching the
  database as that role can already authenticate as any account whose state permits login. What
  024 removes is the part password control does not reach: lifting a ban, which the account-state
  gate refuses before any credential is read, and mass denial of service, which no code path can
  perform at all.
- **It is not a boundary against the owner**, for the reasons AR-14 and AR-15 give.
- **Guarded against regression.** `TestVaultAppCannotFlipThePrivilegedAccountStateColumns`
  connects as the real roles with the real grants and asserts both halves: the refusals, and that
  email confirmation, import claiming, the import path's own ban and the lock/unlock pair all
  still work.

---

## Resolved Risks

### AR-2: GitHub OAuth2 Without PKCE (S256) -- RESOLVED

**Originally:** GitHub's OAuth2 implementation did not support PKCE, making S256 enforcement impossible for the GitHub provider.

**Resolution (July 2025):** GitHub added PKCE S256 support. Vault42 already sends `code_challenge` and `code_verifier` in the authorization flow (`internal/oauth2/github.go`). PKCE S256 is now enforced on all three OAuth2 providers (Google, GitHub, Facebook).
