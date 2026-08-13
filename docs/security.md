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

## Resolved Risks

### AR-2: GitHub OAuth2 Without PKCE (S256) -- RESOLVED

**Originally:** GitHub's OAuth2 implementation did not support PKCE, making S256 enforcement impossible for the GitHub provider.

**Resolution (July 2025):** GitHub added PKCE S256 support. Vault42 already sends `code_challenge` and `code_verifier` in the authorization flow (`internal/oauth2/github.go`). PKCE S256 is now enforced on all three OAuth2 providers (Google, GitHub, Facebook).
