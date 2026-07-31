# Vault42 -- Security Decisions & Accepted Risks

> Complements the [Security Review](security-review.md) and [Spec section 13](spec.md#13-security-mitigations).
> Documents deliberate security tradeoffs and platform limitations that have been reviewed and accepted.

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

### AR-5: User Roles Hardcoded to `["user"]` by Design

**Severity:** Medium (architectural decision) | **Source:** M-6

Token issuance always assigns `["user"]` roles without consulting the database. If roles were modified between refreshes, the stale role would persist until the refresh family expires.

**Why this is accepted:**

- **Single-tenant, no admin interface:** Vault42 is designed as a single-tenant authentication service. All users are self-service and equal. There is no admin UI, no role management API, and no privileged user class.
- **No RBAC consumers:** No endpoint in Vault42 checks for roles beyond the base `"user"` role. Adding dynamic role fetching would add complexity and a database round-trip with zero current benefit.
- **Short access token TTL:** Access tokens live 5-15 minutes. Even if roles changed, stale claims expire quickly.
- **v2 feature if needed:** If RBAC is required (multi-tenant, admin panel), it will be implemented as a full feature with DB schema, role management API, and token claim population. Tracked in `docs/TODO.md`.

No code change is planned for v1.

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

### AR-10: KMS Unwrap Oracle Accepts Plain-Bearer Tokens When DPoP Is Disabled

**Severity:** Low (by design) | **Source:** KMS unwrap review (0.8.6)

`POST /kms/unwrap` is a key-release endpoint. When `VAULT_DPOP_ENABLED=false`, it authorizes on a plain Bearer client-credential token carrying the `kms:unwrap` scope, so a captured token could be replayed within its (short) TTL to re-release the plaintext.

**Why this is accepted:**

- **DPoP closes it when enabled:** with `VAULT_DPOP_ENABLED=true` the handler is wrapped so a fresh, single-use DPoP proof is mandatory; a captured Bearer token plus body cannot be replayed. Deployments that hold DPoP-bound kms tokens should enable it.
- **Defense in depth already applied:** the endpoint is scope-gated (`kms:unwrap`), per-IP rate limited with fail-closed behaviour, mounted only when `KMS_ROOT_KEY_FILE` is set, and every attempt is synchronously audited.
- **Oracle-resistant by construction:** all post-authorization failures collapse to one opaque `400 unwrap_failed`, so the endpoint leaks only success vs failure, never why an envelope was rejected, and never the KEK.
- **Backward compatibility:** the plain-Bearer path keeps clients that cannot yet present DPoP proofs (e.g. the initial life42 kms client) working; the trade-off is documented at the mount site in `internal/server/server.go`.

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

## Resolved Risks

### AR-2: GitHub OAuth2 Without PKCE (S256) -- RESOLVED

**Originally:** GitHub's OAuth2 implementation did not support PKCE, making S256 enforcement impossible for the GitHub provider.

**Resolution (July 2025):** GitHub added PKCE S256 support. Vault42 already sends `code_challenge` and `code_verifier` in the authorization flow (`internal/oauth2/github.go`). PKCE S256 is now enforced on all three OAuth2 providers (Google, GitHub, Facebook).
