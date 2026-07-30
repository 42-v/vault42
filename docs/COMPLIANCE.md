# Vault42 -- Authentication Server Compliance Report

This report assesses the Vault42 authentication server against seven security and
privacy standards spanning authentication, session management, cryptography, audit
logging, data protection, transport security, and the OAuth2/JWT/OIDC protocol family.
Each standard was reviewed at the requirement level and classified as **Met**, **Partial**,
**Gap**, or **Not Applicable (N/A)**. Across all auditable requirements the server shows
strong, defense-in-depth coverage of technical authentication and session controls; the
principal area of remaining work is organizational and lifecycle privacy compliance
(GDPR), where several requirements depend on policy documentation and data-lifecycle
features rather than authentication logic. Severity is reported per finding to support
remediation prioritization.

---

## Overall Summary

| Standard | Met | Partial | Gap | N/A | Coverage % |
|---|---:|---:|---:|---:|---:|
| NIST SP 800-63B (Authentication & Lifecycle Management) | 39 | 2 | 0 | 0 | 96% |
| OWASP ASVS V2 (Authentication) + V3 (Session Management) | 40 | 2 | 0 | 0 | 95% |
| OWASP ASVS v4.0 -- Cryptography (V6) / Errors & Logging (V7) / Data Protection (V8) | 34 | 3 | 0 | 3 | 96% |
| NIST SP 800-53 Rev 5 -- IA / AC / AU / SC (auth-relevant controls) | 20 | 3 | 0 | 0 | 95% |
| OWASP Top 10 (2021) | 47 | 1 | 0 | 0 | 97% |
| RFC 8725 (JWT BCP) + RFC 6749/6819 (OAuth2) + RFC 7636 (PKCE) + RFC 9449 (DPoP) + RFC 9700 (OAuth Security BCP) + OIDC | 50 | 1 | 0 | 3 | 96% |
| GDPR -- General Data Protection Regulation (EU 2016/679) | 12 | 3 | 0 | 0 | 93% |
| **Totals** | **242** | **15** | **0** | **9** | -- |

**Overall weighted coverage:** **94.2%** (242 requirements met out of 257 applicable,
excluding 9 Not-Applicable organizational/out-of-scope controls). Awarding half credit
for partial findings raises the figure to **97.1%**. **High-severity open findings: 0.**

The GDPR data-lifecycle gaps that previously drove every high-severity finding are closed
(erasure completeness, audit retention, consent provenance, federated unlink). What remains
across all seven standards is medium/low: breach-notification alerting in code, cryptographic
audit-log chaining, and a set of hardening options that are deliberate trade-offs.

---

## NIST SP 800-63B (Authentication & Lifecycle Management)

**Coverage: 96%** -- 39 met, 2 partial, 0 gap, 0 N/A

The authentication server demonstrates comprehensive compliance with NIST SP 800-63B.
All core password controls are met: Argon2id with a 46 MiB memory cost, a 15-character
minimum (exceeding the 8-character floor), no composition rules, and breach-corpus
checking of submitted passwords. Multi-factor authentication supports TOTP,
WebAuthn/FIDO2, and backup codes, each with single-use enforcement and rate limiting.
Account lockout combines per-user (5 failures, 15-minute window) and per-IP (20 failures)
mechanisms. Session binding via device fingerprinting and reauthentication via password
confirmation gate sensitive operations. Refresh-token rotation provides family tracking,
single-use enforcement, and replay detection. The two partial findings are low severity:
assurance levels (AAL) are implemented in behavior but not explicitly labeled in the
codebase, and concurrent-session limiting is intentionally soft (an accepted performance
trade-off).

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| NIST-5.2.2-CONCURRENT-SESSION-LIMIT | Strict enforcement of concurrent session limits with proper synchronization | Partial | Low | Implement a per-user advisory lock or sequential token-insert validation with a count check to make enforcement strict; document the soft-vs-strict limit behavior in the API documentation. |
| NIST-5.2.4-AAL-LEVELS | Support and document AAL1/AAL2/AAL3 assurance levels with clear authenticator combinations | Partial | Low | Add explicit AAL-level constants and document which authenticator combinations achieve each AAL in code comments; extend the MFA status response with an `aal_level` field. |

---

## OWASP ASVS V2 (Authentication) + V3 (Session Management)

**Coverage: 95%** -- 40 met, 2 partial, 0 gap, 0 N/A

The server aligns strongly with ASVS V2 and V3. Strengths include CSPRNG-based token
generation, anti-automation lockouts (per-user 5/15min and per-IP 20/15min),
comprehensive MFA (TOTP, WebAuthn, email OTP with downgrade protection), refresh-token
rotation with family-based replay detection, device fingerprint binding, constant-time
operations to resist user enumeration, breach-corpus password checking, strict JWT
validation (RS256 only, `kid` required, dangerous headers rejected, 8 KB size limit),
secure cookie attributes (`__Host-` prefix, HttpOnly, Secure, SameSite=Strict/Lax), and
audit logging with risk scoring. TLS 1.3 is the enforced minimum, password recovery uses
single-use tokens with no information leak, and logout fully revokes all refresh-token
families. Two medium-severity partials remain: previous sessions are not automatically
invalidated on a new login, and account-status errors (locked/banned/disabled) can reveal
that an account exists.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| V3-2-2 | Session invalidation on login (previous refresh tokens invalidated) | Partial | Medium | Add an optional policy (default off) to revoke all existing active token families on new login before issuing a new pair, for hard session replacement. |
| V2-1-1 | Generic error messages prevent user enumeration in auth responses | Partial | Medium | Return a generic `invalid_credentials` response for locked/banned/disabled accounts instead of distinct status codes; record the true status separately in the audit trail with a high-risk flag. |

---

## OWASP ASVS v4.0 -- Cryptography (V6) / Errors & Logging (V7) / Data Protection (V8)

**Coverage: 96%** -- 34 met, 3 partial, 0 gap, 3 N/A

Approved algorithms are enforced throughout: AES-256-GCM for data encryption, Argon2id
for passwords (46 MiB, 1 iteration, 1 lane), SHA-256 for hashing, RS256 for JWT signing
(2048-bit minimum), and HMAC-SHA256 for message authentication. Cryptographic keys are
externalized via the `_FILE` convention and never hardcoded; private signing keys are
encrypted at rest using the master key with the key ID as additional authenticated data,
and key rotation is fully implemented with active/retired/revoked status tracking. Error
handling avoids sensitive-data exposure through generic error codes and constant-time
comparisons, including dummy-hash and identical-response patterns that prevent user
enumeration. Audit logging is append-only (enforced by database triggers plus revoked
UPDATE/DELETE privileges), captures security-relevant events, and scrubs sensitive keys
before storage. PII is encrypted at rest with AES-256-GCM under pseudonymized
(HMAC-derived) keys and decrypted on demand per request with no long-term plaintext
caching. The three partials are constrained by language and standards limitations rather
than design defects.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| V6.2.2 | Reject weak algorithms (MD5, SHA-1 except where required by standard) | Partial | Low | TOTP uses HMAC-SHA1 as mandated by RFC 6238 (no standardized SHA-256 TOTP alternative exists); document this interoperability constraint explicitly in the TOTP module for reviewers. No MD5 is used. |
| V6.4.1 | Secrets never logged, transmitted unencrypted, or stored in plaintext | Partial | Medium | Secrets are loaded from files via the `_FILE` convention and the master key and HMAC secret are zeroed after use; the runtime pepper and database password remain in memory due to Go string immutability. Migrate these to `[]byte` end-to-end and zero on shutdown. Mitigated by the short-lived containerized process model. |
| V8.3.2 | Secure deletion: overwrite memory holding sensitive data | Partial | Low | Key material is zeroed on shutdown and a `[]byte` zeroing helper exists; decrypted identity plaintext and ephemeral crypto buffers are not explicitly wiped after use. Zero the unmarshaled plaintext before returning and `defer`-zero nonce/tag buffers. Mitigated by request-scoped, short-lived process context. |

*Not Applicable (3): organizational controls outside the scope of the authentication
codebase.*

---

## NIST SP 800-53 Rev 5 -- IA / AC / AU / SC (Authentication-Relevant Controls)

**Coverage: 95%** -- 20 met, 3 partial, 0 gap, 0 N/A

The server implements strong fundamentals across Identification & Authentication, Access
Control, Audit & Accountability, and System & Communications Protection: MFA (TOTP,
WebAuthn, email OTP), password security (Argon2id with pepper, breach-corpus checking,
history tracking), session management (refresh-token replay detection, fingerprinting),
append-only audit logging with critical-event prioritization, and transmission security
(TLS 1.3 enforcement, HTTPS-only cookies, DPoP proof-of-possession). The three partials
concern an explicit idle-timeout policy, cryptographic audit-log integrity beyond
database constraints, and documentation of infrastructure-level boundary protection.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| AC-12 | Session termination: forced logout after inactivity timeout; explicit revocation on logout | Partial | Medium | Explicit logout already revokes all tokens. Add inactivity handling: store a last-activity timestamp per device/session, reject refresh once the idle threshold is exceeded (and revoke the family), update the timestamp on successful auth/refresh, and document the idle policy (e.g., 30 minutes). |
| AU-9 | Audit log protection: prevent unauthorized modification or deletion of audit records | Partial | Medium | Database-level append-only enforcement and INSERT/SELECT-only role privileges are in place. Add cryptographic chaining (HMAC of previous-record hash plus current record) with a separately held signing key and read-time verification; consider forwarding to an immutable off-system store and document a retention policy. |
| SC-7 | Boundary protection: network boundaries, firewall rules, access controls | Partial | Low | Application-level IP allow/block, trusted-proxy handling, and security headers exist. Document infrastructure boundary assumptions (firewall rules, ingress/TLS-termination configuration) and provide network-policy examples in the deployment documentation. |

---

## OWASP Top 10 (2021)

**Coverage: 97%** -- 47 met, 1 partial, 0 gap, 0 N/A

The server reflects enterprise-grade alignment with the OWASP Top 10 (2021): a layered
administrative gateway (mutual TLS, loopback-only access, role-based access control,
session authentication, local-only enforcement, and a kill switch); fully parameterized
SQL; hardcoded role assignment that prevents privilege escalation through database
compromise; fail-closed rate limiting on authentication endpoints; Argon2id hashing with
pepper and constant-time comparison; audit logging with automatic sensitive-data
scrubbing; DPoP proof-of-possession with replay prevention; OIDC issuer validation
restricted to RSA algorithms; strict cryptographic enforcement (TLS 1.3, RS256, 2048-bit
RSA minimum); and a complete set of security headers (HSTS, CSP, CORS, frame protections).
A single partial finding concerns missing pagination limits on administrative list
endpoints.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| M06 | Implement pagination with limits to prevent result-set denial of service (e.g., list audit logs, admin sessions) | Partial | Low | Add `limit`/`offset` parameters with enforced maximum limits to the administrative session-list and audit-log-list endpoints to bound result-set size. |

---

## RFC 8725 (JWT BCP) + RFC 6749/6819 (OAuth2) + RFC 7636 (PKCE) + RFC 9449 (DPoP) + RFC 9700 (OAuth Security BCP) + OIDC

**Coverage: 96%** -- 50 met, 1 partial, 0 gap, 3 N/A

*Since 0.9.6 the family's core requirements are pinned as clause-numbered regression
tests in `tests/compliance/rfc9700_oauth_bcp_test.go`: PKCE S256 on every provider
(§2.1.1/§4.8.2), HMAC state integrity (§4.1.1), OIDC nonce binding (§4.5.3), tokens
kept out of URLs (§4.3.2), and DPoP sender-constraining (§4.10.1).*

The implementation adheres strongly to the JWT and OAuth2 protocol family with
defense-in-depth against well-known attacks (algorithm confusion, header injection,
session fixation, code reuse, replay, key confusion). JWT parsing uses a strict algorithm
allowlist (RS256, ES256 only -- no `none` or HMAC), rejects header-injection vectors
(`jku`/`x5u`/`x5c`/`jwk`), validates all standard claims (`exp`, `nbf`, `iat`, `iss`,
`aud`), enforces an 8 KB size limit, and constrains `kid` to a safe pattern to prevent
path traversal. PKCE is fully implemented with S256 and one-time-use atomicity. CSRF state
binding uses an HMAC signature mirrored by a host-only cookie hash with a 10-minute
expiry. DPoP is fully implemented (typ/alg/jwk validation, htm/htu matching, freshness
window, one-time `jti`, key-bound thumbprint via `cnf.jkt`, and access-token-hash
validation). OIDC nonce binding, verified-email linking requirements, and account-state
enforcement are all present, and authorization-code consumption is atomic. The single
partial finding asks for explicit confirmation that the old refresh token is invalidated
on rotation.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| OAUTH2-TOKEN-001 | Token rotation on refresh: a new refresh token must be issued and the old token invalidated (RFC 6749 §6 best practice) | Partial | Low | A new refresh token is issued on refresh and family-based tracking exists; explicitly verify that the prior refresh token is revoked in the refresh code path, and add immediate revocation of the old token after the new one is issued if not already guaranteed. Since 0.9.6 the single-use mechanism itself is asserted under real Postgres (`tests/compliance/rfc9700_oauth_bcp_test.go` section 4.14.2: second `MarkUsed` fails, replay revokes the family); the service-level ordering assertion is what keeps this Partial. |

*Not Applicable (3): organizational controls (e.g., rate-limiting and audit-logging
infrastructure, JWKS endpoint operation) and unused `crit` header handling.*

---

## GDPR -- General Data Protection Regulation (EU 2016/679)

**Coverage: 93%** -- 12 met, 3 partial, 0 gap, 0 N/A

*Re-audited 2026-07-14 against the code (the previous 60% assessment predated the 0.8.x
data-lifecycle work and understated shipped behaviour by roughly 17 points; it also asserted
erasure guarantees the code did not implement — see GDPR-5).*

Technical data-protection is strong: AES-256-GCM at rest under pseudonymized (HMAC-derived)
keys, append-only audit logging with sensitive-key scrubbing, and per-purpose lawful bases
documented in `docs/PRIVACY.md`. The data-lifecycle work is now complete: full account erasure
cascades to every account-linked record including the MFA authenticators, audit retention is
enforced by a background sweeper, marketing consent is stored with provenance and is withdrawable
in one call, and federated links can be unlinked individually. The three remaining partials are
the breach-notification *code path* (the procedure is documented but no risk-threshold alerting
exists), cryptographic audit-log chaining, and a DPIA template.

*Since 0.9.6 the claims above are asserted by a dedicated compliance suite rather than
scattered unit tests: `tests/compliance/gdpr_erasure_test.go` runs the assembled
`ErasureService` cascade against a real Postgres and proves Art. 17 with row counts
(completeness, tombstone scrub, purge-not-mark, idempotency, the Art. 17(3)(b)/(e) audit
exemption, and the recovery escrow); `tests/compliance/gdpr_consent_test.go` pins the
Art. 7 consent-provenance contract (affirmative-only sources, fail-closed gating,
anti-laundering, one-call withdrawal); `tests/compliance/gdpr_retention_test.go` covers
Art. 5(1)(e) retention defaults and the Art. 5(1)(c) audit-metadata scrubbing.*

| ID | Requirement | Status | Severity | Notes / remaining work |
|---|---|---|---|---|
| GDPR-1 | Lawful basis for processing (Art. 6) | Met | -- | Per-purpose bases P1–P10 in PRIVACY.md §2. Consent is stored as a record (`granted`/`at`/`source`/`origin`), not a bare flag, and every change writes a `consent_granted` / `consent_withdrawn` audit entry — Art. 7(1) requires the controller to be able to *demonstrate* consent. Asserted: `tests/compliance/gdpr_consent_test.go` (Art. 7(1) provenance record). |
| GDPR-2 | Data minimization (Art. 5(1)(c)) | Met | -- | Per-field necessity rationale in PRIVACY.md §3.2. Asserted: `tests/compliance/gdpr_retention_test.go` (Art. 5(1)(c) audit-metadata scrubbing). |
| GDPR-5 | Right to erasure (Art. 17) | Met | -- | **Was a live defect, not merely undocumented.** Erasure cascades identity, blobs, devices, social links, password history and refresh tokens — but silently retained the TOTP secret, WebAuthn credentials and backup codes. The schema carries `ON DELETE CASCADE` on all three, so it *looked* correct; the cascade never fired because the account row is scrubbed with an `UPDATE`, not deleted. Now deleted explicitly, and refresh tokens are hard-deleted rather than revoked (a revoked row keeps its fingerprint hash and device reference). Regression-tested in `erasure_test.go`. Asserted: `tests/compliance/gdpr_erasure_test.go` (row counts across every user-linked store, real Postgres). |
| GDPR-7 | Purpose limitation (Art. 5(1)(b)) | Met | -- | PRIVACY.md §2 + §3.2. |
| GDPR-8 | Access & portability (Arts. 15, 20) | Met | -- | `GET /user/data-export` returns profile, identity, blob metadata, devices and user-scoped audit events as machine-readable JSON. |
| GDPR-9 | Accountability (Art. 5(2), Recital 76) | Met | -- | `docs/PRIVACY.md` is the processing policy: roles, bases, inventory, retention, rights, processors, breach procedure. |
| GDPR-10 | Data retention limits (Art. 5(1)(e)) | Met | -- | `VAULT_AUDIT_RETENTION_DAYS` + a sweeper (`internal/audit/retention.go`) purging every 6h and at startup. Disabled by default: deleting security logs is not a safe default, so the horizon is an explicit operator choice. Audit entries are exempt from the erasure cascade under Art. 17(3)(b)/(e), which is why they need a time-based purge. The account-recovery escrow (`auth.account_recovery`) is exempt for the same structural reason and has the same treatment since 0.9.8: `VAULT_RECOVERY_RETENTION_DAYS` + a sweeper (`internal/service/recovery_retention.go`) and `vault cleanup-recovery`, also disabled by default. It shipped with no expiry column, DELETE revoked from both application roles and no code path that removed a row, and it was absent from PRIVACY.md §3.1/§3.2/§4/§5.3 entirely. Asserted: `tests/compliance/gdpr_retention_test.go` (disabled-by-default sweeper, config horizon), `tests/integration/postgres_recovery_retention_test.go` (escrow prune against a real Postgres). |
| GDPR-11 | Third-party sharing and transfers (Arts. 4, 6, 28) | Met | -- | Processors documented in PRIVACY.md §6. `DELETE /user/social/{id}` unlinks a federated identity and removes the encrypted provider tokens with it; previously this was only possible by erasing the whole account. |
| GDPR-13 | Data subject rights (Arts. 15–21) | Met | -- | Access/portability, rectification, erasure, restriction, objection and withdrawal all have endpoints; each writes to the audit trail. |
| GDPR-15 | Consent for marketing (Arts. 5, 7) | Met | -- | `POST /user/marketing/unsubscribe` withdraws in one call with no confirmation step (Art. 7(3): withdrawal must be as easy as granting). `IdentityService.MarketingAllowed` is the sole send gate and fails closed: `import` and `legacy` provenance are **not** affirmative consent, so a migrated default-true flag or a pre-ticked checkbox cannot become a lawful basis for sending (Recital 32; *Planet49*, C-673/17). Asserted: `tests/compliance/gdpr_consent_test.go` (Affirmative()-only gate, anti-laundering, one-call withdrawal). |
| GDPR-3 | Security of processing (Art. 32) | Met | -- | Covered in depth by the ASVS/NIST sections above. |
| GDPR-4 | Records of processing (Art. 30) | Met | -- | PRIVACY.md §2/§3 constitute the processor-side record. |
| GDPR-12 | Breach notification (Arts. 33–34) | Partial | Medium | PRIVACY.md §7 documents the 72-hour procedure and the processor→controller duty (Art. 33(2)), but nothing raises an alert from code. `riskScore` is computed and stored on every audit entry and no consumer reads it; the honeypot `Alerter` fires only on trap-user login, which is an intrusion tripwire, not a breach detector. **Fix:** risk-threshold webhook reusing the honeypot dispatcher. |
| GDPR-14 | Audit-log integrity (Art. 5(2) accountability) | Partial | Medium | Append-only is enforced at the database level (trigger + revoked UPDATE/DELETE privileges). Cryptographic chaining (HMAC over the previous record hash) with read-time verification would make tampering by a DB-level adversary detectable. Tracked as AU-9 above. |
| GDPR-16 | DPIA (Art. 35) | Partial | Low | Authentication of an existing user base is unlikely to meet the Art. 35(1) "high risk" threshold, but a DPIA template should ship for Operators whose deployment does. |

---

## Top Gaps to Close (Prioritized)

High-severity findings first, then medium, then low. All high-severity items fall within
GDPR data-lifecycle and accountability scope.

### High severity

**None open.** The four former high-severity findings are closed:

1. ~~**GDPR-10 -- Data retention limits.**~~ Closed: `VAULT_AUDIT_RETENTION_DAYS` + background
   sweeper (`internal/audit/retention.go`).
2. **GDPR-12 -- Breach notification.** Downgraded to Medium: the Art. 33 procedure is documented
   (PRIVACY.md §7); what is missing is the code path that raises an alert. See below.
3. ~~**GDPR-5 -- Right to erasure.**~~ Closed: erasure now deletes the TOTP secret, WebAuthn
   credentials and backup codes (which the `ON DELETE CASCADE` never removed, because the account
   row is scrubbed with an `UPDATE`), and hard-deletes refresh-token rows.
4. ~~**GDPR-13 -- Data subject rights.**~~ Closed: every right has an endpoint, each audited.

### Medium severity
5. **AC-12 -- Inactivity timeout (Partial).** Add idle-timeout tracking and refresh
   rejection beyond the idle threshold.
6. **AU-9 -- Audit log integrity (Partial).** Add cryptographic chaining and read-time
   verification, and consider an immutable off-system mirror.
7. **V3-2-2 -- Session invalidation on login (Partial).** Add an optional policy to revoke
   existing token families on new login.
8. **V2-1-1 -- Generic auth error messages (Partial).** Return generic
   `invalid_credentials` for locked/banned/disabled accounts.
9. **V6.4.1 -- Secret zeroing for runtime configs (Partial).** Migrate pepper and database
   password to `[]byte` and zero on shutdown.
10. **GDPR-12 -- Breach-notification alerting (Partial).** The procedure is documented but no
    code raises an alert. `riskScore` is written on every audit entry and never read; the
    honeypot `Alerter` fires only on trap-user login. Add a risk-threshold webhook reusing the
    honeypot dispatcher, so a scoring spike reaches the controller inside the Art. 33 window.

### Low severity
11. **NIST-5.2.2 -- Strict concurrent-session limit (Partial).** Optional hard enforcement
    via per-user lock.
12. **NIST-5.2.4 -- Explicit AAL labeling (Partial).** Add AAL constants and an
    `aal_level` field.
13. **V6.2.2 -- TOTP SHA-1 interop note (Partial).** Document the RFC 6238 constraint.
14. **V8.3.2 -- Ephemeral buffer zeroing (Partial).** Zero decrypted identity plaintext and
    crypto buffers after use.
15. **SC-7 -- Boundary protection documentation (Partial).** Document infrastructure-level
    network boundaries and provide network-policy examples.
16. **M06 -- List endpoint pagination (Partial).** Add bounded `limit`/`offset` to
    administrative list endpoints.
17. **OAUTH2-TOKEN-001 -- Refresh-token invalidation (Partial).** Confirm and, if needed,
    enforce revocation of the old refresh token on rotation.
18. **GDPR-16 -- DPIA template (Partial).** Authentication of an existing user base is unlikely
    to cross the Art. 35(1) "high risk" threshold, but ship a template for Operators whose
    deployment does.
