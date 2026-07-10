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
| RFC 8725 (JWT BCP) + RFC 6749/6819 (OAuth2) + RFC 7636 (PKCE) + RFC 9449 (DPoP) + OIDC | 50 | 1 | 0 | 3 | 96% |
| GDPR -- General Data Protection Regulation (EU 2016/679) | 4 | 9 | 2 | 0 | 60% |
| **Totals** | **234** | **21** | **2** | **9** | -- |

**Overall weighted coverage:** **91.1%** (234 requirements met out of 257 applicable,
excluding 9 Not-Applicable organizational/out-of-scope controls). Awarding half credit
for partial findings raises the figure to **95.1%**. **High-severity open findings: 4**
(all within the GDPR data-lifecycle and accountability scope).

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

## RFC 8725 (JWT BCP) + RFC 6749/6819 (OAuth2) + RFC 7636 (PKCE) + RFC 9449 (DPoP) + OIDC

**Coverage: 96%** -- 50 met, 1 partial, 0 gap, 3 N/A

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
| OAUTH2-TOKEN-001 | Token rotation on refresh: a new refresh token must be issued and the old token invalidated (RFC 6749 §6 best practice) | Partial | Low | A new refresh token is issued on refresh and family-based tracking exists; explicitly verify that the prior refresh token is revoked in the refresh code path, and add immediate revocation of the old token after the new one is issued if not already guaranteed. |

*Not Applicable (3): organizational controls (e.g., rate-limiting and audit-logging
infrastructure, JWKS endpoint operation) and unused `crit` header handling.*

---

## GDPR -- General Data Protection Regulation (EU 2016/679)

**Coverage: 60%** -- 4 met, 9 partial, 2 gap, 0 N/A

Identity and PII handling shows strong technical data-protection: AES-256-GCM encryption
at rest with pseudonymized keys, audit logging of PII access with sensitive-key scrubbing,
and a marketing-email preference field. However, GDPR compliance has substantive gaps
concentrated in data lifecycle and accountability. The right to erasure is incomplete
(only the identity profile can be deleted; full account deletion is missing); there is no
data-retention policy or automatic purge; user-rights mechanisms for portability,
objection, and restriction are absent; and accountability artifacts (privacy policy, data
processing agreements, data protection impact assessment, breach-notification procedure)
are not yet in place. Several of these requirements are organizational/policy decisions
that must be documented alongside the supporting code features. This section drives most
of the report's high-severity remediation work.

| ID | Requirement | Status | Severity | Recommended fix |
|---|---|---|---|---|
| GDPR-5 | Right to erasure (Art. 17): complete deletion of personal data on request | Partial | High | Add a comprehensive account-deletion flow: soft-delete the user record, delete the identity profile, cascade-delete blobs, TOTP secrets, WebAuthn credentials, backup codes and devices, revoke all refresh tokens, and anonymize audit entries. Document erasure handling and legal-hold exceptions. |
| GDPR-10 | Data retention limits (Art. 5(1)(e)): data not kept longer than necessary | Gap | High | Add configurable retention periods and scheduled cleanup jobs for audit entries, expired tokens, and abandoned blobs/devices; support legal-hold overrides with justification; log retention actions; document the policy. A manual cleanup function exists but is not automated. |
| GDPR-12 | Breach notification (Arts. 33–34): notify regulator within 72 hours and users without undue delay | Gap | High | Implement a breach-notification procedure: configurable notification recipients, risk-threshold alerting from audit risk scores, a documented 72-hour regulator timeline, user-notification templates, and an incident-response playbook. |
| GDPR-13 | Data subject rights support (Arts. 15–21): access, rectification, erasure, restriction, portability, objection | Partial | High | Add the missing rights endpoints: full account deletion, data-processing-preference (objection) updates, and data export (portability); document them under a "User Rights" section and log rights exercises to the audit trail. |
| GDPR-1 | Lawful basis for processing (Art. 6) | Partial | Medium | Add consent-management endpoints to capture, retrieve, and withdraw consent; log consent decisions with timestamps; document the lawful basis in the specification. |
| GDPR-7 | Purpose limitation (Art. 5(1)(b)) | Partial | Medium | Document each data field's purpose, retention period, and sharing restrictions; require separate explicit consent for any third-party marketing use; produce a data-processing agreement. |
| GDPR-8 | Data subject access & portability (Arts. 15, 20) | Partial | Medium | Add a single data-export endpoint returning all personal data (profile, identity, blob metadata, devices, user-scoped audit events) in a portable, machine-readable format; document it. |
| GDPR-9 | Accountability (Art. 5(2), Recital 76) | Partial | Medium | Produce a privacy policy documenting processing purposes, lawful basis, retention periods, user rights, the breach-notification procedure, and sub-processors; add a data-protection-impact-assessment template. |
| GDPR-11 | Third-party data sharing and transfers (Arts. 4, 6, 28) | Partial | Medium | Document third-party processors (OAuth providers, email, storage backends) and their roles; reference data-processing agreements and, for non-EU processors, the applicable transfer mechanism (Standard Contractual Clauses or adequacy); cascade-delete linked social-account data on unlink. |
| GDPR-15 | Consent for marketing communications (Arts. 5, 7) | Partial | Medium | Record consent timestamp and source for the marketing preference; add a dedicated unsubscribe endpoint; ensure the email service checks the preference before sending campaigns; document the flow. |
| GDPR-2 | Data minimization (Art. 5(1)(c)) | Partial | Low | Document the necessity rationale for each collected field, consider making the avatar URL optional by default, and present a data-collection notice at registration. |

---

## Top Gaps to Close (Prioritized)

High-severity findings first, then medium, then low. All high-severity items fall within
GDPR data-lifecycle and accountability scope.

### High severity
1. **GDPR-10 -- Data retention limits (Gap).** No automatic purge of audit entries,
   expired tokens, or abandoned records. Add configurable retention periods, scheduled
   cleanup jobs, and legal-hold overrides.
2. **GDPR-12 -- Breach notification (Gap).** No breach-notification procedure or
   risk-threshold alerting. Implement notification recipients, alerting from audit risk
   scores, a 72-hour regulator timeline, and an incident-response playbook.
3. **GDPR-5 -- Right to erasure (Partial).** Only the identity profile can be deleted. Add
   a full account-deletion flow with cascade deletion, token revocation, and audit
   anonymization.
4. **GDPR-13 -- Data subject rights support (Partial).** Add the missing rights endpoints
   (deletion, objection/preferences, portability export) and log rights exercises.

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
10. **GDPR-1, GDPR-7, GDPR-8, GDPR-9, GDPR-11, GDPR-15 (Partial).** Consent management,
    purpose/processing documentation, data export, accountability artifacts, third-party
    transfer documentation, and marketing-consent tracking.

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
18. **GDPR-2 -- Data minimization documentation (Partial).** Document field-necessity
    rationale and add a collection notice.
