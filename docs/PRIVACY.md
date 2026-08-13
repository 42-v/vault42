# Privacy & Data Protection Policy

**Component:** vault42 authentication server
**Regulation:** EU General Data Protection Regulation 2016/679 (GDPR)
**Status:** Living document -- review at least annually and on any change to the data model

---

## 1. Scope and Roles

This policy describes the personal data processed by the vault42 authentication server, the
lawful basis for each processing activity, the retention periods applied, the rights available
to data subjects, the third-party processors involved, and the procedure followed in the event
of a personal-data breach.

vault42 is authentication infrastructure. It is operated by a **deploying organization** (the
"Operator"), which is the **controller** for the personal data of its end users. vault42 itself --
the software and its maintainers -- acts as a **processor** that handles personal data on the
Operator's behalf under documented instructions (the configuration and this policy).

Several controls described here are **operator-configurable** (token lifetimes, audit-log
retention, choice of email and identity providers, deployment region). Where that is the case it
is stated explicitly. The Operator is responsible for setting these values consistently with its
own obligations and for publishing an end-user-facing privacy notice that incorporates the
relevant parts of this document.

This policy covers personal data only. Operational secrets (signing keys, client secrets,
internal configuration) are out of scope here and are addressed in the security documentation.

---

## 2. Lawful Basis for Processing (Art. 6)

Each processing purpose below is tied to the lawful basis on which it is carried out.

| # | Processing purpose | Personal data used | Lawful basis (Art. 6) |
|---|---|---|---|
| P1 | **Account creation and authentication** -- verifying identity at login, issuing tokens | Email, password hash, roles, account-state flags | Art. 6(1)(b) -- performance of a contract (providing the account) |
| P2 | **Multi-factor authentication** -- TOTP, WebAuthn passkeys, backup codes, email one-time codes | Encrypted TOTP secret, WebAuthn public key + credential ID, hashed backup codes, email | Art. 6(1)(b) contract; Art. 6(1)(f) legitimate interest in account security |
| P3 | **Session and device management** -- tracking active sessions, recognizing known devices, "remember me" | Refresh-token records, device records (fingerprint hash, friendly name, IP, user-agent, timestamps) | Art. 6(1)(b) contract; Art. 6(1)(f) legitimate interest in fraud/abuse prevention |
| P4 | **Security monitoring and abuse prevention** -- audit logging, rate limiting, account lockout, breach-password screening | Audit entries (user/client id, IP, user-agent, fingerprint hash, event metadata, risk score), rate-limit counters, failed-login counters | Art. 6(1)(f) legitimate interest in securing the service; Art. 6(1)(c) legal obligation to keep security records where applicable |
| P5 | **Identity profile** -- storing optional personal details an end user chooses to provide (name, country, date of birth, sex, billing address, app-specific data) | Encrypted identity profile | Art. 6(1)(b) where required to deliver a requested feature; otherwise Art. 6(1)(a) consent |
| P6 | **Encrypted user data blobs** -- opaque user-supplied data stored on the user's behalf | Encrypted blob payload + encrypted label | Art. 6(1)(b) contract (storage feature requested by the user) |
| P7 | **Social / federated login** -- linking an external OAuth/OIDC identity to an account | Provider name, provider user id, provider-supplied email, encrypted provider tokens | Art. 6(1)(b) contract; Art. 6(1)(a) consent (the user initiates the link) |
| P8 | **Account import** -- migrating a pre-existing account from a prior system | Email, source-system tag, source-system id, import-pending flag | Art. 6(1)(b) contract; Art. 6(1)(f) legitimate interest in service continuity |
| P9 | **Transactional email** -- verification, password reset, MFA codes, security notices | Email address | Art. 6(1)(b) contract (necessary to operate the account) |
| P10 | **Marketing email** -- optional product/marketing communications | Email address + marketing-email preference flag | Art. 6(1)(a) consent -- sent only when the user has opted in |
| P12 | **Service-scoped documents** -- opaque JSON a trusted service stores about a user on the platform's behalf, private to the writing service unless it marks a document shared | Encrypted document payload + HMAC pseudonym of the user id, owning client id, document key, size and visibility | Art. 6(1)(b) contract, on the same footing as P6: the Operator's service requests the storage. The contents are opaque to vault42, so the Operator remains responsible for what its services write |
| P11 | **Account-deletion recovery escrow** -- keeping a recoverable record of an erased account so an accidental or malicious deletion can be reversed | Encrypted payload (email, creation date, roles, display name) + HMAC pseudonym of the user id, requester and reason tag | Art. 6(1)(f) legitimate interest in the integrity and availability of user accounts. Only when the Operator configures a recovery key; see §3.1, §4 and §5.3 |

Consent (P5 where applicable, P7, P10) is freely given, specific, and withdrawable. Withdrawing
consent does not affect the lawfulness of processing carried out before withdrawal. Marketing
email is **off unless the user opts in** via the `marketing_emails` preference; clearing that
preference withdraws consent.

### 2.1 Demonstrating consent (Art. 7(1))

Art. 7(1) puts the burden on the controller to **demonstrate** that consent was given. A boolean
preference records what the user wants; it cannot show that they ever chose it. Every marketing
preference is therefore stored together with a consent record — `granted`, `at`, `source` and, for
migrated accounts, `origin` — on the encrypted identity profile, and each change also writes a
`consent_granted` / `consent_withdrawn` audit entry.

Only two sources count as **affirmative** consent, and only these authorise sending:

| Source | Meaning | Affirmative? |
|---|---|---|
| `registration` | an explicit boolean supplied by a frontend at sign-up | **yes** |
| `profile` | the user changed the preference on their profile | **yes** |
| `unsubscribe` | withdrawal via the one-click unsubscribe path | n/a (always a withdrawal) |
| `import` | carried over from a migrated system | **no** |
| `legacy` | profile predates consent provenance; value known, origin unknown | **no** |

`import` and `legacy` are deliberately **not** affirmative. A migrated flag may be a default the
user was never shown: a column that defaults to true, or a consent checkbox that ships pre-ticked,
produces a `true` that is indistinguishable from a choice — and Recital 32 (and *Planet49*,
C-673/17) is explicit that pre-ticked boxes and silence are not consent. The imported value is
preserved so the Operator can run a re-permission campaign against it, but it does not by itself
authorise sending. `IdentityService.MarketingAllowed` is the only sanctioned gate for a campaign
sender and fails closed on everything except the two affirmative sources.

---

## 3. Data Inventory

Personal data is held in five logical stores: the **auth** store (account and credential
records), the **identity** store (encrypted personal profile, keyed by pseudonym), the
**objects** store (encrypted user blobs, keyed by pseudonym), the **audit** store
(append-only security log), and the **recovery escrow** (`auth.account_recovery`, an
append-only log of encrypted deletion records, written only when the Operator configures a
recovery key).

### 3.1 Sensitivity and protection notes

- **Encrypted at rest (AES-256-GCM):** the identity profile, user data blobs and blob labels,
  TOTP secrets, and stored OAuth/OIDC provider tokens.
- **Pseudonymization:** the identity profile and blobs are stored under a deterministic
  **pseudonym** derived by HMAC from the user id, not under the user id or email. The plaintext
  reference name of a named blob never reaches the database -- only its HMAC is stored. Audit
  metadata for blob events carries the blob id, never the reference name or the label; the
  logger scrubs those keys from any blob event as a backstop.
- **Hashed, not recoverable:** passwords (and password history), backup codes, refresh tokens,
  device fingerprints, and admin/admin-session tokens are stored as hashes only.
- **Append-only:** the audit log and the recovery escrow are enforced append-only at the
  database layer (UPDATE and DELETE are blocked by triggers); bulk removal is possible only
  through the dedicated retention-cleanup routine for each.
- **Recovery escrow (`auth.account_recovery`):** written on account erasure **only when the
  Operator has configured `VAULT_RECOVERY_PUBLIC_KEY_FILE`**. Each record holds the erased
  user's email, account creation date, roles and display name in a single payload encrypted
  with an RSA public key, plus the HMAC pseudonym of the user id, who requested the deletion
  and a short reason tag. The running service holds only the **public** key: it can write an
  escrow record but cannot read one back. Decryption requires the private key, which the
  Operator keeps offline (`cmd/recover`), so a compromised server or database cannot recover
  the erased addresses. Its purpose is to reverse an accidental or malicious deletion; it is
  bounded by the retention horizon in §4 and disclosed as a limitation of erasure in §5.3.
  Where the Operator does not configure a recovery key, nothing is written and the store does
  not exist for that deployment.

### 3.2 Inventory table

| Store / field | Purpose (see §2) | Retention | Lawful basis |
|---|---|---|---|
| **auth.users** | | | |
| email (unique) | P1, P9 | Life of account; removed/anonymized on erasure | 6(1)(b) |
| email_verified | P1 | Life of account | 6(1)(b) |
| password_hash | P1 | Life of account; null for import-pending/federated-only | 6(1)(b) |
| display_name | P1 | Life of account | 6(1)(b) |
| avatar_url | P1 | Life of account (optional) | 6(1)(b) / 6(1)(a) |
| locale | P1 | Life of account | 6(1)(b) / 6(1)(f) |
| mfa_required | P2 | Life of account | 6(1)(f) |
| roles | P1 | Life of account | 6(1)(b) |
| locked_until, failed_login_count | P4 | Transient; reset on successful auth or lockout expiry | 6(1)(f) |
| disabled, banned, ban_reason | P4 | Life of account (account-state) | 6(1)(f) |
| last_login_at | P3, P4 | Life of account | 6(1)(f) |
| deleted, deleted_at | erasure lifecycle | Per erasure procedure (§5) | 6(1)(c) |
| import_pending, imported_from, legacy_id | P8 | Cleared/retained per import lifecycle | 6(1)(b) |
| created_at, updated_at | account lifecycle | Life of account | 6(1)(b) |
| **auth.password_history** | | | |
| password_hash (historical) | P1 (reuse prevention) | Life of account; cascade-deleted with user | 6(1)(f) |
| **auth.social_accounts** | | | |
| provider, provider_user_id | P7 | Until unlinked or account erased | 6(1)(b)/6(1)(a) |
| email (provider-supplied) | P7 | Until unlinked or account erased | 6(1)(b)/6(1)(a) |
| access_token_enc, refresh_token_enc | P7 | Until unlinked or account erased | 6(1)(b) |
| **auth.refresh_tokens** | | | |
| token_hash, family_id, device_id, fingerprint_hash | P3 | Until expiry, rotation, or revocation (§4) | 6(1)(b)/6(1)(f) |
| expires_at, used, revoked | P3 | As above | 6(1)(b) |
| **auth.devices** | | | |
| fingerprint_hash | P3, P4 | Until device removed or account erased | 6(1)(f) |
| friendly_name | P3 | Until device removed or account erased | 6(1)(b) |
| ip | P3, P4 | Until device removed or account erased | 6(1)(f) |
| user_agent | P3, P4 | Until device removed or account erased | 6(1)(f) |
| trusted, trusted_until, first/last_seen_at | P3 | Until device removed or account erased | 6(1)(f) |
| **auth.totp_secrets** | | | |
| secret_enc, verified | P2 | Until MFA removed or account erased | 6(1)(b)/6(1)(f) |
| **auth.webauthn_credentials** | | | |
| credential_id, public_key, sign_count, flags, friendly_name | P2 | Until credential removed or account erased | 6(1)(b)/6(1)(f) |
| **auth.backup_codes** | | | |
| code_hash, used, used_at | P2 | Until regenerated or account erased | 6(1)(f) |
| **auth.rate_limits** | | | |
| key, window_start, count | P4 | Transient; expires with the rate-limit window | 6(1)(f) |
| **identity.profiles** (encrypted, pseudonym-keyed) | | | |
| given_name, family_name | P5 | Until profile deleted or account erased | 6(1)(b)/6(1)(a) |
| username | P5 | As above | 6(1)(b)/6(1)(a) |
| country, state | P5 | As above | 6(1)(b)/6(1)(a) |
| date_of_birth | P5 | As above | 6(1)(b)/6(1)(a) |
| sex | P5 | As above | 6(1)(a) |
| marketing_emails (preference) | P10 | Until changed or account erased | 6(1)(a) |
| billing (address line 1/2, city, postal code, country, VAT id) | P5 | As above | 6(1)(b) |
| dynamic (opaque app-specific data, namespaced) | P5 | As above; vault42 stores it encrypted and does not interpret it | 6(1)(b)/6(1)(a) |
| **objects.blobs** (encrypted, pseudonym-keyed) | | | |
| data_enc (payload), label_enc | P6 | Until blob deleted or account erased | 6(1)(b) |
| ref_hash, checksum, size_bytes, stored_bytes | P6 | As above | 6(1)(b) |
| **objects.service_documents** (encrypted, pseudonym-keyed, off unless configured) | | | |
| value_enc (payload) | P12 | Until the document is deleted or the account is erased | 6(1)(b) |
| client_id (owning service), doc_key, visibility, size_bytes | P12 | As above | 6(1)(b) |
| subject_hash (HMAC pseudonym of the user id) | P12 | As above | 6(1)(b) |
| **audit.audit_log** (append-only) | | | |
| user_id, client_id | P4 | Per audit retention (§4) | 6(1)(f)/6(1)(c) |
| ip, user_agent, fingerprint_hash, device_id | P4 | Per audit retention (§4) | 6(1)(f) |
| event_type, metadata, risk_score, timestamp | P4 | Per audit retention (§4) | 6(1)(f)/6(1)(c) |
| **auth.account_recovery** (append-only, encrypted; only when a recovery key is configured) | | | |
| pseudonym (HMAC of the user id) | P11 | Per recovery-escrow retention (§4) | 6(1)(f) |
| payload (encrypted: email, created_at, roles, display_name) | P11 | Per recovery-escrow retention (§4) | 6(1)(f) |
| deleted_at, deleted_by, reason | P11 | Per recovery-escrow retention (§4) | 6(1)(f) |

Administrator/operator accounts (used to run the service rather than to consume it) are out of
the end-user scope of this policy and are addressed in the operational documentation.

---

## 4. Retention Periods

vault42 minimizes how long it keeps data and ties most records to the lifecycle of the account
or the session they belong to. The following periods apply:

- **Access tokens (JWT):** short-lived, default **15 minutes**. Operator-configurable.
- **Refresh tokens:** default **7 days** (production profile; 24 hours in the development
  profile). With "remember me", default **30 days**. Operator-configurable. Refresh tokens are
  single-use and rotate on each use; superseded, used, revoked, or expired tokens are no longer
  valid and are pruned in the normal course of token lifecycle.
- **Rate-limit counters:** transient; bounded to the active rate-limit window.
- **Lockout / failed-login state:** transient; cleared on successful authentication or when the
  lockout window expires.
- **Audit log:** retained for security and accountability, then purged. The retention horizon is
  **operator-set** via `VAULT_AUDIT_RETENTION_DAYS`; a background sweeper runs every 6 hours (and
  once at startup) and removes entries older than the horizon. Because the audit log is
  append-only, this is the only sanctioned removal path; `vault cleanup-audit` performs the same
  purge on demand. **The sweeper is disabled by default** (`VAULT_AUDIT_RETENTION_DAYS=0`):
  silently deleting security logs is not a safe default, so an Operator processing personal data
  under Art. 5(1)(e) must set a horizon explicitly. Audit entries are deliberately exempt from the
  account-erasure cascade (Art. 17(3)(b)/(e)), which is precisely why they need a time-based
  purge of their own.
- **Service-scoped documents:** kept until the owning service deletes the document or the
  account is erased. There is no time-based sweeper, because vault42 cannot see inside a document
  and so cannot judge when its purpose is spent. The store is off unless the Operator enables it,
  and an Operator that enables it takes on the Art. 5(1)(e) judgement for whatever its services
  write: the per-subject and per-document quotas bound volume, not age.
- **Account-recovery escrow:** where the Operator configures a recovery key
  (`VAULT_RECOVERY_PUBLIC_KEY_FILE`), one encrypted record per erasure is retained so the
  deletion can be reversed, then purged. The retention horizon is **operator-set** via
  `VAULT_RECOVERY_RETENTION_DAYS`; a background sweeper runs every 6 hours (and once at
  startup) and removes records older than the horizon, and `vault cleanup-recovery
  --retention-days N` performs the same purge on demand. Because the escrow is append-only,
  those are the only sanctioned removal paths. **The sweeper is disabled by default**
  (`VAULT_RECOVERY_RETENTION_DAYS=0`): the escrow holds the only recoverable copy of an erased
  account, so destroying it must be an explicit operator choice — but left at `0` nothing is
  ever purged, and an Operator that enables the escrow at all must set a horizon to satisfy
  Art. 5(1)(e). The horizon should be no longer than the window in which an erroneous or
  malicious deletion would still plausibly be noticed and reversed. Escrow records are
  deliberately exempt from the account-erasure cascade (they exist to survive it — see §5.3),
  which is precisely why they need a time-based purge of their own. An Operator that does not
  want this retention at all simply leaves `VAULT_RECOVERY_PUBLIC_KEY_FILE` unset, in which
  case no escrow record is ever written.
- **Signing keys:** retired keys remain published only for a short overlap window (default **1
  hour**, operator-configurable) so in-flight tokens validate, then are removed from the
  published key set.
- **Identity profile, blobs, devices, credentials:** retained for the life of the account (or
  the life of the specific item) and removed on the user's request or on account erasure.
- **Abandoned data:** records tied to an account (identity profile, blobs, devices, credentials,
  social links) are removed when the account is erased (§5). The Operator may additionally
  configure scheduled pruning of stale sessions/devices; where it does, the pruning interval is
  an operator setting and must be reflected in the Operator's end-user notice.

The Operator may set shorter retention than the defaults above to meet its own obligations, and
must not retain personal data longer than necessary for the purpose for which it was collected
(Art. 5(1)(e)).

---

## 5. Data-Subject Rights (Arts. 15–21)

End users (data subjects) may exercise the following rights. Authenticated self-service
endpoints are listed where they exist; remaining requests are handled by the Operator through
the contact in §8. The Operator responds **without undue delay and within one month** (Art. 12),
extendable by two months for complex requests with notice.

Exercising a right requires the requester's identity to be verified -- for self-service endpoints
this is the authenticated session; sensitive operations additionally require a recent
re-confirmation of credentials (step-up). Rights exercises are recorded in the audit log.

### 5.1 Right of access and data portability (Arts. 15, 20)

- The user can read the currently stored identity profile via **`GET /user/identity`**, and
  review active sessions and devices via **`GET /user/sessions`** and **`GET /user/devices`**.
- A consolidated, machine-readable export of all personal data associated with the account --
  profile, identity, blob metadata, service-scoped documents, linked social accounts, devices,
  and the user-scoped audit events -- is provided via the data-export facility (**`GET /user/data-export`**) where the
  deployment exposes it; otherwise the Operator produces the same export on request. The export
  is delivered in a structured, commonly used, machine-readable format (JSON) so it can be ported
  to another controller.
- The audit events in that export are capped at the **most recent 1000** so a single request
  cannot pull an unbounded history into memory. The export is never silently partial: it always
  carries `audit_events_total` (how many events are held), `audit_events_limit` (the cap) and
  `audit_events_truncated`. Where `audit_events_truncated` is `true`, the remaining events are
  part of the same right of access and the Operator supplies them on request through the contact
  in §8. Every other category in the export is complete and uncapped.

### 5.2 Right to rectification (Art. 16)

- The user updates account fields via **`PUT /user/profile`** and the identity profile via
  **`PUT /user/identity`** (name, username, country, state, date of birth, sex, billing details,
  marketing preference, app-specific data). Submitted values are validated for shape and bounds
  before being encrypted and stored.

### 5.3 Right to erasure (Art. 17)

- The user can delete the identity profile via **`DELETE /user/identity`**, individual blobs via
  **`DELETE /user/blobs/{id}`** (and named blobs), individual devices/sessions, and MFA
  credentials, each through the corresponding authenticated endpoint.
- The user can unlink a federated identity via **`DELETE /user/social/{id}`**, which removes the
  provider link together with the encrypted provider access/refresh tokens held for it.
- Full account erasure removes or anonymizes the account record and deletes every account-linked
  auth record: password history, refresh tokens (deleted outright, not merely revoked — a revoked
  row still carries a fingerprint hash and a device reference), devices, TOTP secrets, WebAuthn
  credentials, backup codes, and social-account links, plus the pseudonym-keyed identity profile
  blobs and service-scoped documents. Documents written about the user by a service are personal
  data under Art. 4(1) whichever service authored them, so the cascade reaches them on both the
  self-service and the administrator paths. The MFA authenticators are deleted explicitly rather
  than by database cascade: the
  account row is scrubbed in place (an `UPDATE`) so that foreign keys stay valid, which means the
  `ON DELETE CASCADE` on those tables never fires. Backup codes are **purged**, not merely marked
  used — invalidating a code leaves its hash and the user ID in the table, which is enough to end
  a session but not to erase a person. Account erasure is requested through the Operator (§8)
  where no self-service account-deletion endpoint is exposed in the deployment.
- **Order of operations.** The cascade spans nine stores with no transaction across them, so the
  account is tombstoned **before** any personal data is destroyed, never after. A failure part-way
  therefore leaves an account that has already stopped authenticating and still holds some data
  pending deletion — not a live, loginable account whose second factors have already been
  destroyed. Every step is idempotent, so an interrupted erasure is completed by re-running it.
- **The recovery escrow is a second exception to immediate erasure.** Where the Operator has
  configured a recovery key, full account erasure **first writes one encrypted record** to
  `auth.account_recovery` holding the user's email, account creation date, roles and display
  name, and erasure is refused if that write fails. The account record is then scrubbed as
  described above, so the plaintext email no longer exists anywhere the service can read: the
  escrow payload is encrypted to a public key whose private half the Operator holds offline,
  and the running service cannot decrypt it. The retained copy exists so an accidental or
  malicious deletion can be reversed (P11, Art. 6(1)(f)), which the Operator relies on under
  Art. 17(3)(e) where a deletion is disputed and under its own Art. 5(1)(f) integrity
  obligation. It is not indefinite: it is bounded by the retention horizon in §4 and removed
  when that horizon passes. A data subject who does not want any recoverable copy retained
  should be told which of the two configurations their deployment runs — an Operator that
  leaves `VAULT_RECOVERY_PUBLIC_KEY_FILE` unset writes no escrow record at all, and erasure is
  then final at the moment the cascade completes. Operators must reflect the configuration
  they actually run in their end-user privacy notice.
- **Audit records are an exception to immediate erasure.** Security audit entries are retained
  for their retention period (§4) and for any applicable legal-hold or legal-obligation reason
  (Art. 17(3)(b)/(e)); they are minimized (identifiers are limited to what is needed for the
  security purpose) and removed when the retention horizon passes.

### 5.4 Right to restriction (Art. 18)

- On a restriction request, the Operator can disable the account (account-state flag) so that
  the data is retained but no longer actively processed for authentication, pending resolution of
  a dispute over accuracy or lawfulness.

### 5.5 Right to object (Art. 21)

- The user can object to marketing communications at any time by clearing the
  `marketing_emails` preference (via `PUT /user/identity`), or in a single call with no
  confirmation step via **`POST /user/marketing/unsubscribe`**, which withdraws consent under P10.
  Art. 7(3) requires withdrawal to be as easy as granting; granting is one checkbox, so
  withdrawal is one request. Both paths write a `consent_withdrawn` audit entry.
- Objections to processing based on legitimate interest (P3, P4) are assessed by the Operator;
  security and abuse-prevention processing necessary to protect the service and other users may
  continue where compelling legitimate grounds apply.

### 5.6 Rights relating to automated decision-making (Art. 22)

- vault42 does not make decisions producing legal or similarly significant effects solely by
  automated means. Risk scores in the audit log and automated lockout/rate-limiting are security
  controls that gate access; they do not profile users for any other purpose.

A data subject also has the right to lodge a complaint with a supervisory authority (Art. 77).

---

## 6. Third-Party Processors and Recipients (Arts. 4, 6, 28, 44–49)

vault42 shares personal data with external parties only as needed to deliver the functions the
Operator enables. The set of processors depends on the Operator's configuration.

| Recipient / processor | Role | Data shared | Notes |
|---|---|---|---|
| **OAuth / OIDC identity providers** (e.g. Google, GitHub, Facebook, and any generic OpenID Connect provider the Operator registers) | Processor / independent controller for federated login | The provider returns a provider user id and, typically, an email; vault42 stores these plus encrypted provider tokens | Used only when the Operator enables social login and the user initiates the link. The provider's own privacy notice governs data the user holds with that provider. |
| **Email delivery service** (SMTP server, or a hosted email provider) | Processor | Recipient email address and message content (verification, reset, MFA, security and -- if opted in -- marketing messages) | Backend and credentials are operator-configured. Transactional mail is necessary to operate the account; marketing mail is sent only on opt-in. |
| **Breach-password screening** (Have I Been Pwned range API) | Processor (k-anonymity) | A short prefix of the SHA-1 hash of a candidate password -- **never the password, email, or any account identifier** | Uses the k-anonymity range protocol: only a hash prefix leaves the server. Fail-open: if the service is unreachable the check is skipped and authentication is not blocked. |
| **Primary datastore (PostgreSQL)** | Processor (storage) | All persisted records described in §3, with the encryption and hashing protections noted there | Hosting/region is the Operator's choice; encrypted blobs and the encrypted identity profile are held here under pseudonymous keys. |
| **Cache backend** (in-memory, PostgreSQL, or Redis, per Operator choice) | Processor (transient) | Short-lived operational values (e.g. confirmation state, cache entries) | Transient; not a long-term store of personal data. |

The Operator must put a data-processing agreement (Art. 28) in place with each processor it
engages, and, where a processor is located outside the EEA, ensure an appropriate transfer
mechanism (an adequacy decision or Standard Contractual Clauses) is in place (Arts. 44–49).
Because processor selection and hosting region are operator-configurable, maintaining this list
for a given deployment is the Operator's responsibility.

---

## 7. Personal-Data Breach Notification (Arts. 33–34)

A personal-data breach is any breach of security leading to accidental or unlawful destruction,
loss, alteration, unauthorized disclosure of, or access to personal data. The following procedure
applies.

### 7.1 Detection and assessment

**What Vault42 provides, stated precisely.** Vault42 records security-relevant events to the
append-only audit log and tags each one with an integer severity in the `risk_score` column
(`migrations/001_initial_schema.sql:163`), assigned by the call site that writes the event
(`audit.Logger.Log`) -- for example 100 for a login attempt against a configured honeypot trap
user (`AuthService.Login`), 100 for a non-loopback request reaching the admin gateway
(`adminapi.LocalOnly`), 80 for a concurrent-session check that failed closed
(`AuthService.checkSessionLimit`), 20 for a rejected KMS unwrap (`handler.KMSHandler.audit`).

**Vault42 does not evaluate that score.** There is no threshold, no scoring engine, no anomaly
detection and no alert derived from it. The value exists so a human reviewing the log can triage
it: the admin dashboard colour-codes and sorts on it
(`internal/adminapi/static/admin.js`), and it is returned by `GET /admin/audit`. The audit query
filter (`repository.AuditFilter`) supports user, event type and time range, so filtering *by*
risk score is done by the reviewer or by an external log pipeline, not by Vault42.

The only automated reactions Vault42 performs are narrow, and none of them is breach detection:
per-account lockout after 5 failed logins and per-IP lockout after 20 (`lockoutThreshold` and
`ipLockoutThreshold`, `internal/service/auth.go`); the honeypot webhook, which fires on a login
attempt against a name in `VAULT_HONEYPOT_TRAP_USERS` and only when `VAULT_HONEYPOT_WEBHOOK` is
configured (wired in `cmd/vault/main.go`); and the admin gateway killswitch, which audits a
non-loopback request and crashes the pod.

**Detection is therefore the Operator's responsibility.** An Operator processing personal data
should ship the audit log to its own monitoring and set the alerting rules there. Vault42 gives
that pipeline a durable, append-only, severity-tagged record; it does not watch it.

The procedure:

1. **Detect.** Sources are the Operator's own monitoring and alerting over the exported audit log
   and infrastructure telemetry, the honeypot webhook where configured, and external reports
   (including reports received under the process in `SECURITY.md`).
2. **Contain.** Take immediate containment steps (e.g. revoke affected sessions and refresh
   tokens, rotate signing keys, lock or disable affected accounts, rotate compromised secrets).
3. **Assess.** Determine the nature of the breach, the categories and approximate number of data
   subjects and records affected, the likely consequences, and the measures taken or proposed.
   Record this assessment.

### 7.2 Regulator notification -- within 72 hours

If the breach is likely to result in a risk to the rights and freedoms of data subjects, the
controller (the Operator) notifies the competent supervisory authority **without undue delay and,
where feasible, within 72 hours** of becoming aware of it (Art. 33). If the 72-hour deadline
cannot be met, the notification states the reasons for the delay. The notification includes the
nature of the breach, the categories and approximate numbers affected, the likely consequences,
the contact point (§8), and the measures taken or proposed. Where information is not yet
available, it is provided in phases without further undue delay.

A breach that is **unlikely** to result in a risk to data subjects need not be notified to the
authority, but the reasoning is documented.

### 7.3 Data-subject notification -- without undue delay

If the breach is likely to result in a **high risk** to the rights and freedoms of data subjects,
affected users are notified **without undue delay**, in clear and plain language, describing the
nature of the breach, the contact point, the likely consequences, and the measures taken and
recommended (Art. 34). Direct notification is via the user's account email.

Direct notification is not required if (a) the affected data was rendered unintelligible to
unauthorized parties -- for example data protected by the encryption-at-rest and hashing measures
in §3 -- (b) subsequent measures ensure the high risk is no longer likely to materialize, or (c)
direct notification would involve disproportionate effort, in which case a public communication
of equivalent effectiveness is used.

### 7.4 Record-keeping

All breaches are documented -- facts, effects, and remedial action -- regardless of whether they
were notifiable, so the supervisory authority can verify compliance (Art. 33(5)). The
append-only audit log supports reconstructing the timeline of security-relevant events.

---

## 8. Accountability and Contact (Art. 5(2), Recital 76)

- **Data minimization and purpose limitation** are designed into the system: optional profile
  fields are collected only when the user provides them; credentials and tokens are hashed;
  the identity profile and blobs are encrypted and stored under pseudonymous keys; the audit log
  records only what is needed for the security purpose.
- **Records of processing.** This document, together with the data inventory in §3 and the
  processor list in §6, forms the basis of the records of processing activities. The Operator
  maintains the deployment-specific record (configured processors, retention values, hosting
  region).
- **Review.** This policy is reviewed at least annually and whenever the data model, the set of
  processors, or the configuration of retention or providers changes. Changes to the personal
  data fields in §3 must be reflected here in the same change.
- **Data Protection Impact Assessment.** Where a deployment processes data likely to result in a
  high risk to data subjects, the Operator carries out a DPIA (Art. 35) before that processing.

**Contact.** Requests to exercise data-subject rights, breach reports, and data-protection
enquiries should be directed to the contact point published by the Operator in its end-user
privacy notice. The Operator is the controller and the point of contact for data subjects; where
the Operator has appointed a Data Protection Officer, that contact is published in the same
notice.

---

*This policy describes the data-protection behavior of the vault42 authentication server as
implemented. Items marked operator-configurable depend on deployment settings and must be
finalized by the Operator for its specific deployment.*
