# Task 007: exported field documentation

## Suggested commit

```
docs(api): document model and handler wire fields

Add consumer-facing comments on every exported struct field
and exported constant in internal/model and internal/handler.
json:"-" fields say why they are withheld. Optional fields say
what absence means. Route- and config-specific fields name the
route or flag. No field name, tag, type or behaviour changed.
```

## Code vs docs/api.md discrepancies

Nothing was changed to reconcile these. The comments describe the
code. The document was not edited.

### Presence

1. **GET /user/devices `fingerprint_hash`.** `docs/api.md` includes
   `fingerprint_hash` (truncated to 8 characters) on each device.
   `DeviceInfo` has no such field. `model.Device.FingerprintHash` is
   `json:"-"` and the list handler never copies it. The wire response
   does not contain this key.

2. **GET /user/sessions `total`.** `SessionsResponse` always emits
   `total` (equal to `len(sessions)`). The api.md example omits it,
   and the common-response section says unpaged collections return
   the collection key alone.

3. **GET /user/devices `total`.** Same as sessions: the code always
   emits `total`; the api.md example does not.

4. **GET /user/social `total`.** The handler writes
   `{"accounts": ..., "total": N}`. The api.md example has only
   `accounts`.

5. **GET /user/blobs `total`.** `BlobListResponse.MarshalJSON` emits
   the element count as both `total` (canonical list envelope) and
   `count` (pre-1.0.0 Vue SDK alias). The api.md example shows only
   `count`.

6. **GET /user/data-export `service_documents`.** The handler always
   includes this key (empty array when the store is disabled or the
   subject has none). The data-export example and the "what is
   included" paragraph omit it. The later service-documents section
   does say Art. 15 export returns decrypted documents, including
   private ones.

7. **PUT /user/identity request fields missing from the table.**
   `identityInput` accepts `username`, `state`, `marketing_emails`
   and `dynamic`. The api.md request table lists given_name,
   family_name, country, date_of_birth, sex and billing only.
   `marketing_emails` is described in the marketing-consent section
   but not on the PUT schema.

8. **GET /user/identity response fields missing from the example.**
   The handler can emit `username`, `state`, `marketing_emails`,
   `marketing_consent` and `dynamic` (all omitempty except the
   always-present empty strings). The GET example shows only
   given_name, family_name, country, date_of_birth, sex, billing
   and updated_at.

### Meaning / constraint

9. **`mfa_required` is two different values.**
   `GET /auth/capabilities` and `GET /user/profile` report the
   server-wide `VAULT_MFA_REQUIRED` flag
   (`mfaSvc.IsRequired()` / `cfg.MFARequired`).
   `GET /user/data-export` `account.mfa_required` copies
   `model.User.MFARequired`, the per-account column. api.md uses
   the same name on both routes without saying they can disagree.

10. **PUT /user/profile `avatar_url`.** api.md says the value must be
    a valid HTTPS URL, which reads as a 400. `sanitize.AvatarURL`
    stores `""` for a non-`https://` or over-long value. The update
    still returns 200 with a cleared avatar.

11. **PUT /user/profile `locale`.** api.md says a BCP 47 tag.
    `sanitize.Locale` stores `"en"` for empty or invalid input. No
    400.

12. **PUT /user/identity `sex`.** api.md says optional, max 50 runes,
    truncated. After truncation, `IdentityData.Validate` rejects
    anything other than `""`, `"male"` or `"female"` with 400
    `invalid_profile`. That error code is also absent from the PUT
    error table (the table lists `invalid_country` /
    `invalid_date_of_birth` / `invalid_billing_country` only).

13. **POST /auth/2fa/backup-codes `codes`.** api.md says each code is
    12 hex characters (48-bit entropy), stored as Argon2id hashes, and
    the example values are 12 hex chars. The handler emits
    `vaultcrypto.RandomHex(8)`: 16 hex characters, 64-bit entropy.
    Storage is HMAC-SHA256 of the plaintext under the server HMAC key
    (`BackupCode.CodeHash`), not Argon2id. `docs/spec.md` already
    records this (16 hex / HMAC-SHA256); api.md does not. The later
    verify paragraph in api.md does say HMAC-SHA256, so the document
    disagrees with itself.

14. **`mfa_methods` never includes `email_otp`.**
    `ProfileResponse.MFAMethods` and `GET /auth/2fa/status` both copy
    `MFAService.GetStatus`, which appends only `totp`, `webauthn` and
    `backup_code`. `email_otp` is not an enrolled factor: it is minted
    only on `POST /auth/login` `available_methods` when
    `VAULT_MFA_REQUIRED` is set and GetStatus returned no methods.
    api.md's login field-naming paragraph says `mfa_methods` and
    `available_methods` "name the same list", and the email-OTP
    section says a code is sent when the user's only available method
    is `email_otp`. A client that expects `GET /user/profile` or
    `GET /auth/2fa/status` to list `email_otp` will see `[]`.

16. **HMAC vs unkeyed SHA-256 on stored hashes.**
    The two algorithms are not interchangeable. The code splits as:

    | Field | Algorithm | Source |
    |---|---|---|
    | `RefreshToken.TokenHash` | unkeyed SHA-256 hex (`SHA256Hex`) | `internal/service/auth.go` |
    | `AdminSession.TokenHash` | unkeyed SHA-256 hex (`sha256.Sum256`) | `internal/adminapi/auth.go` `hashSessionToken` |
    | `Device.FingerprintHash` | unkeyed SHA-256 of length-prefixed IP, User-Agent, Accept-Language, TLS-fingerprint (`ComputeFingerprint`) | `internal/crypto/fingerprint.go` |
    | `RefreshToken.FingerprintHash` | same `ComputeFingerprint` | issuance in `internal/service/auth.go` |
    | `AuditEntry.FingerprintHash` | same digest, stored as the caller supplied it | `internal/audit/audit.go` |
    | `BackupCode.CodeHash` | HMAC-SHA256 of the 16-hex plaintext under the server HMAC key | `internal/handler/backup_codes.go` |
    | `IdentityProfile.PseudonymID` | HMAC-SHA256(`userID + ":identity"`) | `internal/service/identity.go` |
    | `Blob.PseudonymID` | HMAC-SHA256(`userID + ":objects"`) | `internal/service/blob.go` |
    | `AccountRecovery.Pseudonym` | HMAC-SHA256(`userID + ":recovery"`) | `internal/service/erasure.go` |
    | `Blob.RefHash` | HMAC-SHA256(`"ref:" + name + ":" + pseudonym`) | `internal/service/blob.go` `refHash` |
    | password / client / admin secret hashes | Argon2id | verify paths |

    Possession of a SHA-256 `TokenHash` cannot reconstruct or mint a
    cookie. There is no HMAC secret on that field.

    api.md disagreements with this split:
    - The Device Fingerprint section writes
      `SHA256(IP + User-Agent + Accept-Language + TLS-fingerprint)`
      (simple concatenation). The code is 4-byte big-endian length
      then bytes for each field. The family is SHA-256, not HMAC.
    - The backup-code generate paragraph still says Argon2id (item
      13); the verify paragraph says HMAC-SHA256.

    `docs/spec.md` section 21.4 also calls `fingerprint_hash` "an HMAC
    of a device fingerprint". That is wrong: it is unkeyed SHA-256.
    spec.md section 5.1 and the `refresh_tokens` / `admin_sessions`
    schema table match the code. The document was not edited.

### Related contract mismatch (not a struct field)

15. **Refresh-token cookie name.** api.md names the cookie
    `refresh_token`. The handler sets and reads
    `__Host-refresh_token`. The constant is unexported, so it was
    not part of the comment pass, but a client written from api.md
    will send the wrong cookie name.

17. **Authenticated-route fingerprint mismatch error code.**
    api.md lists `fingerprint_mismatch` on most Bearer routes.
    `internal/middleware/fingerprint.go` writes `invalid_token`.
    POST /auth/refresh also maps a stored-vs-request fingerprint
    miss to `invalid_token` (the refresh error table is correct on
    this one). A client written from the per-route tables will look
    for an error code the server does not emit.

## What was documented

Every exported struct field in `internal/model` (22 persistence
structs plus `WebAuthnUser`) and every exported struct field in
`internal/handler` named types, including unexported view/input
types whose fields are still exported (`capabilitiesResponse`,
`blobListWire`, `identityInput`, `billingInput`,
`socialAccountView`). Anonymous request structs whose fields are
exported are also documented: `password` (confirm, account
delete), `current_password` / `new_password` (change password),
`friendly_name` (PATCH device), `code` (TOTP, backup-code, email
OTP, OAuth exchange). Every exported constant in those packages
(`MintScope`, `AuditTokenMinted`, `AuditSvcDocPut`,
`AuditSvcDocGet`, `AuditSvcDocDelete`) already had comments; they
were left as they were.

`json:"-"` fields state why they are withheld (credential material
or a cross-account correlator) and name the actual algorithm.
Optional / pointer / omitempty fields state what absence means.
Fields that exist only on some routes or under a config flag name
the route or flag.

No field name, JSON tag, type or behaviour was changed.

Prior-review remediations (comments now follow the code, not a
guessed threat model):

- `Device.FriendlyName`, `SessionInfo.FriendlyName`,
  `DeviceInfo.FriendlyName` and `DataExportDevice.FriendlyName`
  describe the User-Agent-derived name `findOrCreateDevice` stores
  (`useragent.FriendlyName`; "Unknown Device" if the header is
  empty or unrecognized). PATCH can replace it. The previous
  "server does not invent one / empty until the user names it"
  text was false.
- `RefreshToken.TokenHash` and `AdminSession.TokenHash` are
  unkeyed SHA-256. The previous "HMAC" wording and the claim that
  "possession of the hash plus the HMAC secret is enough to mint a
  usable cookie" were false.
- `Device.FingerprintHash`, `RefreshToken.FingerprintHash` and
  `AuditEntry.FingerprintHash` are `ComputeFingerprint` (unkeyed
  SHA-256 of length-prefixed fields), not HMAC.
- `AccountRecovery.Pseudonym` is HMAC-SHA256(`userID + ":recovery"`),
  not HMAC of the bare user id.
- `Blob.RefHash` is HMAC-SHA256(`"ref:" + name + ":" + pseudonym`),
  not HMAC of the name alone.
- The HMAC-vs-SHA-256 split is item 16.

`BackupCodesResponse.Codes` and `BackupCode.CodeHash` still
describe 16-hex HMAC-SHA256 (see `RandomHex(8)` and `HMACSign`
in `internal/handler/backup_codes.go`). `ProfileResponse.MFAMethods`
lists only the names GetStatus appends. The api.md disagreements
are items 13 and 14.

## Self-review

1. **Would my tests fail if my code were wrong?**
   No tests were added. The task forbids non-comment changes and
   forbids touching `tests/`. Comments cannot be asserted by a
   unit test that the host would run without also adding a test
   file. The "tests define done" bar is the field inventory
   against the revive exported-field count (model 172, handler 185,
   response_types.go 131) and a line-by-line reread.

2. **Did I shape the fixture to fit my code?**
   No fixtures were written. Meanings were taken from handlers,
   `internal/crypto/fingerprint.go`, `internal/service/auth.go`
   `findOrCreateDevice` / `SHA256Hex`, `internal/adminapi/auth.go`
   `hashSessionToken`, `docs/api.md` and the existing type comments.
   Where api.md and the code disagree, the comment follows the code
   and the disagreement is listed above.

3. **Can a failure look like a success?**
   Not introduced. One pre-existing case is now written down:
   PUT /user/profile accepts a non-HTTPS `avatar_url` and stores
   empty, which is a 200 that looks like "cleared" rather than
   "rejected". Listed as discrepancy 10. A user with only the
   email-OTP fallback has `mfa_methods: []` on profile/status
   while login reports `available_methods: ["email_otp"]`.
   Listed as discrepancy 14.

4. **Did I weaken anything to get green?**
   No assertions, bounds or counts were edited. No behaviour
   changed.

5. **Did I trace every gate the task names?**
   The task names no build or test command. Host compile of the
   two packages should be unchanged (comments only). Host
   `gofmt` / revive `exported` on the touched lines should pass
   if every exported field now has a comment immediately above
   it. I could not run those gates here.

6. **Is every file I touched on the permitted list?**
   Yes: `internal/model/*.go` (non-test), `internal/handler/*.go`
   (non-test), and `GROK_OUTPUT.md` as required. No `docs/`,
   `.github/`, `migrations/`, `cmd/`, `internal/crypto`,
   `internal/keystore`, `internal/service`, or `tests/` edits.

## Verified / not verified

**Verified by reading, not by running:**

- Every capitalized field on the named types in those two packages
  now has a comment immediately above it. Anonymous request
  structs (`password`, `code`, `friendly_name`, `current_password`,
  `new_password`) also have field comments.
- `findOrCreateDevice` sets `FriendlyName: useragent.FriendlyName(ua)`.
  Empty/unrecognized UA is "Unknown Device". The FriendlyName
  comments match that, not "empty until PATCH".
- `AuthService.Refresh` and token issuance use `SHA256Hex` for
  `RefreshToken.TokenHash`. `hashSessionToken` uses `sha256.Sum256`.
  `ComputeFingerprint` is unkeyed SHA-256 of length-prefixed
  fields. Backup codes and pseudonyms use `HMACSign`. The field
  comments match those call sites.
- JSON tags, field names and types in the files I rewrote match
  the versions I read before editing.
- `#nosec G117` trailers on `access_token`, `password` and
  `plaintext` are still present.
- No new em-dashes in comments I wrote. Pre-existing em-dashes
  in `model.User` and `model.AccountRecovery` type comments were
  left untouched.
- Exported constants already had comments and still do.

**Could not verify:**

- Host compile, `gofmt -l`, `golangci-lint` / revive `exported`,
  and any test run. This environment cannot compile or test.
- Whether revive treats a field comment that does not start with
  the identifier as undocumented. Every new field comment starts
  with the field name.
- Live responses against a running server. Discrepancies 1-17
  are from source vs `docs/api.md`, not from captured traffic.

**Unsure:**

- Whether the reviewer wants `GROK_OUTPUT.md` in the committed
  tree. The task asked for the discrepancy list in that file and
  forbade editing `docs/`, so this is the only allowed place.
- Whether handler types that are not on the wire (`ReadyzDeps`,
  `WebAuthnUser`) were intended. The task said every exported
  struct field; they are included.
