# Vault42 -- Specification

> Authoritative specification reflecting the implemented system as of 2026-03-02.
> For the original planning document, see [spec-draft.md](spec-draft.md).

---

## 1. Overview

Vault42 is a production-grade authentication and authorization microservice built in Go. It is PostgreSQL-backed, deployed via Kubernetes (Helm chart), HTTPS-only, and single-origin. It implements stateless JWT access tokens (RS256), stateful refresh tokens with family-based replay detection, TOTP and WebAuthn/FIDO2 two-factor authentication, OAuth2 social login (Google, GitHub, Facebook), device fingerprinting, an encrypted identity store for PII, encrypted blob storage with per-user quotas, and an append-only audit log.

**Key properties:**
- Go 1.24, 3 direct dependencies (+ test-only deps in separate modules)
- Single binary, distroless container, non-root, read-only filesystem
- PostgreSQL with least-privilege roles (`vault_mig` for DDL, `vault_app` for runtime, `vault_admin` for admin gateway)
- Pluggable cache layer (Redis, in-memory, PostgreSQL)
- Four deployment profiles: production, embedded (RPi5), dev, honeypot
- Helm chart as the sole deployment method

---

## 2. Authentication Flows

### 2.1 Email/Password Registration

**Endpoint:** `POST /auth/register`

1. Client submits `email`, `password`, `display_name` (optional), `locale` (optional), `redirect_to` (optional)
2. Server validates email format, enforces minimum password length (15 characters, NIST SP 800-63B Rev 4)
3. If HIBP check is enabled (`VAULT_HIBP_CHECK=true`, default), password is checked against Have I Been Pwned via k-anonymity (only SHA-1 prefix sent)
4. If email already exists, a `201 Created` response with `{"status": "verification_email_sent"}` is returned -- identical to the real success case, preventing user enumeration
5. Password is hashed with Argon2id (46 MiB, 1 iteration, 1 parallelism)
6. User record created; password hash stored in password history
7. Verification email sent asynchronously (token stored hashed in cache, 24h TTL)
8. Response: `201 Created` with `{"status": "verification_email_sent", "message": "If this email is not already registered, a verification email has been sent."}`

**Source:** `internal/service/auth.go` (Register), `internal/handler/auth.go` (Register)

### 2.2 Email/Password Login

**Endpoint:** `POST /auth/login`

1. Client submits `email`, `password`, `remember_me` (optional), `client_id` (optional)
2. If user not found, a dummy Argon2id verification runs to prevent timing-based enumeration (also runs on database error)
3. Account lock check: both database `locked_until` field and cache-based auto-lockout (5 failures = 15-minute lockout, with DB fallback when cache unavailable)
3b. IP-wide lockout check: 20 failures per IP within 15 minutes triggers IP-level lockout (via cache with PostgreSQL rate_limits fallback)
4. Password verified with Argon2id (constant-time comparison via `crypto/subtle`)
5. Email verification check -- unverified emails cannot log in
6. Failed login counter reset on success
7. Device fingerprint computed: `SHA256(len‖IP ‖ len‖User-Agent ‖ len‖Accept-Language ‖ len‖TLS-fingerprint)` -- length-prefixed (4-byte big-endian) to prevent separator collision attacks
8. MFA check: if user has any verified 2FA methods (TOTP, WebAuthn, backup codes, email OTP):
   - A `2fa_challenge` JWT (5-minute TTL) is issued instead of real tokens
   - Response includes `requires_2fa: true`, `challenge_token`, and `available_methods`
9. If no MFA: device record created/updated, access + refresh token pair issued
10. Refresh token set as `HttpOnly; Secure; SameSite=Strict; Path=/` cookie
11. Response: `200 OK` with `access_token`, `token_type`, `expires_in`

**Honeypot:** In honeypot profile, if the login email matches a trap user (`VAULT_HONEYPOT_TRAP_USERS`), the system returns fake JWT and refresh tokens, fires an audit event (`honeypot_trigger`), and dispatches a webhook alert. The request appears to succeed from the attacker's perspective.

**Metrics:** Login attempts, successes, and failures are recorded via atomic Prometheus counters (`vault_login_attempts_total`, `vault_login_success_total`, `vault_login_failed_total`).

**Source:** `internal/service/auth.go` (Login), `internal/handler/auth.go` (Login)

### 2.3 OAuth2 Social Login

**Providers:** Google (OIDC + PKCE S256), GitHub (OAuth2 + PKCE S256), Facebook (OAuth2 + PKCE S256)

**Authorize:** `GET /auth/oauth2/authorize?provider=google|github|facebook`

1. PKCE code verifier generated, challenge computed
2. State parameter constructed: `provider.nonce.expiry` + HMAC-SHA256 signature
3. PKCE verifier stored in cache keyed by nonce (10-minute TTL)
4. Client redirected to provider's authorization URL

**Callback:** `GET /auth/oauth2/callback/{provider}`

1. State parameter parsed and HMAC signature verified
2. Expiry checked (10-minute window)
3. PKCE verifier retrieved atomically (`GetAndDelete` -- single-use, prevents race conditions)
4. Authorization code exchanged for tokens with the verifier
5. User info fetched from provider API
6. Account linking:
   - Existing social account link found: use that user
   - Email matches existing user: link only if **both** OAuth provider confirms email verified AND existing account email is verified (prevents takeover via unverified OAuth emails)
   - No match: create new user
7. MFA check (same as email/password login)
8. A one-time exchange code generated, token data cached (`oauth_code:{hash}:{fingerprint}`, 60s TTL)
9. Redirect to `{origin}/oauth/callback#code={exchangeCode}`

**Exchange:** `POST /auth/oauth2/exchange` (rate-limited 10/min/IP)
1. Client submits `code` from the callback fragment
2. Code hashed and looked up in cache (keyed by hash + fingerprint)
3. Atomically deleted after retrieval (single-use)
4. Access + refresh tokens returned, refresh token set as cookie

**Source:** `internal/handler/oauth.go`, `internal/oauth2/google.go`, `internal/oauth2/github.go`, `internal/oauth2/facebook.go`

### 2.4 Token Refresh

**Endpoint:** `POST /auth/refresh`

1. Refresh token read from `refresh_token` cookie
2. Token hash looked up in database
3. Replay detection: if token already `used = true`, entire family is revoked (all tokens in the rotation chain) and `replay_detected` error returned
4. Expiry check
5. Fingerprint recomputed and compared to stored fingerprint; mismatch revokes the entire family
6. Token atomically marked as used (CAS -- `UPDATE ... WHERE used = false` returns affected rows)
7. Concurrent CAS failure treated as replay (entire family revoked)
8. New access + refresh token pair issued in the same family
9. New refresh token stored, cookie updated

**Source:** `internal/service/auth.go` (Refresh)

### 2.5 Logout

**Endpoint:** `POST /auth/logout` (authenticated)

1. All refresh tokens for the user are revoked
2. Refresh token cookie cleared
3. Audit event logged
4. Response: `{"status": "logged_out"}`

**Source:** `internal/handler/auth.go` (Logout), `internal/service/auth.go` (Logout)

### 2.6 Password Reset

**Request:** `POST /auth/password/reset`
- Always returns `200 OK` with `"If that email exists, a reset link has been sent."` (prevents enumeration)
- If user not found, a dummy Argon2id verification runs for constant timing
- Token stored hashed in cache (1-hour TTL), email sent with reset link

**Confirm:** `POST /auth/password/reset/confirm`
- Token atomically retrieved and deleted (`GetAndDelete`) -- single-use
- Password length validated
- Password history checked (last 5 hashes)
- New password hashed and stored; all refresh tokens revoked

**Source:** `internal/handler/password.go`

### 2.7 Password Change

**Endpoint:** `POST /user/password` (authenticated)

- Requires `current_password` and `new_password`
- Current password verified
- New password checked against last 5 password history entries
- All refresh tokens revoked on success (forces re-login on all devices)

**Source:** `internal/handler/password.go` (ChangePassword)

### 2.8 Email Verification

**Endpoint:** `GET /auth/verify-email?token=xxx`

- Token atomically retrieved and deleted (`GetAndDelete`)
- User's `email_verified` flag set to true
- Audit event logged

**Source:** `internal/handler/auth.go` (VerifyEmail)

### 2.9 Password Confirmation (Sensitive Operations)

**Endpoint:** `POST /auth/confirm` (authenticated)

- User submits current password
- On success, a 5-minute confirmation window is cached (`confirm:{user_id}`)
- Sensitive endpoints (TOTP setup/disable, WebAuthn register/delete, backup code generation) check for this confirmation via the `Confirmed` middleware
- Returns `403 requires_confirmation` if no recent confirmation exists

**Source:** `internal/handler/auth.go` (ConfirmPassword), `internal/middleware/auth.go` (Confirmed)

---

## 3. Token Architecture

### 3.1 Access Token (RS256 JWT)

- **Algorithm:** RS256 only (algorithm whitelist enforced at parse time)
- **Key size:** 2048-bit RSA
- **TTL:** 15 minutes (configurable via `VAULT_ACCESS_TOKEN_TTL`)
- **Claims:**
  - `iss` -- origin URL
  - `aud` -- origin URL
  - `sub` -- user ID (UUID)
  - `exp`, `nbf`, `iat` -- time bounds (expiration required)
  - `jti` -- unique token ID (UUID)
  - `roles` -- user roles array (e.g., `["user"]`)
  - `scopes` -- granted scopes (e.g., `["read", "write"]`)
  - `client_id` -- requesting client (if applicable)
  - `fingerprint` -- SHA256 hash of device fingerprint
  - `token_type` -- `"Bearer"` or `"2fa_challenge"`
  - `cnf.jkt` -- JWK thumbprint for DPoP binding (if DPoP enabled)
- **Max size:** 8KB enforced at parse time
- **Dangerous headers rejected:** `jku`, `x5u`, `x5c`, `jwk` -- rejected at parse time
- **`kid` validation:** UUID format only (hex + dashes, max 64 chars), prevents path traversal

**Source:** `internal/crypto/jwt.go`

### 3.2 Refresh Token

- **Format:** 32-byte cryptographically random token (base64url encoded)
- **TTL:** 7 days (production), 24 hours (dev), 30 days (remember me) -- configurable
- **Storage:** SHA-256 hash in PostgreSQL, never stored in plaintext
- **Single-use:** each use issues a new pair, old token marked `used = true`
- **Family tracking:** each token belongs to a `family_id` (UUID). Replay of a used token revokes the entire family.
- **Session limit:** new family creation is blocked when a user has `VAULT_MAX_SESSIONS_PER_USER` (default 10) active families. Returns `429 too_many_sessions`. Fails open if the count query errors.
- **Bound to device:** fingerprint hash stored alongside the token
- **Cookie attributes:** `__Host-refresh_token`; `HttpOnly; Secure; SameSite=Strict; Path=/`
- **Secure flag:** derived from `TLSEnabled` config, not profile name

**Source:** `internal/service/token.go`, `internal/handler/auth.go`

### 3.3 2FA Challenge Token

- **Purpose:** Short-lived JWT issued after successful password verification when MFA is required
- **TTL:** 5 minutes
- **Token type claim:** `"2fa_challenge"`
- **Accepted by:** endpoints using `AuthChallenge` middleware (TOTP verify, WebAuthn verify begin/finish)
- **Not accepted by:** standard `Auth` middleware (prevents using challenge tokens for normal API access)
- **On successful 2FA verification:** exchanged for real access + refresh token pair

**Source:** `internal/service/token.go` (IssueChallengeToken)

### 3.4 JWKS Key Rotation

- **Endpoint:** `GET /.well-known/jwks.json` (public, cached 1 hour)
- **Key format:** JWK with `kty=RSA`, `use=sig`, `alg=RS256`, `kid` identifier
- **`kid` in JWT header** identifies which key signed the token
- **Key generation:** `crypto/rand` source, 2048-bit RSA
- **Old keys remain** in JWKS for validation of existing tokens until they expire
- **Signing key update:** thread-safe via `sync.RWMutex` in `TokenService`
- **`kid` derivation:** deterministic, computed as SHA-256 of the public key modulus

**Mode 1: File-Based (Default)**
- If `SIGNING_KEY_FILE` is set: RSA-2048 key loaded from PKCS#8 PEM file. Shared across all pods for horizontal scaling. Tokens survive pod restarts.
- If not set (fallback): ephemeral key generated at startup. Tokens invalidated on restart. Multi-pod deployments will fail (each pod signs with a different key).
- Key rotation via `TokenService.UpdateSigningKey()` or restart

**Mode 2: DB-Backed (`VAULT_KEY_ROTATION_DB=true`)**
- Keys stored in `auth.signing_keys` table, encrypted at rest with AES-256-GCM (master key), `kid` as AAD
- Unique partial index enforces exactly one `active` key at a time
- All pods refresh from DB every `VAULT_KEY_REFRESH_INTERVAL` (default 60s) -- automatic multi-pod coordination
- On first boot: imports `SIGNING_KEY_FILE` if present, otherwise generates new RSA-2048 key
- Rotation: `POST /admin/keys/rotate` generates new key, retires old one in a single transaction
- Retired keys remain in JWKS until `VAULT_KEY_RETENTION_PERIOD` (default 1h) -- zero-downtime rotation
- Revocation: `DELETE /admin/keys/{kid}` immediately removes key from JWKS; tokens signed with it fail validation
- `OnKeyChange` callback updates `TokenService` signing key and `WellKnownHandler` JWKS

**Source:** `internal/crypto/jwt.go` (SerializeJWKS, KIDFromPublicKey), `internal/handler/wellknown.go`, `internal/keystore/keystore.go`

---

## 4. Multi-Factor Authentication

### 4.1 TOTP (RFC 6238)

**Setup:** `POST /auth/2fa/totp/setup` (authenticated + confirmed)
- Generates 20-byte secret (base32-encoded)
- Secret encrypted with AES-256-GCM using master key before storage (user ID as AAD)
- Returns `secret` and `otp_url` (otpauth:// URI for QR code generation)
- Previous unverified setups are deleted

**Verify:** `POST /auth/2fa/totp/verify` (authenticated or challenge)
- 6-digit code validated with +/-1 period skew (30-second periods)
- Constant-time comparison (`crypto/subtle`)
- TOTP replay prevention: `last_totp_counter` stored per-user in DB -- replayed codes (same or earlier counter) rejected. Returns HTTP 429 `totp_code_already_used`
- If verifying during login (challenge token): issues real access + refresh tokens
- If first-time verification: marks TOTP as verified

**Disable:** `DELETE /auth/2fa/totp` (authenticated + confirmed)
- Requires recent password confirmation
- Deletes TOTP secret from database

**Implementation:** Hand-rolled RFC 6238 (~80 lines), HMAC-SHA1 per spec.

**Source:** `internal/crypto/totp.go`, `internal/handler/totp.go`

### 4.2 WebAuthn/FIDO2

Implemented via `go-webauthn/webauthn` library (v0.15.0).

**Register Begin:** `POST /auth/2fa/webauthn/register/begin` (authenticated + confirmed)
- Returns WebAuthn creation options
- Session data cached (5-minute TTL)

**Register Finish:** `POST /auth/2fa/webauthn/register/finish` (authenticated + confirmed)
- Validates attestation response
- Session data atomically consumed (`GetAndDelete`) to prevent reuse race conditions
- Stores credential ID, public key, sign count in database
- Multiple credentials per user supported

**Verify Begin:** `POST /auth/2fa/webauthn/verify/begin` (authenticated or challenge)
- Returns assertion options
- Session data cached (5-minute TTL)

**Verify Finish:** `POST /auth/2fa/webauthn/verify/finish` (authenticated or challenge)
- Validates assertion response
- Session data atomically consumed (`GetAndDelete`)
- Sign count updated (clone detection)
- If challenge token: issues real tokens

**List Credentials:** `GET /auth/2fa/webauthn/credentials` (authenticated)
**Delete Credential:** `DELETE /auth/2fa/webauthn/credentials/{id}` (authenticated + confirmed)

**Behavior when not configured:** Returns `501 Not Implemented` with `webauthn_not_configured` if WebAuthn initialization fails (e.g., missing origin config).

**Source:** `internal/handler/webauthn.go`

### 4.3 Backup Codes

**Generate:** `POST /auth/2fa/backup-codes` (authenticated + confirmed)
- Generates 10 single-use codes (16 hex chars each, 64-bit entropy)
- Each code hashed with HMAC-SHA256 before storage (high-entropy codes make Argon2id unnecessary; avoids 10× Argon2id cost on generation)
- Previous codes are deleted
- Codes shown once and never displayed again

**Verify:** `POST /auth/2fa/backup-code/verify` (authenticated or challenge)
- 6-digit backup code submitted
- Constant-time HMAC comparison against stored hashes
- Single-use: atomically marked as used (CAS)
- If challenge token: completes MFA login (issues real tokens)

**Source:** `internal/handler/backup_codes.go`

### 4.4 MFA Policy and Status

**Status:** `GET /auth/2fa/status` (authenticated)
- Returns: `totp_enabled`, `webauthn_enabled`, `backup_codes_remaining`, `available_methods`, `mfa_required`

**Policy:**
- MFA is required at login if the user has any verified 2FA method configured
- `VAULT_MFA_REQUIRED` (default: `true`) forces all users to set up MFA
- Trusted devices can skip MFA (within trust window, checked via `RequiresMFA`)

**Source:** `internal/service/mfa.go`, `internal/handler/mfa.go`

### 4.5 Email OTP (Fallback)

When `VAULT_MFA_REQUIRED=true` but a user has no configured 2FA methods (no TOTP, no WebAuthn, no backup codes), the system falls back to email OTP:

**Verify:** `POST /auth/2fa/email-otp/verify` (authenticated or challenge)
- 6-digit numeric code sent to user's verified email address
- Code cached with 10-minute TTL, single-use (`GetAndDelete`)
- Shares the TOTP rate limiter (5 attempts / 5 min / IP)

**Resend:** `POST /auth/2fa/email-otp/resend` (authenticated or challenge)
- Re-sends the email OTP code
- Shares the TOTP rate limiter

**Template:** `email_otp` -- renders the 6-digit code with app branding.

**Source:** `internal/handler/email_otp.go`

---

## 5. Device Fingerprinting

### 5.1 Composition

```
fingerprint = SHA256(length_prefix(IP) + length_prefix(User-Agent) + length_prefix(Accept-Language) + length_prefix(TLS-fingerprint))

The TLS-fingerprint field is populated from the header specified by VAULT_TLS_FINGERPRINT_HEADER
(e.g. "X-TLS-Fingerprint"). The TLS-terminating proxy (nginx-ingress, Cloudflare, etc.) must
extract the JA4 fingerprint during the TLS handshake and pass it as a header. When the header
is not configured, the field is empty (backward compatible with existing fingerprints).
```

Length-prefixed fields (4-byte big-endian length + data) prevent separator collision attacks.

**Source:** `internal/crypto/fingerprint.go`

### 5.2 Verification

- Every authenticated request: fingerprint recomputed from request headers, compared to JWT `fingerprint` claim
- **Strict mode** (default): mismatch rejects the request with `invalid_token` (generic error to avoid revealing fingerprint enforcement)
- **Soft mode**: mismatch is logged but request is allowed (for mobile networks). Currently hardcoded to `false` (strict mode); not exposed as a config var.
- Comparison uses constant-time comparison

**Source:** `internal/middleware/fingerprint.go`

### 5.3 Device Registry

- Each user has a list of known devices (friendly name, IP, user agent, last seen, trusted flag (fingerprint hash and first_seen_at are not exposed in the API response))
- New devices auto-created on login (friendly name auto-generated from user agent)
- Users can:
  - List devices: `GET /user/devices`
  - Rename devices: `PATCH /user/devices/{id}`
  - Delete devices: `DELETE /user/devices/{id}` (also revokes associated refresh tokens)
- Fingerprint hash is not exposed in device API responses (removed per security review N-2)

**Source:** `internal/handler/user.go`, `internal/repository/repository.go` (DeviceRepository)

---

## 6. Client Authentication

### 6.1 Client Registration

Clients are registered via CLI commands, the admin gateway API, or declarative seed files. There is no public API endpoint for client creation.

**CLI:**
```
vault42 add-client --admin-token <token> --name "frontend" --role "frontend" --scopes "user:read,user:write"
```

**Declarative seeding (JSON):**
```
VAULT_SEED_FILE=/etc/vault42/seed.json
```
Or via CLI: `vault42 seed --admin-token <token> --file seed.json`

Seed files define clients and users declaratively. Seeding is idempotent -- existing entries (matched by client name) are skipped. Client secrets are always generated (never in the seed file) and printed to stdout. See `seed.example.json` for the file format.

- Generates UUID `client_id` and high-entropy random secret (64 hex chars)
- Secret displayed once, only the Argon2id hash is stored
- Secret cannot be retrieved later

**Source:** `internal/cli/cli.go` (addClient), `internal/seed/seed.go` (declarative seeding)

### 6.2 Client Credentials Grant

**Endpoint:** `POST /client/token`

- Authentication: HTTP Basic Auth (`client_id:client_secret`) or form body
- Secret verified against stored Argon2id hash
- If client not found, a dummy hash computation runs (timing attack prevention)
- If client found but inactive, password still verified before returning error (prevents timing-based enumeration of revoked clients)
- Requested scopes intersected with client's allowed scopes
- Returns access token with client's role and granted scopes

**Source:** `internal/handler/client.go`

### 6.3 Client Management

All commands require `--admin-token`:

| Command | Purpose |
|---------|---------|
| `add-client` | Register new service client |
| `list-clients` | List all registered clients |
| `revoke-client` | Deactivate a client |
| `rotate-client-secret` | Issue new secret, invalidate old |
| `lock-user` | Lock a user account (1 year) |
| `unlock-user` | Unlock a user account |
| `revoke-all-sessions` | Revoke all refresh tokens system-wide |
| `rotate-admin-token` | Rotate the admin token itself |
| `rotate-jwks` | Rotate the JWKS signing key |
| `seed` | Declarative client + user creation from JSON file |
| `cleanup-audit` | Delete audit entries older than N days |
| `export-audit` | Export audit log entries as JSONL to stdout |

**Admin token lifecycle:**
1. Generated on first boot (256-bit random), displayed once to stdout
2. Stored as Argon2id hash in `auth.admin_config` table
3. Verified with `VerifyPassword` (Argon2id) on every CLI command

**Source:** `internal/cli/cli.go`

### 6.4 KMS Envelope-Unwrap Oracle

**Endpoint:** `POST /kms/unwrap` (mounted only when `KMS_ROOT_KEY_FILE` is configured)

A KEK envelope-unwrap oracle: a caller presents a wrapped-key envelope and vault42 returns the unwrapped key while holding the Key-Encryption-Key itself and never releasing it. Backs the life42 vault re-root.

- **Key derivation:** per-`kid` KEKs are derived from a single KMS root secret (`KMS_ROOT_KEY_FILE`, >= 32 bytes) via HKDF-SHA256 with a versioned, domain-separated info label (`vault42/kms/kek/v1/<kid>`). This keeps the KMS keyspace cryptographically separate from the master key that encrypts TOTP/identity/blob at rest, and supports rotation without provisioning a new secret per kid.
- **Envelope format:** `nonce || AES-256-GCM ciphertext`, with `kid` bound as GCM AAD, base64 (std) on the wire. Reuses `internal/crypto` AEAD; no new crypto.
- **Authorization:** requires a client-credential access token carrying the `kms:unwrap` scope (`middleware.RequireScope`). When `VAULT_DPOP_ENABLED=true`, a fresh single-use DPoP proof is also required (anti-replay).
- **Oracle resistance:** every failure mode (empty kid, malformed envelope, bad base64, tampered ciphertext, wrong KEK) collapses to a single opaque `400 unwrap_failed` with a byte-identical body and audit outcome. No branch reveals which check failed.
- **Rate limiting:** per-IP, fail-closed (a cache/Redis outage rejects with 503 rather than degrading to a weaker per-pod limiter).
- **Audit:** every attempt is written synchronously (never dropped under buffer pressure), recording `kid` and outcome only. Key material is never logged, and KEKs plus the root secret are wiped after use.
- **Tooling:** `vault kms wrap` produces envelopes the oracle accepts.

**Source:** `internal/kms/kms.go`, `internal/handler/kms.go`, `internal/server/server.go`, `cmd/vault/kms.go`

---

## 7. User Management

### 7.1 Profile

**Read:** `GET /user/profile` (authenticated)

Returns: `id`, `email`, `email_verified`, `display_name`, `locale`, `mfa_required`, `mfa_enabled`, `mfa_methods`, `created_at`

**Update:** `PUT /user/profile` (authenticated)

Accepts partial update with pointer-field semantics (`display_name`, `avatar_url`, `locale`). Omitted fields are unchanged. Email is not updatable (requires re-verification -- deferred to v2). Returns the full updated profile.

### 7.2 Sessions

**List:** `GET /user/sessions` (authenticated)
- Returns all devices for the user with: `id`, `friendly_name`, `ip`, `user_agent`, `trusted`, `last_seen_at`, `first_seen_at`

**Revoke:** `DELETE /user/sessions/{id}` (authenticated)
- Verifies device belongs to user
- Revokes all refresh tokens for the device, then deletes the device

**Revoke All:** `DELETE /user/sessions` (authenticated)
- Revokes all refresh tokens for the user
- Deletes all device records

### 7.3 Devices

**List:** `GET /user/devices` (authenticated)
**Rename:** `PATCH /user/devices/{id}` (authenticated)
- Friendly name max 100 runes, control characters rejected
**Delete:** `DELETE /user/devices/{id}` (authenticated)
- Revokes associated refresh tokens before deleting

**Source:** `internal/handler/user.go`

### 7.4 Identity Store

The Identity Store provides encrypted storage for personal identity information (PII). All data is encrypted at rest with AES-256-GCM and keyed to the user via HMAC-SHA256 pseudonymous foreign keys, ensuring that even database administrators cannot associate identity data with user accounts.

**Architecture:**
- Pseudonymous key: `HMAC-SHA256(userID + ":identity", hmac_secret)` -- a different salt than blob storage, so identity and blob pseudonyms cannot be correlated
- Data encryption: JSON-serialized identity fields encrypted with AES-256-GCM using the master key
- AAD binding: pseudonym ID used as authenticated additional data (AAD) for AES-256-GCM encryption -- ciphertext bound to owner
- Single row per user in `identity.profiles` table (upsert semantics)
- Schema: `identity.profiles(pseudonym_id VARCHAR(128) PK, data_enc BYTEA, version INT, updated_at, created_at)`
- Permissions: `vault_app` role has SELECT, INSERT, UPDATE, DELETE on identity schema (DELETE required for user-initiated data removal)

**Fields:**
- `given_name` -- max 100 runes
- `family_name` -- max 100 runes
- `country` -- ISO 3166-1 alpha-2 (regex `^[A-Z]{2}$`)
- `date_of_birth` -- ISO 8601 date (`YYYY-MM-DD`), must not be in the future
- `sex` -- max 50 runes (freeform)
- `billing` -- optional sub-object:
  - `address_line_1`, `address_line_2` -- max 200 runes each
  - `city` -- max 100 runes
  - `postal_code` -- max 20 runes
  - `country` -- ISO 3166-1 alpha-2
  - `vat_id` -- max 50 runes

**Endpoints:**
- `GET /user/identity` -- retrieve decrypted identity (404 if none set)
- `PUT /user/identity` -- upsert identity (create or replace)
- `DELETE /user/identity` -- permanently delete identity data

**Audit events:** `identity_read`, `identity_write`, `identity_delete`

**Source:** `internal/handler/identity.go`, `internal/service/identity.go`

### 7.5 Encrypted Blob Storage

Encrypted blob storage allows users to upload, download, and manage encrypted files. Blobs are compressed with DEFLATE, encrypted with AES-256-GCM, and stored in PostgreSQL. Labels are encrypted separately to allow metadata listing without full decryption of blob data.

**Architecture:**
- Pseudonymous key: `HMAC-SHA256(userID + ":objects", hmac_secret)` -- different salt from identity store
- Pipeline: raw data → DEFLATE compression → AES-256-GCM encryption → PostgreSQL BYTEA
- Labels encrypted separately with AES-256-GCM
- Checksum: `sha256:<hex>` of original (uncompressed, unencrypted) data
- Schema: `objects.blobs(id UUID PK, pseudonym_id VARCHAR(128), ref_hash VARCHAR(128), label_enc BYTEA, data_enc BYTEA, size_bytes INT, stored_bytes INT, checksum VARCHAR(128), created_at)`
- Named blobs: `ref_hash` is HMAC(name, secret) -- allows lookup by name without storing plaintext. UNIQUE index on `(pseudonym_id, ref_hash) WHERE ref_hash IS NOT NULL`
- Immutability: database trigger prevents UPDATE -- blobs can only be created and deleted
- Permissions: `vault_app` role has SELECT, INSERT, DELETE (no UPDATE)
- **AAD binding:** Data encryption uses `id + ":" + pseudonym` as AAD; label encryption uses `"label:" + id + ":" + pseudonym` as AAD -- ciphertext is bound to specific blob and owner
- **Decompression bomb protection:** Download decompression capped at 10 MB (`io.LimitReader`)

**Quota enforcement:**
- Per-user file count limit: `VAULT_BLOB_MAX_PER_USER` (default: 50)
- Per-user total storage limit: `VAULT_BLOB_QUOTA_BYTES` (default: 10 MB)
- Minimum blob size: `VAULT_BLOB_MIN_SIZE` (default: 0, disabled -- empty blobs are still rejected)
- Maximum single blob size: `VAULT_BLOB_MAX_SIZE` (default: 10 MB)
- Setting `VAULT_BLOB_QUOTA_BYTES=0` disables the blob storage feature entirely (routes are not registered)
- Quota checked before compression/encryption to fail fast

**Upload methods:**
- Raw binary body with `X-Blob-Label` header
- Multipart form data with `file` field and optional `label` field

**Endpoints:**
- `POST /user/blobs` -- upload a blob (returns metadata with id, size, checksum)
- `GET /user/blobs` -- list blobs with metadata and quota info
- `GET /user/blobs/{id}` -- download decrypted blob (returns `application/octet-stream`)
- `DELETE /user/blobs/{id}` -- permanently delete a blob
- `PUT /user/blobs/named/{name}` -- create or replace a named blob (upsert by name)
- `GET /user/blobs/named/{name}` -- download a blob by name
- `DELETE /user/blobs/named/{name}` -- delete a blob by name

**Named blobs:** Addressed by a human-readable name (e.g. `session-data`) instead of UUID. The name is stored as HMAC hash -- the plaintext name never persists to the database. PUT replaces any existing blob with the same name (atomic delete + insert, preserving the immutability trigger). Names must match `[a-zA-Z0-9_-]+` (max 255 chars).

**Response headers on download:** `Content-Type: application/octet-stream`, `X-Blob-Checksum`, `X-Blob-Label` (if set)

**Audit events:** `blob_upload`, `blob_upload_named`, `blob_download`, `blob_download_named`, `blob_delete`, `blob_delete_named`

**Source:** `internal/handler/blob.go`, `internal/service/blob.go`

---

## 8. Rate Limiting

### 8.1 Endpoint Tiers

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /auth/login` | 5 | 15 min | IP |
| `POST /auth/register` | 3 | 1 hour | IP |
| `POST /auth/refresh` | 30 | 1 min | IP |
| `POST /auth/password/reset` | 3 | 1 hour | IP |
| `POST /auth/password/reset/confirm` | 3 | 1 hour | IP |
| `POST /auth/2fa/totp/verify` | 5 | 5 min | IP |
| `POST /auth/confirm` | 5 | 15 min | user ID |
| `POST /client/token` | 10 | 1 min | IP |
| `POST /auth/2fa/backup-code/verify` | 5 | 5 min | IP |
| `POST /auth/2fa/email-otp/verify` | 5 | 5 min | IP |
| `POST /auth/2fa/email-otp/resend` | 5 | 5 min | IP |
| `GET /auth/verify-email` | 10 | 1 hour | IP |
| `POST /auth/oauth2/exchange` | 10 | 1 min | IP |
| `GET /auth/oauth2/callback/{provider}` | 5 | 15 min | IP |
| `POST /user/password` | 5 | 15 min | user ID |
| `GET /user/identity` | 30 | 1 min | IP |
| `PUT /user/identity` | 10 | 1 min | IP |
| `DELETE /user/identity` | 10 | 1 min | IP |
| `POST /user/blobs` | 10 | 1 min | IP |
| `GET /user/blobs`, `GET /user/blobs/{id}` | 30 | 1 min | IP |
| `DELETE /user/blobs/{id}` | 10 | 1 min | IP |

Rate limiting is enabled by default (`VAULT_RATE_LIMIT_ENABLED=true`). The dev profile inherits this from production and only disables it if explicitly overridden.

### 8.2 Response Headers

All rate-limited responses include:
- `X-RateLimit-Limit` -- maximum requests in window
- `X-RateLimit-Remaining` -- remaining requests
- `X-RateLimit-Reset` -- Unix timestamp when window resets

Rate-limited requests return `429 Too Many Requests` with a `Retry-After` header.

### 8.3 Cache Backend

Rate limit counters use the cache interface (`Increment` with TTL). If the cache is unreachable, the rate limiter falls back to an in-memory counter (`localRateLimiter` with `sync.Mutex` + map). Auth never fails because cache is down, but rate limits remain enforced via the in-memory fallback.

**Source:** `internal/middleware/ratelimit.go`

---

## 9. Audit Logging

### 9.1 Events

| Event | Constant | Description |
|-------|----------|-------------|
| `login_success` | `LoginSuccess` | Successful user authentication |
| `login_failure` | `LoginFailure` | Failed login attempt |
| `registration` | `Registration` | New user account creation |
| `token_refresh` | `TokenRefresh` | Refresh token exchange |
| `token_revoke` | `TokenRevoke` | Token revocation (logout, replay) |
| `password_change` | `PasswordChange` | User-initiated password change |
| `password_reset` | `PasswordReset` | Password reset via email |
| `2fa_setup` | `TwoFASetup` | TOTP or WebAuthn enrollment |
| `2fa_verify` | `TwoFAVerify` | 2FA verification attempt |
| `device_trust` | `DeviceTrust` | Device trust change |
| `session_revoke` | `SessionRevoke` | Session revocation |
| `client_auth` | `ClientAuth` | Client credentials grant |
| `rate_limit` | `RateLimit` | Rate limit triggered |
| `fingerprint_anomaly` | `FingerprintAnomaly` | Fingerprint mismatch on refresh |
| `oauth2_authorize` | `OAuth2Authorize` | OAuth2 redirect initiated |
| `oauth2_callback` | `OAuth2Callback` | OAuth2 callback processed |
| `admin_action` | `AdminAction` | CLI admin operation |
| `honeypot_trigger` | `HoneypotTrigger` | Trap credential used in honeypot mode |
| `honeypot_alert` | `HoneypotAlert` | Webhook alert dispatched in honeypot mode |
| `admin_login` | `AdminLogin` | Admin gateway login success |
| `admin_login_failure` | `AdminLoginFailure` | Admin gateway login failure |
| `admin_logout` | `AdminLogout` | Admin gateway logout |
| `admin_session_revoke` | `AdminSessionRevoke` | Admin session revoked |
| `admin_user_lock` | `AdminUserLock` | User locked by admin |
| `admin_user_unlock` | `AdminUserUnlock` | User unlocked by admin |
| `admin_user_delete` | `AdminUserDelete` | User deleted by admin |
| `admin_key_rotate` | `AdminKeyRotate` | Signing key rotated |
| `admin_key_revoke` | `AdminKeyRevoke` | Signing key revoked |
| `admin_client_create` | `AdminClientCreate` | Service client created |
| `admin_client_revoke` | `AdminClientRevoke` | Service client revoked |
| `admin_client_rotate` | `AdminClientRotate` | Client secret rotated |
| `admin_config_change` | `AdminConfigChange` | Configuration changed |
| `admin_account_create` | `AdminAccountCreate` | Admin account created |
| `admin_account_revoke` | `AdminAccountRevoke` | Admin account revoked |
| `admin_lockout` | `AdminLockout` | Admin account locked out |

### 9.2 Schema

Each audit entry contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique entry ID |
| `timestamp` | TIMESTAMPTZ | Event time |
| `event_type` | VARCHAR(100) | Event type constant |
| `user_id` | UUID | Associated user (nullable) |
| `client_id` | UUID | Associated client (nullable) |
| `ip` | VARCHAR(45) | Client IP address |
| `user_agent` | VARCHAR(1024) | User-Agent header |
| `fingerprint_hash` | VARCHAR(128) | Device fingerprint hash |
| `device_id` | UUID | Associated device (nullable) |
| `metadata` | JSONB | Event-specific data |
| `risk_score` | INTEGER | Risk assessment (0-100) |

### 9.3 Security

- **Append-only:** PostgreSQL triggers (`BEFORE UPDATE`, `BEFORE DELETE`) raise exceptions on `audit.audit_log`
- **Database role enforcement:** `vault_app` has only `INSERT` and `SELECT` on the audit schema
- **Sensitive data scrubbing:** metadata keys matching `password`, `secret`, `token`, `access_token`, `refresh_token`, `code`, `totp_secret`, `backup_code`, `master_key`, `client_secret`, `api_key` are automatically stripped before storage
- **Batching:** configurable via `VAULT_AUDIT_FLUSH_INTERVAL`; when set, entries are buffered in memory and flushed periodically
- **Buffer overflow protection:** configurable buffer size (`VAULT_AUDIT_BUFFER_SIZE`, default 1000). When the buffer is full, critical events (`login_failure`, `admin_login_failure`, `admin_lockout`) bypass the buffer and write synchronously. Dropped events are counted and logged.

**Source:** `internal/audit/audit.go`

---

## 10. Email

### 10.1 Templates

| Template | Purpose |
|----------|---------|
| `verification` | Email verification after registration (24h link) |
| `password_reset` | Password reset link (1h expiry) |
| `new_device` | New device login notification (IP + device info) |
| `account_locked` | Account locked due to failed login attempts |
| `2fa_setup` | 2FA enabled confirmation |
| `suspicious_activity` | Suspicious activity alert |
| `email_otp` | Email OTP code for 2FA fallback |

All templates render subject, HTML body, and plain-text body.

### 10.1.1 Template Engine

Templates are HTML files embedded into the Go binary via `go:embed`. A shared base layout (`templates/base.html`) wraps each content template, providing consistent branding (app name, logo URL, primary color) across all emails.

**Override mechanism:** Custom templates can be loaded from a filesystem directory (`VAULT_EMAIL_TEMPLATES_DIR`). Override files are matched by filename (e.g., `verification.html` replaces the embedded verification template). Only the specified templates are overridden; the rest fall back to embedded defaults.

**Security validation:** All custom templates are scanned for forbidden patterns before loading. Templates containing `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form action=...>`, `javascript:` URIs, `on*=` event handlers, or Go template `call`/`js` directives are rejected with an error. The safe function map exposes only `safeURL`, `upper`, `lower`, and `truncate`.

**Source:** `internal/email/templates.go`

### 10.2 Providers

Interface: `email.Sender` with a single method `Send(ctx context.Context, to, subject, htmlBody, textBody string) error`.

**Built-in adapters:**
- **SMTP** -- configured via `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER_FILE`, `SMTP_PASS_FILE`
- **SendGrid** -- configured via `VAULT_EMAIL_PROVIDER=sendgrid`

**Development:** Helm chart includes optional Mailpit deployment for email testing.

**Source:** `internal/email/email.go`

---

## 11. Cache Layer

### 11.1 Interface

```go
type Cache interface {
    Get(ctx, key) (string, error)
    Set(ctx, key, value, ttl) error
    SetIfNotExists(ctx, key, value, ttl) (bool, error)  // atomic set-if-absent
    Delete(ctx, key) error
    GetAndDelete(ctx, key) (string, error)  // atomic get+delete
    Increment(ctx, key, ttl) (int64, error) // atomic counter
    Exists(ctx, key) (bool, error)
    Close() error
}
```

**Source:** `internal/cache/cache.go`

### 11.2 Backends

| Backend | Config | Use Case |
|---------|--------|----------|
| Redis | `CACHE_BACKEND=redis` | Production -- sub-ms, atomic ops, auto-expiry |
| In-memory | `CACHE_BACKEND=memory` | Dev/embedded -- `sync.RWMutex` + `map[string]memEntry` + expiry goroutine |
| PostgreSQL | `CACHE_BACKEND=postgres` | Fallback -- uses `auth.cache` table |

### 11.3 Degradation

Cache failures are non-fatal. Rate limiting, TOTP replay prevention, and MFA challenge storage degrade gracefully -- auth never fails because cache is down.

---

## 12. Database

### 12.1 Schema

Four schemas: `auth` (user data), `audit` (append-only logs), `identity` (encrypted PII), and `objects` (encrypted blob storage).

**Tables in `auth` schema:**

| Table | Purpose |
|-------|---------|
| `users` | User accounts (email, password hash, display name, locale, MFA flags, lock state) |
| `password_history` | Previous password hashes for reuse prevention |
| `social_accounts` | Linked OAuth providers (encrypted access/refresh tokens) |
| `clients` | Registered service clients (Argon2id-hashed secrets, roles, scopes) |
| `refresh_tokens` | Stored refresh tokens (SHA-256 hashed, family ID, device binding) |
| `devices` | Known devices/fingerprints per user |
| `totp_secrets` | AES-256-GCM encrypted TOTP secrets |
| `webauthn_credentials` | WebAuthn credential IDs, public keys, sign counts |
| `backup_codes` | HMAC-SHA256-hashed single-use backup codes |
| `rate_limits` | Rate limit counters (PostgreSQL cache fallback) |
| `admin_config` | Key-value admin settings (admin token hash) |
| `signing_keys` | Encrypted signing keys (AES-256-GCM private key, DER public key, status lifecycle) |
| `admin_roles` | RBAC admin roles reference table (`viewer`, `operator`, `super_admin`) |
| `admin_users` | Admin gateway accounts (Argon2id password, TOTP, role FK, lockout tracking) |
| `admin_sessions` | Admin gateway sessions (SHA256 token hash, CASCADE delete on admin revoke) |
| `cache` | Key-value cache with TTL (PostgreSQL cache backend) |

**Tables in `audit` schema:**

| Table | Purpose |
|-------|---------|
| `audit_log` | Append-only security event log (triggers prevent UPDATE/DELETE) |

**Table in `identity` schema:**

| Table | Purpose |
|-------|---------|
| `profiles` | Encrypted PII (pseudonymous key, AES-256-GCM encrypted JSON, version tracking) |

**Table in `objects` schema:**

| Table | Purpose |
|-------|---------|
| `blobs` | Encrypted files (pseudonymous key, compressed+encrypted data, immutable via trigger) |

**Source:** `migrations/001_initial_schema.sql`

### 12.2 Roles

- **`vault_mig`:** DDL privileges, used only at startup for migrations, then connection closed
- **`vault_app`:** `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `auth` schema; `INSERT`, `SELECT` only on `audit` schema; `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `identity` schema; `SELECT`, `INSERT`, `DELETE` on `objects` schema (no UPDATE -- enforced by trigger); NO `TRUNCATE`, NO DDL
- **`vault_admin`:** Full CRUD on admin tables, read/update on user tables, full on clients + config, read + append on audit
- All schemas, tables, indexes, and role grants are defined in `migrations/001_initial_schema.sql`

### 12.3 Migrations

Hand-rolled SQL migration runner (~90 lines). Reads `migrations/*.sql` sorted by filename, executes each migration in its own transaction. Auto-migration enabled by default in dev and embedded profiles.

**Source:** `internal/migrate/`

---

## 13. Security Mitigations

### 13.1 JWT Attacks

| Attack | Mitigation |
|--------|-----------|
| `alg: none` | Algorithm whitelist -- only RS256 accepted |
| RS256-to-HS256 confusion | Asymmetric keys only, HMAC verification disabled |
| `kid` injection / path traversal | `kid` is UUID-safe only (hex + dashes), max 64 chars |
| `jku` / `x5u` / `x5c` / `jwk` header manipulation | Rejected by `ParseAndValidate` wrapper in `internal/crypto/jwt.go` (core parser in `internal/jwt/` does not reject these) |
| Token replay (access) | Short expiry (15 min) + fingerprint binding |
| Token replay (refresh) | Single-use + family tracking (replay = nuke family) + fingerprint |
| Token sidejacking | Fingerprint binding, HttpOnly/Secure/SameSite=Strict cookies |
| Nested JWT | Not explicitly rejected. Nested JWTs fail signature validation naturally due to structure mismatch. |
| Claim validation bypass | All claims validated: iss, aud, exp, nbf, iat |
| JWKS endpoint poisoning | JWKS served from local key store |
| JWT size DoS | Max 8KB enforced at parsing |

### 13.2 OAuth2 Attacks

| Attack | Mitigation |
|--------|-----------|
| CSRF on OAuth flow | HMAC-signed state parameter with expiry |
| Authorization code interception | PKCE S256 enforced on all providers (Google, GitHub, Facebook) |
| Open redirect | Redirect to origin only (fixed) |
| Account takeover via social | Both OAuth email verified AND existing account verified required for linking |

### 13.3 General Auth Attacks

| Attack | Mitigation |
|--------|-----------|
| Brute force (password) | Rate limiting (5/15min) + failed login counter |
| Brute force (TOTP) | Rate limiting (5/5min) + code replay prevention |
| Credential stuffing | IP-based rate limiting + HIBP breach check |
| Session fixation | New family ID on every login |
| Session hijacking | Fingerprint binding + secure cookie flags |
| CSRF | SameSite=Strict cookies |
| XSS token theft | HttpOnly cookies, CSP `default-src 'none'; frame-ancestors 'none'` |
| Timing attacks | Constant-time comparison for all secret/hash comparisons |
| User enumeration | Identical responses for "not found" and "wrong password"; dummy Argon2id burn |
| Email enumeration | `"If that email exists, a reset link has been sent."` -- same response always |
| Insecure password reset | Token is single-use (GetAndDelete), time-limited, stored hashed |
| Clickjacking | `X-Frame-Options: DENY` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Information disclosure | `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| Argon2id resource exhaustion | Counting semaphore (max 4 concurrent), `503 server_busy` load-shedding |
| IP-based lockout | 20 failures per IP = 15-minute IP lockout (cache + DB fallback) |
| Decompression bomb | 10 MB decompression limit on blob downloads |

### 13.4 Argon2id Concurrency Control

Each Argon2id operation allocates 46 MiB of memory. Without concurrency control, a burst of authentication requests can exhaust memory and crash the process. Vault42 enforces a counting semaphore (buffered channel) that limits concurrent Argon2id operations to 4, capping peak Argon2id memory at 184 MiB.

- **Semaphore capacity:** 4 concurrent operations
- **Acquisition timeout:** 5 seconds -- if the semaphore cannot be acquired within this window, the operation returns `ErrArgon2Overloaded`
- **Affected functions:** `HashPassword` and `VerifyPassword` both acquire the semaphore before computing
- **HTTP response:** Handlers that call password hashing/verification (`/auth/register`, `/auth/login`, `/auth/confirm`, `/user/password`, `/auth/password/reset/confirm`) return `503 server_busy` when the semaphore is full
- **Anti-enumeration under load:** Dummy hash paths (user-not-found, inactive client, etc.) propagate `ErrArgon2Overloaded` instead of discarding it. Both existing-user and non-existing-user paths return 503 when the semaphore is full, preventing status-code-based user enumeration.
- **Observability:** Atomic counters track active operations and rejected requests. Exported via `Argon2ActiveCount()`, `Argon2RejectedCount()`, `Argon2MaxConcurrent()` for Prometheus metrics.

This is load-shedding (backpressure), not a server error. The HPA can use `vault_argon2_active` / `vault_argon2_rejected_total` Prometheus metrics for responsive scaling.

**Source:** `internal/crypto/argon2.go`

---

## 14. Configuration

### 14.1 Environment Variables

**Core:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_PROFILE` | `production` | Deployment profile |
| `LISTEN_ADDR` | `:8443` | Listen address |
| `VAULT_ORIGIN` | (required) | Public-facing URL |
| `LOG_LEVEL` | `warn` (prod) / `debug` (dev) | Log verbosity |
| `VAULT_TLS_ENABLED` | `true` | Enable HTTPS |
| `VAULT_TLS_CERT_FILE` | (optional) | TLS certificate PEM path |
| `VAULT_TLS_KEY_FILE` | (optional) | TLS private key PEM path |

**Database:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL hostname |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `vault` | Database name |
| `DB_SSLMODE` | `require` | SSL mode (forced `disable` in dev) |
| `DB_MAX_CONNS` | `25` (prod) / `5` (embedded) | Max connections |

**Cache:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_BACKEND` | `redis` (prod) / `memory` (embedded) | Cache implementation |
| `REDIS_ADDR` | (optional) | Redis address |

**Tokens:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ACCESS_TOKEN_TTL` | `15m` | Access token lifetime |
| `VAULT_REFRESH_TOKEN_TTL` | `7d` (prod) / `24h` (dev/embedded) | Refresh token lifetime |
| `VAULT_REMEMBER_ME_TTL` | `30d` | Extended refresh token lifetime |

**Security:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `VAULT_PASSWORD_MIN_LENGTH` | `15` | Minimum password length (NIST) |
| `VAULT_HIBP_CHECK` | `true` | Enable HIBP breach check |
| `VAULT_MFA_REQUIRED` | `true` | Force all users to set up MFA |
| `VAULT_MAX_SESSIONS_PER_USER` | `10` | Max concurrent refresh families |
| `VAULT_DPOP_ENABLED` | `false` | Enable DPoP (Demonstration of Proof-of-Possession) middleware |
| `VAULT_FORCE_SECURE_COOKIES` | `false` | Force Secure flag on cookies regardless of TLS state |

**Email:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_EMAIL_PROVIDER` | `smtp` | Email backend (`smtp` or `sendgrid`) |
| `SMTP_HOST` | (optional) | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `VAULT_EMAIL_FROM` | (optional) | Sender address |
| `VAULT_EMAIL_TEMPLATES_DIR` | (optional) | Directory for custom email template overrides |

**OAuth2:**

| Variable | Description |
|----------|-------------|
| `VAULT_OAUTH_GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `VAULT_OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth2 client ID |
| `VAULT_OAUTH_FACEBOOK_CLIENT_ID` | Facebook OAuth2 client ID |

**Blob Storage:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_BLOB_MIN_SIZE` | `0` (disabled) | Minimum blob size in bytes (0 = no minimum, empty blobs still rejected) |
| `VAULT_BLOB_MAX_SIZE` | `10485760` (10 MB) | Maximum single blob size in bytes |
| `VAULT_BLOB_MAX_PER_USER` | `50` | Maximum number of blobs per user |
| `VAULT_BLOB_QUOTA_BYTES` | `10485760` (10 MB) | Total storage quota per user (0 = disable feature) |

**Metrics:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_METRICS_ENABLED` | `false` | Enable Prometheus-compatible `/metrics` endpoint |

**Seeding:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_SEED_FILE` | (none) | Path to JSON seed file for declarative client/user creation at startup |

**Key Rotation:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_KEY_ROTATION_DB` | `false` | Enable DB-backed keystore (false = file-based) |
| `VAULT_KEY_RETENTION_PERIOD` | `1h` | How long retired keys remain in JWKS after rotation |
| `VAULT_KEY_REFRESH_INTERVAL` | `60s` | How often pods refresh keys from the database |

**Honeypot:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_HONEYPOT_WEBHOOK` | (optional) | URL to POST honeypot alerts to |
| `VAULT_HONEYPOT_TRAP_USERS` | (optional) | Comma-separated trap email addresses |
| `VAULT_SERVE_FRONTEND` | `false` | Serve embedded Vue SPA (auto-enabled in honeypot) |

**Branding:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_APP_NAME` | `Vault42` | Application display name |
| `VAULT_LOGO_URL` | (optional) | Logo URL for emails |
| `VAULT_PRIMARY_COLOR` | `#00FF42` | Primary branding color |

**Other:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_AUDIT_BUFFER_SIZE` | `1000` | Maximum audit log buffer entries before overflow |
| `CORS_ORIGINS` | (optional) | Comma-separated additional allowed origins (beyond `VAULT_ORIGIN`) |

| `CORS_ALLOW_ALL` | `false` (prod) / `true` (dev) | Allow all CORS origins |
| `TRUSTED_PROXIES` | (optional) | CIDR/IP list for X-Forwarded-For |
| `REAL_IP_HEADER` | (optional) | Proxy real-IP header (e.g. `CF-Connecting-IP`, `X-Real-IP`) |
| `IP_ALLOWLIST` | (optional) | CIDR/IP allowlist -- only matching IPs permitted |
| `IP_BLOCKLIST` | (optional) | CIDR/IP blocklist -- matching IPs denied (dynamic at runtime) |
| `GEO_IP_HEADER` | (optional) | Country code header (e.g. `CF-IPCountry`) -- empty disables geo-fencing |
| `GEO_ALLOWLIST` | (optional) | ISO 3166-1 alpha-2 country allowlist |
| `GEO_BLOCKLIST` | (optional) | ISO 3166-1 alpha-2 country blocklist (`T1` = Tor) |
| `VAULT_AUTO_MIGRATE` | `false` (prod) / `true` (dev/embedded) | Auto-migrate on startup |
| `VAULT_SHUTDOWN_TIMEOUT` | `15s` (prod) / `5s` (dev) | Graceful shutdown timeout |
| `VAULT_AUDIT_FLUSH_INTERVAL` | `0` (prod) / `30s` (embedded) | Audit log batch interval |

### 14.2 Profiles

| Setting | Production | Embedded | Dev | Honeypot |
|---------|-----------|----------|-----|---------|
| Listen address | `:8443` | `:8443` | `:8443` | `:8443` (inherited) |
| Log level | `warn` | `info` | `debug` | `debug` |
| TLS | enabled | enabled | enabled | enabled (inherited) |
| Rate limiting | enabled | enabled | enabled (inherited) | enabled (inherited) |
| Auto-migrate | disabled | enabled | enabled | enabled |
| CORS | explicit origins only | -- | allow all | explicit (inherited) |
| Access token TTL | 15m | 15m | 15m | 15m (inherited) |
| Refresh token TTL | 7d | 24h | 24h | 7d (inherited) |
| Remember Me TTL | 30d | 30d | 30d | 30d (inherited) |
| Cache backend | redis | memory | redis (inherited) | redis (inherited) |
| DB max connections | 25 | 5 | 25 (inherited) | 25 (inherited) |
| Shutdown timeout | 15s | 5s | 5s | 15s (inherited) |
| Audit flush | immediate | 30s | immediate | immediate (inherited) |
| Serve frontend | off | off | off | **enabled** |

Dev profile extends production -- it inherits all production defaults, then applies minimal overrides. TLS, rate limits, listen address, and cache backend are all inherited from production unless explicitly overridden.

Honeypot profile extends production -- it inherits all production defaults, then enables debug logging, auto-migration, and the embedded frontend. See section 14.4 for details.

### 14.3 Secret Loading (_FILE Convention)

All secrets use the `_FILE` suffix convention: the env var points to a file containing the secret, not the secret itself. After reading, the file is zeroed (defense in depth).

**Secrets loaded via `_FILE`:**

| Env Var | Secret |
|---------|--------|
| `MASTER_KEY_FILE` | AES-256 key (32 bytes) for TOTP encryption |
| `ADMIN_TOKEN_FILE` | Admin CLI token (Argon2id hash) |
| `VAULT_PEPPER_FILE` | Server-side password pepper |
| `HMAC_SECRET_FILE` | HMAC-SHA256 key (min 32 bytes in prod) |
| `DB_MIG_PASSWORD_FILE` | Migration role password |
| `DB_APP_PASSWORD_FILE` | Application role password |
| `REDIS_PASS_FILE` | Redis password |
| `SMTP_USER_FILE` | SMTP username |
| `SMTP_PASS_FILE` | SMTP password |
| `VAULT_OAUTH_GOOGLE_CLIENT_SECRET_FILE` | Google OAuth2 secret |
| `VAULT_OAUTH_GITHUB_CLIENT_SECRET_FILE` | GitHub OAuth2 secret |
| `VAULT_OAUTH_FACEBOOK_CLIENT_SECRET_FILE` | Facebook OAuth2 secret |
| `SIGNING_KEY_FILE` | RSA-2048 PKCS#8 PEM signing key (shared across pods) |
| `SENDGRID_API_KEY_FILE` | SendGrid API key |

**Source:** `internal/config/secrets.go`, `internal/config/config.go`

### 14.4 Honeypot Profile

The honeypot profile (`VAULT_PROFILE=honeypot`) is a 4th deployment profile designed for threat observation. It extends the production baseline with the following overrides:

- **Debug logging:** all requests and responses logged at debug level
- **Auto-migration:** schema migrations run automatically on startup
- **Embedded frontend:** the Vue SPA is served from the Go binary (`ServeFrontend=true`), making the deployment look like a fully operational application to attackers
- **Full request logging middleware:** wraps all handlers to log method, path, IP, status, duration, and user-agent for every request

**Trap user detection:** Configurable via `VAULT_HONEYPOT_TRAP_USERS` (comma-separated list of fake email addresses). When a login attempt matches a trap user, the honeypot alerter fires an audit event (`honeypot_trigger`) and dispatches a webhook alert.

**Webhook alerting:** `VAULT_HONEYPOT_WEBHOOK` specifies a URL to POST JSON alerts to. Each alert includes timestamp, event type, IP, user-agent, headers (with Authorization/Cookie redacted), request body (with passwords redacted), and a risk score. Webhook dispatch is best-effort with a 5-second timeout; failures are logged but do not affect request handling. Successful dispatches are recorded as `honeypot_alert` audit events.

**Fake JWT generation:** When a trap user login is detected, the system can return a realistic-looking but invalid JWT. The fake token has a valid RS256 header structure and plausible claims but a random 256-byte signature, making it useless for any real API call. A matching fake refresh token (random hex) is also generated.

**Automation detection:** User-Agent strings are checked against a list of known automated tools (curl, wget, python-requests, sqlmap, nikto, burp, etc.) and assigned elevated risk scores.

**Source:** `internal/honeypot/honeypot.go`, `internal/honeypot/fake_token.go`, `internal/config/profiles.go`

### 14.5 Embedded Frontend

The Vue SPA can be served directly from the Go binary via `go:embed`. The build process (`scripts/build-all.sh`) copies `web/dist/*` into `internal/frontend/dist/` before compilation, embedding all static assets into the binary.

**Configuration:** Controlled by `VAULT_SERVE_FRONTEND` (default: `false`). Enabled automatically in the honeypot profile. When enabled, the frontend handler serves the catch-all `/` route. API routes (`/auth/*`, `/user/*`, `/client/*`, `/.well-known/*`, `/healthz`, `/readyz`) take priority via `ServeMux` specificity.

**SPA routing:** Requests for paths that don't match a static file (JS, CSS, images) return `index.html`, enabling client-side routing.

**Source:** `internal/frontend/frontend.go`, `internal/frontend/handler.go`

---

## 15. Deployment

### 15.1 Docker Image

Multi-stage build:
1. **Builder:** `golang:1.24-alpine` -- builds static binary (`CGO_ENABLED=0`)
2. **Runtime:** `gcr.io/distroless/static-debian12:nonroot`

Properties:
- Static binary, no CGO, no dynamic linking
- Non-root user (`nonroot:nonroot`)
- Read-only root filesystem
- All capabilities dropped
- Migrations copied to `/app/migrations`
- Build args: `VERSION`, `GIT_COMMIT`, `BUILD_TIME` embedded via ldflags
- ARM64 cross-compilation uses native `GOARCH` (no QEMU)
- BuildKit cache mounts for Go module and build caches

**Source:** `Dockerfile`

### 15.2 Helm Chart

**Location:** `charts/vault42/`

Single deployment method for all environments. Templates:

| Template | Purpose |
|----------|---------|
| `deployment.yaml` | Vault42 backend (with optional TLS volume mount) |
| `service.yaml` | ClusterIP service |
| `ingress.yaml` | Split routing: API to vault42, `/` to frontend |
| `configmap.yaml` | Non-secret configuration |
| `postgres.yaml` | Optional in-cluster PostgreSQL (dev) |
| `redis.yaml` | Optional in-cluster Redis (dev) |
| `frontend.yaml` | Optional Vue frontend |
| `mailpit.yaml` | Optional dev email server |
| `init-db.yaml` | Database initialization |
| `networkpolicy.yaml` | Network isolation |
| `pdb.yaml` | PodDisruptionBudget |
| `hpa.yaml` | HorizontalPodAutoscaler |
| `serviceaccount.yaml` | Service account |
| `bridge.yaml` | Honeypot bridge proxy |
| `honeypot-postgres.yaml` | Honeypot-dedicated PostgreSQL |
| `honeypot-vault42.yaml` | Honeypot Vault42 instance |
| `admin-gateway.yaml` | Admin gateway (mTLS, RBAC) |
| `cloudflared.yaml` | Cloudflare Tunnel sidecar |
| `servicemonitor.yaml` | Prometheus ServiceMonitor |

**Values files:**
- `values.yaml` -- production defaults
- `values-dev.yaml` -- dev overlay (single replica, local images, TLS, in-cluster services)

### 15.3 Profiles

**Production (`VAULT_PROFILE=production`):**
PostgreSQL + Redis, TLS, multiple replicas, 25 DB connections, rate limits enabled.

**Embedded (`VAULT_PROFILE=embedded`):**
Target: RPi5 (4GB). In-memory cache, 5 DB connections, auto-migration, 30s audit flush. Total idle RAM ~60-80 MB.

**Dev (`VAULT_PROFILE=dev`):**
Single command: `scripts/deploy-dev.sh` handles certs (mkcert), Docker builds, namespace/secrets, `helm upgrade --install`. Access at `https://vault.localhost`.

**Honeypot (`VAULT_PROFILE=honeypot`):**
Threat observation deployment. Extends production with debug logging, auto-migration, embedded Vue frontend, full request logging, trap user detection, and webhook alerting. Designed to present a convincing attack surface while capturing attacker behavior. See section 14.4.

### 15.4 TLS

- TLS 1.3 minimum enforced when TLS is enabled
- HSTS header: `max-age=31536000; includeSubDomains; preload`
- Secure cookie flag derived from `TLSEnabled` config (not profile name)
- Dev: locally-trusted certs via `mkcert`

---

## 16. API Endpoints

### Public (No Auth)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness check |
| `GET` | `/readyz` | Readiness check (pings DB + cache) |
| `POST` | `/auth/register` | User registration |
| `POST` | `/auth/login` | User login |
| `POST` | `/auth/refresh` | Token refresh (cookie) |
| `GET` | `/auth/verify-email` | Email verification |
| `POST` | `/auth/password/reset` | Request password reset |
| `POST` | `/auth/password/reset/confirm` | Confirm password reset |
| `POST` | `/client/token` | Client credentials grant |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/auth/oauth2/authorize` | OAuth2 authorization redirect |
| `GET` | `/auth/oauth2/callback/{provider}` | OAuth2 callback |
| `POST` | `/auth/oauth2/exchange` | Exchange one-time OAuth code for tokens |
| `GET` | `/metrics` | Prometheus metrics (requires `VAULT_METRICS_ENABLED=true`) |

### Authenticated

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/auth/logout` | Bearer | Logout |
| `POST` | `/auth/confirm` | Bearer | Password confirmation (5-min window) |
| `GET` | `/user/profile` | Bearer | Get user profile |
| `GET` | `/user/sessions` | Bearer | List sessions/devices |
| `DELETE` | `/user/sessions/{id}` | Bearer | Revoke specific session |
| `DELETE` | `/user/sessions` | Bearer | Revoke all sessions |
| `GET` | `/user/devices` | Bearer | List devices |
| `PATCH` | `/user/devices/{id}` | Bearer | Rename device |
| `DELETE` | `/user/devices/{id}` | Bearer | Remove device |
| `POST` | `/user/password` | Bearer | Change password |
| `GET` | `/auth/2fa/status` | Bearer | MFA status |
| `POST` | `/auth/2fa/totp/setup` | Bearer + Confirmed | TOTP setup |
| `POST` | `/auth/2fa/totp/verify` | Bearer or Challenge | TOTP verify |
| `DELETE` | `/auth/2fa/totp` | Bearer + Confirmed | Disable TOTP |
| `POST` | `/auth/2fa/webauthn/register/begin` | Bearer + Confirmed | WebAuthn register begin |
| `POST` | `/auth/2fa/webauthn/register/finish` | Bearer + Confirmed | WebAuthn register finish |
| `POST` | `/auth/2fa/webauthn/verify/begin` | Bearer or Challenge | WebAuthn verify begin |
| `POST` | `/auth/2fa/webauthn/verify/finish` | Bearer or Challenge | WebAuthn verify finish |
| `GET` | `/auth/2fa/webauthn/credentials` | Bearer | List WebAuthn credentials |
| `DELETE` | `/auth/2fa/webauthn/credentials/{id}` | Bearer + Confirmed | Delete WebAuthn credential |
| `POST` | `/auth/2fa/backup-codes` | Bearer + Confirmed | Generate backup codes |
| `POST` | `/auth/2fa/backup-code/verify` | Bearer or Challenge | Verify backup code |
| `POST` | `/auth/2fa/email-otp/verify` | Bearer or Challenge | Verify email OTP |
| `POST` | `/auth/2fa/email-otp/resend` | Bearer or Challenge | Resend email OTP |
| `GET` | `/user/identity` | Bearer | Get identity profile |
| `PUT` | `/user/identity` | Bearer | Upsert identity profile |
| `DELETE` | `/user/identity` | Bearer | Delete identity profile |
| `POST` | `/user/blobs` | Bearer | Upload encrypted blob |
| `GET` | `/user/blobs` | Bearer | List blobs + quota |
| `GET` | `/user/blobs/{id}` | Bearer | Download decrypted blob |
| `DELETE` | `/user/blobs/{id}` | Bearer | Delete blob |

### Admin (Admin Gateway)

Key management endpoints (`/admin/keys/rotate`, `/admin/keys`, `/admin/keys/{kid}`) are served exclusively by the admin gateway (`cmd/admin-gateway/`), which provides mTLS + RBAC + session authentication with 6-layer local-only enforcement. They are not exposed on the main vault42 binary. CLI admin commands remain available via pod exec.

---

## 17. Testing Strategy

Eight layers:

1. **Unit tests** (`tests/unit/`, `internal/*/`) -- stdlib only, table-driven, covers all crypto operations
2. **Attack simulation** (`tests/attack/`) -- 208 attack vectors against real server + real PostgreSQL via testcontainers-go
3. **Compliance tests** (`tests/compliance/`) -- 157 NIST SP 800-63B and OWASP ASVS v4.0.3 verification checks
4. **Integration tests** (`tests/integration/`) -- testcontainers-based PostgreSQL + Redis integration
5. **Fuzz tests** (`tests/fuzz/`) -- Go built-in `testing.F`, 10 targets: JWT parser/header/claims/time, registration input, login input, email validator, TOTP validator, ES256 signature, kid validation
6. **Browser tests** (`tests/browser/`) -- chromedp-based, separate Go module (`tests/browser/go.mod`), 11 tests covering cookie security, XSS, CSRF, CSP, clickjacking, auth flows
7. **Frontend unit tests** (`web/src/__tests__/`) -- Vitest + Vue Test Utils, tests for IdentityView, BlobsView, AppNav, LanguageSwitcher
8. **Frontend integration** -- i18n locale switching, searchable locale picker, reactive translation updates

**CI pipeline:** `go vet` -> unit/attack/compliance -> fuzz (10 targets, 1 min each) -> gosec -> govulncheck -> trivy -> hadolint -> frontend build + test. Zero tolerance on security findings.

**Test infrastructure:**
- Integration tests use testcontainers-go (PostgreSQL module)
- Browser tests use chromedp in a separate module to keep it out of the main dependency tree
- Frontend: Vitest + Vue Test Utils for Vue component testing
- Scripts: `scripts/t.sh` (run tests), `scripts/tcount.sh` (count tests)

---

## 18. Dependencies

### Direct (3 + 1 library)

| Dependency | Version | Purpose |
|------------|---------|---------|
| `github.com/jackc/pgx/v5` | v5.8.0 | PostgreSQL driver (pure Go) |
| `github.com/go-webauthn/webauthn` | v0.15.0 | WebAuthn/FIDO2 passkeys |
| `golang.org/x/crypto` | v0.48.0 | Argon2id password hashing |

### Test-Only

| Dependency | Module | Purpose |
|------------|--------|---------|
| `testcontainers-go` | main (`go.mod`) | Integration tests (PostgreSQL + Redis containers) |
| `chromedp` | separate (`tests/browser/go.mod`) | Browser tests |

### Hand-Rolled (Replaces Common Libraries)

| What | How | Lines |
|------|-----|-------|
| HTTP router | `net/http.ServeMux` (Go 1.22+ pattern routing) | stdlib |
| Config | `os.Getenv` + `os.ReadFile` for `_FILE` secrets | ~45 |
| Validation | Explicit per-field functions | ~50 |
| TOTP | `crypto/hmac` + `crypto/sha1` + `encoding/binary` | ~80 |
| CORS | Custom middleware | ~15 |
| Migrations | Read `migrations/*.sql` sorted, execute in transaction | ~90 |
| JWKS serialization | Marshal `crypto/rsa` public key to JSON | ~30 |
| JWT | `internal/jwt` -- RS256 signing/verification, ES256 verification (DPoP), parsing, claims validation | ~500 |
| Redis client | `internal/redis` -- RESP2 protocol, connection pooling, semaphore-based blocking, idle reaping | ~350 |

---

## 19. Companion Projects

### Vue NPM Package (`@vault42/vue`)

Vue 3 package (`packages/vue/`) with composables for auth UI: `useAuth` (authentication state, login, logout, token refresh), `useIdentity` (encrypted PII CRUD), `useBlobs` (encrypted file storage), `useT` (i18n translations with reactive locale switching). Built-in i18n plugin supporting 38 locales with automatic locale detection (browser → localStorage → fallback), interpolation, and `formatDate`/`formatNumber` utilities.

### Web Frontend

Vue 3 + Vite + Tailwind frontend (`web/`) with full i18n support. All UI strings are translated via `useT()` composable from `@vault42/vue`. Features a searchable locale picker (`LanguageSwitcher.vue`) with native language names. Can be embedded into the Go binary via `go:embed` (`internal/frontend/`) or deployed as a separate container. Helm chart includes optional frontend deployment with ingress split routing.

---

## 20. OpenID Connect Discovery

**Endpoint:** `GET /.well-known/openid-configuration`

Returns a discovery document with:
- `issuer`: origin URL
- `authorization_endpoint`: `/auth/oauth2/authorize`
- `token_endpoint`: `/auth/login`
- `userinfo_endpoint`: `/user/profile`
- `jwks_uri`: `/.well-known/jwks.json`
- `registration_endpoint`: `/auth/register`
- `scopes_supported`: `["openid", "profile", "email"]`
- `response_types_supported`: `["code"]`
- `grant_types_supported`: `["authorization_code", "refresh_token", "client_credentials"]`
- `id_token_signing_alg_values_supported`: `["RS256"]`
- `token_endpoint_auth_methods_supported`: `["client_secret_basic", "client_secret_post"]`
- `code_challenge_methods_supported`: `["S256"]`
- `subject_types_supported`: `["public"]`
- `dpop_signing_alg_values_supported`: `["RS256", "ES256"]`

**Source:** `internal/handler/wellknown.go`

---

## Appendix A: Changes from SpecV0

### Implemented as Designed

The following features match the original planning specification:

- **Authentication flows:** email/password registration, login, token refresh, logout, password reset, email verification
- **Token architecture:** RS256 JWT access tokens, SHA-256 hashed refresh tokens, single-use rotation, family-based replay detection, fingerprint binding
- **JWKS:** served at `/.well-known/jwks.json`, key rotation via CLI
- **TOTP:** RFC 6238 implementation with encrypted secrets, QR code URL generation, rate limiting
- **WebAuthn/FIDO2:** full registration + authentication ceremony, sign count verification, multiple keys per user
- **Backup codes:** 10 single-use codes, hashed with HMAC-SHA256
- **Device fingerprinting:** SHA256(IP + UA + Accept-Language + TLS), stored with refresh tokens, verified on every request
- **Rate limiting:** per-endpoint tiers with sliding window counters, response headers
- **Audit logging:** append-only, database-enforced (triggers), sensitive data scrubbing, risk scores
- **Cache interface:** Redis / in-memory / PostgreSQL backends, graceful degradation
- **Client authentication:** CLI-only registration, Argon2id-hashed secrets, client credentials grant, scope intersection
- **Security mitigations:** all JWT attacks, OAuth2 CSRF/PKCE, timing attacks, user enumeration prevention, constant-time comparisons
- **Password policy:** NIST SP 800-63B (15-char minimum, no composition rules, HIBP breach check, history prevention)
- **Email templates:** verification, password reset, new device, account locked, 2FA setup, suspicious activity
- **Secrets architecture:** `_FILE` convention, file zeroing after read, secrets never in env vars
- **Docker image:** multi-stage, distroless, non-root, static binary, read-only filesystem
- **Admin token:** generated on first boot, Argon2id hashed, required for all CLI commands
- **Honeypot profile:** 4th deployment profile for threat observation with trap user detection, webhook alerting, fake JWT generation, and full request logging
- **Embedded frontend:** Vue SPA served from Go binary via `go:embed`, controlled by `VAULT_SERVE_FRONTEND`
- **Email template engine:** HTML templates embedded via `go:embed` with filesystem overrides, security validation (rejects script/iframe/event handlers), and branding defaults
- **Database schema:** two schemas (auth + audit), least-privilege roles, all tables implemented
- **Argon2id parameters:** 46 MiB memory, 1 iteration, 1 parallelism, concurrency-limited by semaphore (max 4 in-flight, 184 MiB peak)
- **Max JWT size:** 8KB enforced
- **Cookie attributes:** HttpOnly, Secure, SameSite=Strict, Path=/

### Implementation Differences

| SpecV0 Planned | Actually Implemented | Reason |
|----------------|---------------------|--------|
| Docker Compose deployment | Helm chart (Kubernetes) | More robust for all environments; single chart for prod/dev/embedded |
| Raw K8s manifests (`k8s/deployment.yaml`, etc.) | Helm templates with values overlays | Better parameterization and environment management |
| `docker exec vault42 add-client` | `kubectl exec deploy/vault42-vault42-auth -- /app/vault42 add-client` | Kubernetes is the deployment target |
| TLS 1.2 minimum | TLS 1.3 minimum | Stricter; Go 1.24 defaults |
| Three OAuth2 providers (Google, Facebook, GitHub) | Three providers (Google, GitHub, Facebook) | All three providers implemented with PKCE S256 |
| OAuth2 state as simple HMAC | HMAC-signed state with provider name + nonce + expiry + PKCE | More robust; PKCE verifier stored in cache |
| PKCE enforced on all OAuth2 | PKCE S256 enforced on all three providers (Google, GitHub, Facebook) | All providers now support PKCE S256 |
| Separate `docker-compose.pi5.yml` for embedded | `VAULT_PROFILE=embedded` with Helm chart | Unified deployment |
| `CACHE_BACKEND` defaults to `memory` in dev | Dev inherits `redis` from production | Dev extends production baseline |
| Rate limits disabled in dev | Dev inherits `rate_limit_enabled=true` from production | Dev extends production; explicit override available |
| TLS disabled in dev | Dev inherits `tls_enabled=true` from production | Dev uses mkcert for locally-trusted TLS |
| PostgreSQL 17 in spec | PostgreSQL via Helm (version configurable) | Chart is version-agnostic |
| `/auth/2fa/totp/verify` used for both setup confirmation and login | Same endpoint, behavior differs based on token type (`Bearer` vs `2fa_challenge`) | Cleaner API surface |
| Backup codes stored as Argon2id hashes (spec said this) | Implemented with HMAC-SHA256 (not Argon2id) | 10 codes, 16 hex chars each (64-bit entropy), HMAC-SHA256 hashed |
| `auth.cache` table | Added; not in SpecV0 schema | PostgreSQL cache backend needs storage |
| `auth.admin_config` table | Added; not in SpecV0 schema | Admin token hash and key-value config storage |
| No declarative seeding | `internal/seed/` package: JSON-based idempotent client + user seeding via `VAULT_SEED_FILE` env var or `vault42 seed` CLI command | Enables repeatable dev/staging deployments |
| `failed_login_count` column on `users` | Added; not in SpecV0 schema | Tracks failed login attempts for lockout |
| `used_at` column on `backup_codes` | Added; not in SpecV0 schema | Tracks when backup codes were consumed |
| Audit schema: separate `vault_app` grant with explicit `REVOKE UPDATE, DELETE` | Implemented as designed, plus database triggers | Both role-level and trigger-level enforcement |
| Auth schema: `SELECT, INSERT, UPDATE` only for `vault_app` | `DELETE` grant included in `001_initial_schema.sql` | Required for device removal, session cleanup, TOTP disable |
| OIDC auto-discovery (`.well-known/openid-configuration`) listed as optional | Implemented -- returns a static discovery document | Simple implementation; useful for client configuration |
| Fingerprint separator collision prevention not specified | Length-prefixed fields (4-byte big-endian length + data) | Prevents crafted field values from producing identical hashes |
| Password confirmation for sensitive ops not in spec | `POST /auth/confirm` + `Confirmed` middleware with 5-minute window | Added for TOTP setup/disable, WebAuthn register/delete, backup code generation |
| MFA challenge flow not detailed in spec | 2FA challenge token (5-min JWT with `token_type: "2fa_challenge"`) | Implemented as a distinct token type with separate middleware |
| `rotate-jwks` listed as CLI command | Signing key update method exists (`TokenService.UpdateSigningKey`) | CLI command references this; not a standalone CLI subcommand in the implemented code |
| DPoP middleware listed in SpecV0 | DPoP middleware conditionally wired via `VAULT_DPOP_ENABLED` | Enabled on login, refresh, and 2FA verify when config flag is true |
| Argon2id parameter bounds checking not specified | Parser rejects iterations > 10, parallelism > 4, memory > 128 MiB | Prevents DoS via crafted hashes |

### Deferred to Future Versions

The following features were planned in SpecV0 but are not fully implemented:

| Feature | Status |
|---------|--------|
| **DPoP (Demonstration of Proof-of-Possession)** | Crypto validation (`internal/crypto/dpop.go`), middleware (`internal/middleware/dpop.go`), and route wiring exist. DPoP is conditionally enabled via `VAULT_DPOP_ENABLED` (default: `false`). When enabled, DPoP middleware is applied to login, refresh, and 2FA verify endpoints. VaultClaims include `cnf.jkt` field. |
| **Facebook OAuth** | Fully implemented. `FacebookProvider` in `internal/oauth2/facebook.go`, PKCE S256 enforced, Vue login button added. |
| **Honeypot Bridge** | Fully implemented. `cmd/bridge/` is a standalone reverse proxy (stdlib only) that routes between real and honeypot Vault42 instances. Score-based detection (UA patterns, rate tracking, login failures, decoy page hits), admin API, Redis persistence, and fake login pages for scanner paths. Helm chart support via `bridge.enabled`. See [Bridge Deployment Guide](bridge.md). |
| **OIDC auto-discovery for providers** | Provider configs are hardcoded (Google, GitHub URLs). No `.well-known` fetching from providers. |
| **"Remember Me" as distinct device trust feature** | `remember_me` flag extends refresh token TTL (30 days vs 7 days), but the SpecV0 concept of "trusted device skips 2FA" is partially implemented via `MFAService.RequiresMFA` with `trustedDevice` parameter. Device trust window management is not enforced. |
| **Email encryption (paranoid mode)** | Not implemented |
| **Server-rendered auth pages (branding/theming)** | Partially addressed. Embedded Vue SPA can be served from the Go binary (`VAULT_SERVE_FRONTEND`), and branding config (`AppName`, `LogoURL`, `PrimaryColor`) is used in email templates. Server-side rendered theming is not implemented. |
| **mTLS for service-to-service auth** | Not implemented |
| **Certificate pinning** | Not implemented |
| **ACME auto-renewal (Let's Encrypt)** | Not implemented. BYO certificate only. Dev uses mkcert. |
| **Sidecar injection** | Not implemented |
| **SIEM streaming** | Not implemented |
| **IP geolocation** | Not implemented |
| **Risk scoring (adaptive)** | `risk_score` field exists in audit entries but is always set to hardcoded values (0, 10, 20, 30, 70, 90) based on event type, not dynamically computed |
| **Progressive login delays** | Failed login counter exists (`IncrementFailedLogin`) but exponential backoff/progressive delays are not implemented |
| **Row Level Security** | Not implemented |
| **Audit log retention/cleanup** | Implemented via `cleanup-audit` CLI command using SECURITY DEFINER PostgreSQL function |
| **Account lock email notification** | Implemented: `TemplateAccountLocked` sent once per lockout window via cache dedup |
| **Init container unlock pattern** | Not implemented. Master key delivered via `_FILE` convention. |
| **SealedSecrets / External Secrets Operator** | Not in Helm chart templates. Secrets managed via standard K8s secrets. |
| **PgBouncer / connection pooling** | Not implemented |
| **Read replicas** | Not implemented |
| **Redis Sentinel / Cluster** | Not implemented |
| **User profile update** | Implemented: `PUT /user/profile` for `display_name`, `avatar_url`, `locale` |
| **Export audit** | Implemented: `export-audit` CLI command with JSONL output |
