# API Reference

> Vault42 -- JWT Authentication & Authorization Microservice

## Overview

Vault42 is a production-grade Go authentication and authorization service. All endpoints are served over HTTPS with TLS 1.3 minimum. The API uses JSON for request and response bodies. All endpoints are prefixed at the root (no `/api/v1` prefix).

**Base URL convention:** `https://vault42.example.com`

**Common request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes (POST/PUT/PATCH) | Must be `application/json` |
| `Authorization` | Authenticated endpoints | `Bearer <access_token>` |
| `User-Agent` | Recommended | Included in device fingerprint computation |
| `Accept-Language` | Recommended | Included in device fingerprint computation |

**Global request limits:**

- Maximum request body size: **8 KB** (enforced by middleware)
- JSON decoder rejects unknown fields (`DisallowUnknownFields`)

**Security headers on all responses:**

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `0` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` |
| `Pragma` | `no-cache` |

---

## Authentication

### Bearer Token Authentication

Most endpoints require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Access tokens are RS256-signed JWTs with a short TTL (typically 5-15 minutes). They are stateless and fingerprint-bound.

### 2FA Challenge Tokens

When a user has MFA enabled, the login endpoint returns a `challenge_token` instead of a full access token. This short-lived token must be presented to 2FA verify endpoints (`POST /auth/2fa/totp/verify`, `POST /auth/2fa/webauthn/verify/begin`, `POST /auth/2fa/webauthn/verify/finish`, `POST /auth/2fa/email-otp/verify`) to complete authentication.

### Client Credentials (Basic Auth)

The `POST /client/token` endpoint accepts HTTP Basic authentication:

```
Authorization: Basic base64(client_id:client_secret)
```

Alternatively, `client_id` and `client_secret` can be sent as form values in the request body.

### Password Confirmation (Elevated Access)

Sensitive operations (TOTP setup/disable, WebAuthn register/delete, backup code generation) require a recent password confirmation via `POST /auth/confirm`. This grants a 5-minute elevated access window. Endpoints requiring confirmation return `403 requires_confirmation` if the window has expired.

---

## Device Fingerprint

Authenticated requests are fingerprint-verified. The fingerprint is computed as `SHA256(IP + User-Agent + Accept-Language + TLS-fingerprint)` and embedded in the access token at issuance. The TLS-fingerprint component is populated from the header specified by `VAULT_TLS_FINGERPRINT_HEADER` (e.g. `X-TLS-Fingerprint`), which the TLS-terminating proxy must set. When the header is not configured, the TLS-fingerprint field is empty (backward compatible). On each authenticated request, the server recomputes the fingerprint and compares it to the token claim. A mismatch results in:

```json
{"error": "fingerprint_mismatch"}
```

Status: `401 Unauthorized`

---

## Common Response Format

### Success responses

Success responses have an appropriate HTTP status code (200, 201) and a JSON body whose shape is endpoint-specific.

### Error responses

All errors follow a consistent shape:

```json
{"error": "error_code_here"}
```

Error codes are lowercase, underscore-separated strings (e.g., `invalid_credentials`, `rate_limit_exceeded`).

---

## Rate Limiting

Rate limits are enforced per-IP or per-user depending on the endpoint. When rate limiting is active, the following headers are present on every response (including successful ones):

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum number of requests allowed in the window |
| `X-RateLimit-Remaining` | Number of requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

When the limit is exceeded:

```
HTTP/1.1 429 Too Many Requests
Retry-After: <window_seconds>
```

```json
{"error": "rate_limit_exceeded"}
```

Rate limits degrade gracefully -- if the cache backend is unavailable, requests are allowed through.

---

## Endpoints

### Health

---

#### GET /healthz

Liveness probe. Returns immediately; does not check dependencies. Version is intentionally omitted to avoid information disclosure.

**Authentication:** None

```json
{"status": "ok"}
```

**Status:** `200 OK`

**curl example:**

```bash
curl https://vault42.example.com/healthz
```

---

#### GET /readyz

Readiness probe. Checks database and cache connectivity.

**Authentication:** None

**Success response (200 OK):**

```json
{
  "status": "ready",
  "database": "up",
  "cache": "up"
}
```

**Degraded response (200 OK):**

```json
{
  "status": "ready",
  "database": "up",
  "cache": "degraded"
}
```

**Not ready response (503 Service Unavailable):**

```json
{
  "status": "not_ready",
  "database": "down"
}
```

**curl example:**

```bash
curl https://vault42.example.com/readyz
```

---

#### GET /metrics

Prometheus metrics endpoint. Returns metrics in Prometheus text exposition format. Only available when `VAULT_METRICS_ENABLED=true`. In production, protect this endpoint with a Kubernetes NetworkPolicy to restrict access to the monitoring namespace.

**Authentication:** None

**Feature toggle:** `VAULT_METRICS_ENABLED=true` (default: `false`). When disabled, the endpoint is not registered and returns 404.

**Response headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | `text/plain; version=0.0.4; charset=utf-8` |

**Success response (200 OK):**

```
# HELP vault_argon2_active Current number of in-flight Argon2id operations
# TYPE vault_argon2_active gauge
vault_argon2_active 1

# HELP vault_argon2_max Maximum concurrent Argon2id operations allowed
# TYPE vault_argon2_max gauge
vault_argon2_max 4

# HELP vault_argon2_rejected_total Total Argon2id operations rejected (semaphore full)
# TYPE vault_argon2_rejected_total counter
vault_argon2_rejected_total 0

# HELP vault_login_attempts_total Total login attempts
# TYPE vault_login_attempts_total counter
vault_login_attempts_total 42

# HELP vault_login_success_total Total successful logins
# TYPE vault_login_success_total counter
vault_login_success_total 38

# HELP vault_login_failed_total Total failed logins
# TYPE vault_login_failed_total counter
vault_login_failed_total 4

# HELP vault_tokens_issued_total Total access tokens issued
# TYPE vault_tokens_issued_total counter
vault_tokens_issued_total 76

# HELP vault_tokens_refreshed_total Total token refresh operations
# TYPE vault_tokens_refreshed_total counter
vault_tokens_refreshed_total 120
```

**Exposed metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `vault_argon2_active` | Gauge | Current number of in-flight Argon2id operations |
| `vault_argon2_max` | Gauge | Maximum concurrent Argon2id operations allowed (semaphore size) |
| `vault_argon2_rejected_total` | Counter | Total Argon2id operations rejected due to semaphore full (503 responses) |
| `vault_login_attempts_total` | Counter | Total login attempts (success + failure) |
| `vault_login_success_total` | Counter | Total successful logins |
| `vault_login_failed_total` | Counter | Total failed logins |
| `vault_tokens_issued_total` | Counter | Total access tokens issued (login + MFA completion) |
| `vault_tokens_refreshed_total` | Counter | Total token refresh operations |

**curl example:**

```bash
curl https://vault42.example.com/metrics
```

---

### Auth

---

#### GET /auth/capabilities

Returns server capability flags. Allows clients to discover whether registration is enabled, MFA is required, and which OAuth providers are configured, without authentication.

**Authentication:** None

**Success response (200 OK):**

```json
{
  "registration_enabled": true,
  "mfa_required": true,
  "oauth_providers": ["github", "google"]
}
```

**curl example:**

```bash
curl https://vault42.example.com/auth/capabilities
```

---

#### POST /auth/register

Create a new user account. Sends a verification email with a 24-hour token. The response is intentionally identical whether the email is new or already registered to prevent user enumeration.

**Feature toggle:** `VAULT_REGISTRATION_ENABLED=true` (default). When `false`, returns 403 `registration_disabled`.

**Authentication:** None
**Rate limit:** 3 requests per hour (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email address |
| `password` | string | Yes | Minimum 15 characters (NIST SP 800-63B Rev 4). HIBP breach check enforced. |
| `display_name` | string | No | Display name (max 255 chars, sanitized) |
| `locale` | string | No | User locale (e.g., `en`, `sk`, `hu`) |
| `redirect_to` | string | No | Relative path to redirect after email verification |

**Success response (201 Created):**

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com"
}
```

Note: When the email is already registered, the server returns the same `201` status with an anti-enumeration message:

```json
{
  "status": "verification_email_sent",
  "message": "If this email is not already registered, a verification email has been sent."
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON |
| 400 | `invalid_input` | Invalid email format |
| 400 | `password_too_short` | Password below 15-character minimum |
| 400 | `password_breached` | Password found in HIBP breach database |
| 429 | `rate_limit_exceeded` | Registration rate limit exceeded |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "my-secure-passphrase-here",
    "display_name": "Jane Doe",
    "locale": "en"
  }'
```

---

#### GET /auth/verify-email

Verify a user's email address using the token sent during registration.

**Authentication:** None

**Query parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token` | Yes | Verification token from the email link |

**Success response (200 OK):**

```json
{"status": "email_verified"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_token` | No token query parameter |
| 400 | `invalid_or_expired_token` | Token not found, expired, or already used |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl "https://vault42.example.com/auth/verify-email?token=abc123def456..."
```

---

#### POST /auth/login

Authenticate a user with email and password. If the user has MFA enabled, returns a `challenge_token` instead of access tokens.

> **Honeypot mode:** When `VAULT_PROFILE=honeypot` and the email matches a configured trap user (`VAULT_HONEYPOT_TRAP_USERS`), the endpoint returns a fake 200 response with realistic-looking but unsigned JWT tokens. The attacker's request triggers a webhook alert. Subsequent requests with the fake token will fail silently on any real API call.

**Authentication:** None
**Rate limit:** 5 requests per 15 minutes (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email address |
| `password` | string | Yes | User password |
| `remember_me` | boolean | No | Extend refresh token TTL |
| `client_id` | string | No | Client application identifier |

**Success response -- no MFA (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

The response also sets an `HttpOnly` cookie named `refresh_token` on the `/auth` path with `Secure`, `SameSite=Strict` attributes.

**Success response -- MFA required (200 OK):**

```json
{
  "requires_2fa": true,
  "challenge_token": "eyJhbGciOiJSUzI1NiIs...",
  "available_methods": ["totp", "webauthn", "backup_code"]
}
```

No refresh token cookie is set until MFA is completed.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON |
| 401 | `invalid_credentials` | Wrong email/password or email not verified (identical response for anti-enumeration) |
| 403 | `account_locked` | Account locked due to too many failed attempts |
| 429 | `rate_limit_exceeded` | Login rate limit exceeded |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -c cookies.txt \
  -d '{
    "email": "user@example.com",
    "password": "my-secure-passphrase-here"
  }'
```

---

#### POST /auth/refresh

Exchange a refresh token (from the `refresh_token` cookie) for a new access token and a new refresh token. Implements single-use rotation with family-based replay detection.

**Authentication:** None (uses cookie)
**Rate limit:** 30 requests per minute (per IP)
**Cookie required:** `refresh_token` (set by login/previous refresh)

**Request body:** None

The refresh token is read from the `refresh_token` HttpOnly cookie, not from the request body.

**Success response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Sets a new `refresh_token` cookie (the old refresh token is invalidated).

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `missing_refresh_token` | No `refresh_token` cookie present |
| 401 | `replay_detected` | Refresh token reuse detected; entire token family revoked |
| 401 | `token_expired` | Refresh token has expired |
| 401 | `invalid_token` | Token not found, revoked, or fingerprint mismatch |
| 500 | `internal_error` | Server error |

On any error, the `refresh_token` cookie is cleared.

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/refresh \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -b cookies.txt \
  -c cookies.txt
```

---

#### POST /auth/logout

Revoke all refresh tokens for the authenticated user and clear the refresh token cookie.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

```json
{"status": "logged_out"}
```

Clears the `refresh_token` cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `missing_authorization` | No Authorization header |
| 401 | `invalid_token` | Token invalid or expired |
| 401 | `fingerprint_mismatch` | Device fingerprint does not match token |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/confirm

Verify the user's password to grant a 5-minute elevated access window for sensitive operations (TOTP setup, WebAuthn management, backup codes).

**Authentication:** Bearer token
**Fingerprint:** Verified
**Rate limit:** 5 requests per 15 minutes (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | string | Yes | Current account password |

**Success response (200 OK):**

```json
{
  "confirmed": true,
  "expires_in": 300
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `password_required` | Missing or empty password |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_password` | Wrong password |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/confirm \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{"password": "my-secure-passphrase-here"}'
```

---

### Password Management

---

#### POST /auth/password/reset

Request a password reset email. Always returns success to prevent user enumeration. Uses constant-time dummy hash verification when the user is not found.

**Authentication:** None
**Rate limit:** 3 requests per hour (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Account email address |

**Response (200 OK) -- always identical:**

```json
{
  "status": "If that email exists, a reset link has been sent."
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON or missing email |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

---

#### POST /auth/password/reset/confirm

Complete a password reset using the token from the reset email.

**Authentication:** None
**Rate limit:** 3 requests per hour (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | Yes | Reset token from email |
| `password` | string | Yes | New password (minimum 15 characters) |

**Success response (200 OK):**

```json
{"status": "password_reset_complete"}
```

All existing refresh tokens for the user are revoked after a successful reset.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON or missing fields |
| 400 | `password_too_short` | New password below 15-character minimum |
| 400 | `invalid_or_expired_token` | Token not found, expired, or already used |
| 400 | `password_recently_used` | New password matches one of the last 5 passwords |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/password/reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456...",
    "password": "my-new-secure-passphrase"
  }'
```

---

#### POST /user/password

Change the password for the currently authenticated user. Requires the current password. Revokes all existing sessions after a successful change.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current_password` | string | Yes | Current account password |
| `new_password` | string | Yes | New password (minimum 15 characters) |

**Success response (200 OK):**

```json
{"status": "password_changed"}
```

All existing refresh tokens for the user are revoked.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON |
| 400 | `password_too_short` | New password below 15-character minimum |
| 400 | `password_recently_used` | New password matches one of the last 5 passwords |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_current_password` | Wrong current password |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |

**curl example:**

```bash
curl -X POST https://vault42.example.com/user/password \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{
    "current_password": "my-old-passphrase",
    "new_password": "my-new-secure-passphrase"
  }'
```

---

### User Profile & Sessions

---

#### GET /user/profile

Retrieve the authenticated user's profile information.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "display_name": "Jane Doe",
  "locale": "en",
  "mfa_required": false,
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |

**curl example:**

```bash
curl https://vault42.example.com/user/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### PUT /user/profile

Update the authenticated user's profile fields. Only fields included in the request body are updated; omitted fields remain unchanged. Email is not updatable via this endpoint.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Request body:**

```json
{
  "display_name": "Jane Smith",
  "avatar_url": "https://example.com/avatar.jpg",
  "locale": "sk"
}
```

All fields are optional (pointer semantics — omitted fields are not modified):

| Field | Type | Constraints |
|-------|------|-------------|
| `display_name` | string | Max 100 chars, sanitized |
| `avatar_url` | string | Must be valid HTTPS URL |
| `locale` | string | BCP 47 language tag (e.g., `en`, `sk`, `hu`) |

**Success response (200 OK):**

Returns the full updated profile (same shape as `GET /user/profile`).

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON body |
| 401 | `unauthorized` | Not authenticated |
| 500 | `internal_error` | Database update failed |

**curl example:**

```bash
curl -X PUT https://vault42.example.com/user/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{"display_name": "Jane Smith", "locale": "sk"}'
```

---

#### GET /user/sessions

List all active sessions (devices) for the authenticated user.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "sessions": [
    {
      "id": "device-uuid-1",
      "friendly_name": "Chrome on Windows",
      "ip": "203.0.113.42",
      "user_agent": "Mozilla/5.0...",
      "trusted": false,
      "last_seen_at": "2025-06-15T14:30:00Z",
      "first_seen_at": "2025-06-01T08:00:00Z"
    }
  ]
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/sessions \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### DELETE /user/sessions/{id}

Revoke a specific session. Removes the device record and revokes all associated refresh tokens.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Device/session UUID |

**Success response (200 OK):**

```json
{"status": "revoked"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_session_id` | Empty session ID in path |
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 404 | `session_not_found` | Session not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/sessions/device-uuid-1 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### DELETE /user/sessions

Revoke all sessions (sign out everywhere). Removes all device records and revokes all refresh tokens.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{"status": "all_sessions_revoked"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/sessions \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### GET /user/devices

List all registered devices for the authenticated user.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "devices": [
    {
      "id": "device-uuid-1",
      "fingerprint_hash": "a1b2c3d4...",
      "friendly_name": "Chrome on Windows",
      "trusted": false,
      "ip": "203.0.113.42",
      "user_agent": "Mozilla/5.0...",
      "last_seen_at": "2025-06-15T14:30:00Z"
    }
  ]
}
```

The `fingerprint_hash` field is truncated to the first 8 characters for display purposes.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/devices \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### PATCH /user/devices/{id}

Rename a device (set a friendly name).

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Device UUID |

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `friendly_name` | string | Yes | New device name (max 100 characters, no control chars) |

**Success response (200 OK):**

```json
{
  "status": "updated",
  "friendly_name": "My Work Laptop"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_device_id` | Empty device ID in path |
| 400 | `invalid_request` | Malformed JSON |
| 400 | `name_required` | Empty friendly name |
| 400 | `name_too_long` | Name exceeds 100 characters |
| 400 | `name_invalid_chars` | Name contains control characters |
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 404 | `device_not_found` | Device not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X PATCH https://vault42.example.com/user/devices/device-uuid-1 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{"friendly_name": "My Work Laptop"}'
```

---

#### DELETE /user/devices/{id}

Remove a device and revoke all associated refresh tokens.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Device UUID |

**Success response (200 OK):**

```json
{"status": "device_removed"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 404 | `device_not_found` | Device not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/devices/device-uuid-1 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

### Identity Store

Encrypted personal identity information (PII). All fields are encrypted at rest with AES-256-GCM and stored under a pseudonymous key derived via `HMAC-SHA256(userID + ":identity", hmac_secret)`.

---

#### GET /user/identity

Retrieve the authenticated user's identity profile. Returns decrypted fields.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "given_name": "Jane",
  "family_name": "Doe",
  "country": "US",
  "date_of_birth": "1990-05-15",
  "sex": "female",
  "billing": {
    "address_line_1": "123 Main St",
    "address_line_2": "Apt 4B",
    "city": "Springfield",
    "postal_code": "62704",
    "country": "US",
    "vat_id": ""
  },
  "updated_at": "2026-02-24T10:30:00Z"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 404 | `identity_not_found` | No identity profile stored for this user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/identity \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

#### PUT /user/identity

Create or replace the authenticated user's identity profile. All fields are optional.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Request body:**

| Field | Type | Max Length | Validation |
|-------|------|-----------|------------|
| `given_name` | string | 100 runes | Truncated if longer |
| `family_name` | string | 100 runes | Truncated if longer |
| `country` | string | 2 chars | ISO 3166-1 alpha-2 (`^[A-Z]{2}$`) |
| `date_of_birth` | string | -- | ISO 8601 date (`YYYY-MM-DD`), must not be in the future |
| `sex` | string | 50 runes | Truncated if longer |
| `billing` | object | -- | Optional billing address |
| `billing.address_line_1` | string | 200 runes | Truncated if longer |
| `billing.address_line_2` | string | 200 runes | Truncated if longer |
| `billing.city` | string | 100 runes | Truncated if longer |
| `billing.postal_code` | string | 20 runes | Truncated if longer |
| `billing.country` | string | 2 chars | ISO 3166-1 alpha-2 (`^[A-Z]{2}$`) |
| `billing.vat_id` | string | 50 runes | Truncated if longer |

**Success response (200 OK):**

```json
{"status": "updated"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON |
| 400 | `invalid_country` | Country code not ISO 3166-1 alpha-2 |
| 400 | `invalid_date_of_birth` | Invalid date format or future date |
| 400 | `invalid_billing_country` | Billing country code not ISO 3166-1 alpha-2 |
| 401 | `unauthorized` | Not authenticated |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X PUT https://vault42.example.com/user/identity \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{"given_name":"Jane","family_name":"Doe","country":"US"}'
```

---

#### DELETE /user/identity

Permanently delete the authenticated user's identity profile.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{"status": "deleted"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/identity \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

### Encrypted Blob Storage

Encrypted file storage with per-user quotas. Blobs are compressed (DEFLATE), encrypted (AES-256-GCM), and stored under a pseudonymous key derived via `HMAC-SHA256(userID + ":objects", hmac_secret)`. Blobs are immutable — they can be created and deleted but not updated.

**Feature toggle:** Set `VAULT_BLOB_QUOTA_BYTES=0` to disable blob storage entirely. When disabled, blob endpoints are not registered and return 404.

---

#### POST /user/blobs

Upload an encrypted blob. Accepts raw binary body or multipart form data.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Raw upload:**

| Header | Description |
|--------|-------------|
| `X-Blob-Label` | Optional label for the blob (max 255 bytes) |

Body: raw binary data

**Multipart upload:**

| Field | Description |
|-------|-------------|
| `file` | The file to upload (required) |
| `label` | Optional label (max 255 bytes) |

**Size limits:**

| Limit | Default | Config |
|-------|---------|--------|
| Minimum blob size | 0 (disabled) | `VAULT_BLOB_MIN_SIZE` |
| Maximum blob size | 10 MB | `VAULT_BLOB_MAX_SIZE` |
| Max files per user | 50 | `VAULT_BLOB_MAX_PER_USER` |
| Max total storage | 10 MB | `VAULT_BLOB_QUOTA_BYTES` |

**Success response (201 Created):**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "label": "my-document.pdf",
  "size_bytes": 1048576,
  "stored_bytes": 524300,
  "checksum": "sha256:abc123...",
  "created_at": "2026-02-24T10:30:00Z"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `empty_blob` | No data provided |
| 400 | `blob_too_small` | Below minimum size (`VAULT_BLOB_MIN_SIZE`, disabled by default) |
| 400 | `missing_file` | Multipart upload missing `file` field |
| 401 | `unauthorized` | Not authenticated |
| 409 | `quota_exceeded` | File count or byte quota exceeded |
| 413 | `blob_too_large` | Exceeds maximum size (`VAULT_BLOB_MAX_SIZE`) |
| 500 | `internal_error` | Server error |

**curl example (raw upload):**

```bash
curl -X POST https://vault42.example.com/user/blobs \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "X-Blob-Label: my-document.pdf" \
  --data-binary @document.pdf
```

**curl example (multipart):**

```bash
curl -X POST https://vault42.example.com/user/blobs \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -F "file=@document.pdf" \
  -F "label=my-document.pdf"
```

---

#### GET /user/blobs

List all blobs for the authenticated user with metadata and quota usage.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "blobs": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "label": "my-document.pdf",
      "named": false,
      "size_bytes": 1048576,
      "stored_bytes": 524300,
      "checksum": "sha256:abc123...",
      "created_at": "2026-02-24T10:30:00Z"
    }
  ],
  "count": 1,
  "quota": {
    "used_bytes": 524300,
    "max_bytes": 10485760,
    "used_count": 1,
    "max_count": 50
  }
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/blobs \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

#### GET /user/blobs/{id}

Download a decrypted blob. Returns raw binary data.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Blob UUID |

**Response headers:**

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/octet-stream` |
| `Content-Length` | Size in bytes |
| `X-Blob-Checksum` | SHA-256 checksum of original data |
| `X-Blob-Label` | Label (if set) |

**Success response:** `200 OK` with binary body

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_id` | No blob ID in path |
| 401 | `unauthorized` | Not authenticated |
| 404 | `blob_not_found` | Blob not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/blobs/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -o downloaded-file.pdf
```

---

#### DELETE /user/blobs/{id}

Permanently delete an encrypted blob.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Blob UUID |

**Success response (200 OK):**

```json
{"status": "deleted"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_id` | No blob ID in path |
| 401 | `unauthorized` | Not authenticated |
| 404 | `blob_not_found` | Blob not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/blobs/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

#### PUT /user/blobs/named/{name}

Create or replace a **named blob**. Named blobs are addressed by a human-readable name (e.g. `session-data`, `preferences`) instead of a UUID. If a blob with the same name already exists for this user, it is replaced atomically (delete + insert). The name is stored as an HMAC hash in the database — the plaintext name never touches persistent storage.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Blob name (`[a-zA-Z0-9_-]+`, max 255 chars) |

**Request body:** Raw binary data (the blob content).

**Success response (200 OK):**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "label": "session-data",
  "size_bytes": 4096,
  "stored_bytes": 2048,
  "checksum": "sha256:abc123...",
  "created_at": "2026-02-24T10:30:00Z"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `empty_blob` | No data provided |
| 400 | `missing_name` | No name in path |
| 400 | `name_too_long` | Name exceeds 255 characters |
| 400 | `blob_too_small` | Below minimum size (disabled by default) |
| 401 | `unauthorized` | Not authenticated |
| 409 | `quota_exceeded` | File count or byte quota exceeded |
| 413 | `blob_too_large` | Exceeds maximum size |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X PUT https://vault42.example.com/user/blobs/named/session-data \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  --data-binary @session.bin
```

---

#### GET /user/blobs/named/{name}

Download a named blob by its reference name. Returns raw binary data.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Blob name |

**Response headers:**

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/octet-stream` |
| `Content-Length` | Size in bytes |
| `X-Blob-Checksum` | SHA-256 checksum of original data |
| `X-Blob-Label` | Label (same as name for named blobs) |

**Success response:** `200 OK` with binary body

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_name` | No name in path |
| 401 | `unauthorized` | Not authenticated |
| 404 | `blob_not_found` | Named blob not found |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/blobs/named/session-data \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -o session.bin
```

---

#### DELETE /user/blobs/named/{name}

Delete a named blob by its reference name.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Blob name |

**Success response (200 OK):**

```json
{"status": "deleted"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_name` | No name in path |
| 401 | `unauthorized` | Not authenticated |
| 404 | `blob_not_found` | Named blob not found |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/blobs/named/session-data \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

### Two-Factor Authentication

---

#### GET /auth/2fa/status

Retrieve the MFA status for the authenticated user, including which methods are configured.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "totp_enabled": true,
  "webauthn_enabled": false,
  "backup_codes_remaining": 8,
  "available_methods": ["totp", "backup_code"],
  "mfa_required": false
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/auth/2fa/status \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/totp/setup

Begin TOTP setup. Generates a new TOTP secret and returns it along with an `otpauth://` URL for QR code generation. Requires recent password confirmation via `POST /auth/confirm`.

**Authentication:** Bearer token + password confirmation
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "otp_url": "otpauth://totp/vault42.example.com:user-id?secret=JBSWY3DPEHPK3PXP&issuer=vault42.example.com&algorithm=SHA1&digits=6&period=30"
}
```

The TOTP secret is stored encrypted (AES-256-GCM) and marked as unverified until the first successful code verification.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 403 | `requires_confirmation` | Password confirmation required (call `POST /auth/confirm` first) |
| 409 | `totp_already_setup` | TOTP is already configured and verified |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/totp/setup \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/totp/verify

Verify a TOTP code. Has two modes of operation:

1. **Setup verification:** When called with a standard Bearer token, confirms the TOTP setup by marking the secret as verified.
2. **Login MFA challenge:** When called with a `2fa_challenge` token (from the login flow), completes authentication and issues full access/refresh tokens.

**Authentication:** Bearer token or 2FA challenge token
**Fingerprint:** Verified
**Rate limit:** 5 requests per 5 minutes (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | 6-digit TOTP code (exactly 6 ASCII digits) |

**Success response -- setup verification (200 OK):**

```json
{
  "verified": true
}
```

**Success response -- MFA login completion (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Also sets the `refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_code` | Code is not exactly 6 digits |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_code` | TOTP code is incorrect |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 404 | `totp_not_setup` | TOTP has not been configured |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 429 | `totp_code_already_used` | Same code used within the same 30-second time step (replay prevention) |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# During login MFA flow
curl -X POST https://vault42.example.com/auth/2fa/totp/verify \
  -H "Authorization: Bearer <challenge_token>" \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -c cookies.txt \
  -d '{"code": "123456"}'
```

---

#### DELETE /auth/2fa/totp

Disable TOTP for the authenticated user. Requires recent password confirmation.

**Authentication:** Bearer token + password confirmation
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

```json
{"status": "totp_disabled"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 403 | `requires_confirmation` | Password confirmation required |
| 404 | `totp_not_setup` | TOTP has not been configured |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/auth/2fa/totp \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/webauthn/register/begin

Begin WebAuthn/FIDO2 credential registration. Returns a `PublicKeyCredentialCreationOptions` object for the browser's `navigator.credentials.create()` API. Requires recent password confirmation. Session data is cached for 5 minutes.

**Authentication:** Bearer token + password confirmation
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

Returns a WebAuthn `PublicKeyCredentialCreationOptions` JSON object (structure defined by the W3C WebAuthn specification).

```json
{
  "publicKey": {
    "rp": {"name": "Vault42", "id": "vault42.example.com"},
    "user": {"id": "...", "name": "user@example.com", "displayName": "Jane Doe"},
    "challenge": "base64url-encoded-challenge",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    "excludeCredentials": [],
    "authenticatorSelection": {...},
    "timeout": 60000,
    "attestation": "none"
  }
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 403 | `requires_confirmation` | Password confirmation required |
| 401 | `unauthorized` | User not found |
| 500 | `webauthn_error` | WebAuthn ceremony initialization failed |
| 501 | `webauthn_not_configured` | WebAuthn is not configured on this server |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/webauthn/register/begin \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/webauthn/register/finish

Complete WebAuthn credential registration. Send the `AuthenticatorAttestationResponse` from the browser's `navigator.credentials.create()` call.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Request body:** The `AuthenticatorAttestationResponse` JSON object from the browser WebAuthn API (passed through directly as the raw HTTP request body).

**Success response (200 OK):**

```json
{"status": "webauthn_registered"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `no_pending_registration` | No registration session found (expired or not started) |
| 400 | `webauthn_verification_failed` | Credential verification failed |
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |
| 501 | `webauthn_not_configured` | WebAuthn is not configured |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# This endpoint is normally called from browser JavaScript, not curl.
# The request body is the JSON-serialized AuthenticatorAttestationResponse.
curl -X POST https://vault42.example.com/auth/2fa/webauthn/register/finish \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{ ... AuthenticatorAttestationResponse ... }'
```

---

#### POST /auth/2fa/webauthn/verify/begin

Begin WebAuthn authentication (login verification). Returns a `PublicKeyCredentialRequestOptions` object for the browser's `navigator.credentials.get()` API.

**Authentication:** Bearer token or 2FA challenge token
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

Returns a WebAuthn `PublicKeyCredentialRequestOptions` JSON object.

```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rpId": "vault42.example.com",
    "allowCredentials": [{"type": "public-key", "id": "..."}],
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `no_webauthn_credentials` | No WebAuthn credentials registered for this user |
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |
| 500 | `webauthn_error` | WebAuthn ceremony initialization failed |
| 501 | `webauthn_not_configured` | WebAuthn is not configured |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/webauthn/verify/begin \
  -H "Authorization: Bearer <challenge_token>" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/webauthn/verify/finish

Complete WebAuthn authentication. Send the `AuthenticatorAssertionResponse` from the browser's `navigator.credentials.get()` call. When completing a login MFA challenge, issues full access/refresh tokens.

**Authentication:** Bearer token or 2FA challenge token
**Fingerprint:** Verified

**Request body:** The `AuthenticatorAssertionResponse` JSON object from the browser WebAuthn API.

**Success response -- standard verification (200 OK):**

```json
{
  "verified": true
}
```

**Success response -- MFA login completion (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Also sets the `refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `no_pending_verification` | No verification session found (expired or not started) |
| 401 | `unauthorized` | Not authenticated |
| 401 | `webauthn_verification_failed` | Authenticator assertion verification failed |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |
| 501 | `webauthn_not_configured` | WebAuthn is not configured |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# This endpoint is normally called from browser JavaScript.
curl -X POST https://vault42.example.com/auth/2fa/webauthn/verify/finish \
  -H "Authorization: Bearer <challenge_token>" \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -c cookies.txt \
  -d '{ ... AuthenticatorAssertionResponse ... }'
```

---

#### GET /auth/2fa/webauthn/credentials

List all registered WebAuthn credentials for the authenticated user.

**Authentication:** Bearer token
**Fingerprint:** Verified

**Success response (200 OK):**

```json
{
  "credentials": [
    {
      "id": "cred-uuid-1",
      "sign_count": 42,
      "created_at": "2025-03-10T09:15:00Z"
    }
  ]
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/auth/2fa/webauthn/credentials \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### DELETE /auth/2fa/webauthn/credentials/{id}

Delete a specific WebAuthn credential. Requires recent password confirmation.

**Authentication:** Bearer token + password confirmation
**Fingerprint:** Verified

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Credential UUID |

**Success response (200 OK):**

```json
{"status": "credential_removed"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_credential_id` | Empty credential ID in path |
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 403 | `requires_confirmation` | Password confirmation required |
| 404 | `credential_not_found` | Credential not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/auth/2fa/webauthn/credentials/cred-uuid-1 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/backup-codes

Generate a new set of 10 backup codes. Any existing backup codes are replaced. Requires recent password confirmation. Each code is 12 hex characters (48-bit entropy), stored as Argon2id hashes.

**Authentication:** Bearer token + password confirmation
**Fingerprint:** Verified

**Request body:** None

**Success response (200 OK):**

```json
{
  "codes": [
    "a1b2c3d4e5f6",
    "7890abcdef12",
    "3456789abcde",
    "f0123456789a",
    "bcdef0123456",
    "789abcdef012",
    "3456789abcde",
    "f0123456789a",
    "bcdef0123456",
    "789abcdef012"
  ],
  "warning": "Save these codes. They will not be shown again."
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 403 | `requires_confirmation` | Password confirmation required |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/backup-codes \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

#### POST /auth/2fa/email-otp/verify

Verify an email one-time password code. Has two modes of operation:

1. **Standard verification:** When called with a standard Bearer token, confirms the email OTP code.
2. **Login MFA challenge:** When called with a `2fa_challenge` token (from the login flow), completes authentication and issues full access/refresh tokens.

An email OTP is automatically sent during login when the user's only available 2FA method is `email_otp`. Use `POST /auth/2fa/email-otp/resend` to request a new code.

**Authentication:** Bearer token or 2FA challenge token
**Fingerprint:** Verified
**Rate limit:** 5 requests per 5 minutes (per IP)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | 6-digit email OTP code (exactly 6 ASCII digits) |

**Success response -- standard verification (200 OK):**

```json
{
  "verified": true
}
```

**Success response -- MFA login completion (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Also sets the `refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_code` | Code is not exactly 6 digits |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_code` | Email OTP code is incorrect or expired |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# During login MFA flow
curl -X POST https://vault42.example.com/auth/2fa/email-otp/verify \
  -H "Authorization: Bearer <challenge_token>" \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -c cookies.txt \
  -d '{"code": "123456"}'
```

---

#### POST /auth/2fa/email-otp/resend

Resend the email one-time password code. Generates a new 6-digit code and sends it to the user's registered email address. The previous code (if any) is replaced.

**Authentication:** Bearer token or 2FA challenge token
**Fingerprint:** Verified
**Rate limit:** 5 requests per 5 minutes (per IP)

**Request body:** None

**Success response (200 OK):**

```json
{"status": "sent"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated or user not found |
| 401 | `fingerprint_mismatch` | Device fingerprint mismatch |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/email-otp/resend \
  -H "Authorization: Bearer <challenge_token>" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US"
```

---

### OAuth2 / Social Login

These endpoints are only available when OAuth2 providers are configured.

---

#### GET /auth/oauth2/authorize

Initiate an OAuth2 social login flow. Redirects the user to the provider's authorization page with a signed state parameter and PKCE challenge.

**Authentication:** None

**Query parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `provider` | Yes | OAuth2 provider name (e.g., `google`, `github`, `facebook`) |

**Response:** `302 Found` redirect to the provider's authorization URL.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `unknown_provider` | Provider not configured |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# Follow redirects to see the OAuth2 authorization URL
curl -v "https://vault42.example.com/auth/oauth2/authorize?provider=google"
```

---

#### GET /auth/oauth2/callback/{provider}

Handle the OAuth2 callback from the identity provider. Validates the state parameter (HMAC-signed with expiry), exchanges the authorization code for tokens using PKCE, fetches user info, and either creates a new account or links to an existing one.

If the user has MFA enabled, redirects to `{origin}/oauth/callback#requires_2fa=true&challenge_token=...` instead of issuing full tokens.

**Authentication:** None (callback from provider)

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `provider` | OAuth2 provider name |

**Query parameters (set by the OAuth2 provider):**

| Parameter | Description |
|-----------|-------------|
| `state` | HMAC-signed state parameter |
| `code` | Authorization code |

**Success response:** `302 Found` redirect to `{origin}/oauth/callback#code=...`

Also sets the `refresh_token` HttpOnly cookie. The `code` is a one-time exchange code (60-second TTL) — call `POST /auth/oauth2/exchange` to retrieve the access token.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `unknown_provider` | Provider not configured |
| 400 | `missing_state` | No state parameter in callback |
| 400 | `invalid_state` | State signature validation failed |
| 400 | `state_expired` | State parameter has expired (10-minute window) |
| 400 | `invalid_or_reused_state` | PKCE verifier not found or already consumed |
| 400 | `missing_code` | No authorization code in callback |
| 400 | `unable_to_identify_user` | Could not determine user from provider response |
| 409 | `email_already_registered` | Email exists but verification status prevents linking |
| 502 | `provider_error` | Token exchange or user info request failed |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
# This endpoint is called by the OAuth2 provider's redirect, not directly by clients.
curl -v "https://vault42.example.com/auth/oauth2/callback/google?state=...&code=..."
```

---

#### POST /auth/oauth2/exchange

Exchange a one-time code from the OAuth2 callback redirect for the access token. The code is valid for 60 seconds and can only be used once (atomic get-and-delete).

**Authentication:** None

**Request body:**

```json
{
  "code": "abc123..."
}
```

**Success response:** `200 OK`

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Missing or malformed request body |
| 400 | `invalid_or_expired_code` | Code not found, expired, or already used |

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/oauth2/exchange \
  -H "Content-Type: application/json" \
  -d '{"code":"abc123..."}'
```

---

### Client Credentials

---

#### POST /client/token

Authenticate a service client and issue an access token using the OAuth2 client credentials grant. Supports both HTTP Basic authentication and form-encoded credentials.

**Authentication:** HTTP Basic (client_id:client_secret) or form body
**Rate limit:** 10 requests per minute (per IP)

**Request body (form-encoded alternative):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Conditional | Client ID (if not using Basic auth) |
| `client_secret` | string | Conditional | Client secret (if not using Basic auth) |
| `scope` | string | No | Space-separated requested scopes |

**Success response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "user:read user:write"
}
```

Requested scopes are intersected with the client's allowed scopes. If no scopes are requested, all allowed scopes are granted.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_scope` | Requested scopes have no overlap with allowed scopes |
| 401 | `invalid_client_credentials` | Missing, malformed, or wrong client credentials |
| 401 | `client_revoked` | Client has been deactivated |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |

**curl examples:**

```bash
# Using Basic auth
curl -X POST https://vault42.example.com/client/token \
  -u "client-id:client-secret" \
  -d "scope=user:read"

# Using form body
curl -X POST https://vault42.example.com/client/token \
  -d "client_id=my-client&client_secret=my-secret&scope=user:read"
```

---

### Admin Endpoints

> **Note:** Key management endpoints (`POST /admin/keys/rotate`, `GET /admin/keys`, `DELETE /admin/keys/{kid}`) have moved to the **admin gateway** (`cmd/admin-gateway/`), which provides mTLS + RBAC + session authentication with 6-layer local-only enforcement. See the admin gateway documentation for details.

---

### Well-Known

---

#### GET /.well-known/jwks.json

Return the JSON Web Key Set (JWKS) containing the server's public RSA keys used to verify JWT signatures.

**Authentication:** None

**Response headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |
| `Cache-Control` | `public, max-age=300` |

**Success response (200 OK):**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-uuid-1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 500 | `internal_error` | Failed to serialize JWKS |

**curl example:**

```bash
curl https://vault42.example.com/.well-known/jwks.json
```

---

#### GET /.well-known/openid-configuration

Return the OpenID Connect Discovery document.

**Authentication:** None

**Success response (200 OK):**

```json
{
  "issuer": "https://vault42.example.com",
  "authorization_endpoint": "https://vault42.example.com/auth/oauth2/authorize",
  "token_endpoint": "https://vault42.example.com/auth/login",
  "userinfo_endpoint": "https://vault42.example.com/user/profile",
  "jwks_uri": "https://vault42.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://vault42.example.com/auth/register",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["RS256", "ES256"]
}
```

**curl example:**

```bash
curl https://vault42.example.com/.well-known/openid-configuration
```

---

## Endpoint Summary

| Method | Path | Auth | Rate Limit | Description |
|--------|------|------|------------|-------------|
| `GET` | `/healthz` | None | -- | Liveness probe |
| `GET` | `/readyz` | None | -- | Readiness probe |
| `GET` | `/metrics` | None | -- | Prometheus metrics (requires `VAULT_METRICS_ENABLED=true`) |
| `POST` | `/auth/register` | None | 3/hour | Register new user |
| `GET` | `/auth/verify-email` | None | 10/hour | Verify email address |
| `POST` | `/auth/login` | None | 5/15min | Authenticate user |
| `POST` | `/auth/refresh` | Cookie | 30/min | Refresh access token |
| `POST` | `/auth/logout` | Bearer | -- | Revoke all sessions |
| `POST` | `/auth/confirm` | Bearer | 5/15min | Confirm password for elevated access |
| `POST` | `/auth/password/reset` | None | 3/hour | Request password reset |
| `POST` | `/auth/password/reset/confirm` | None | 3/hour | Complete password reset |
| `POST` | `/user/password` | Bearer | -- | Change password |
| `GET` | `/user/profile` | Bearer | -- | Get user profile |
| `GET` | `/user/sessions` | Bearer | -- | List active sessions |
| `DELETE` | `/user/sessions/{id}` | Bearer | -- | Revoke a session |
| `DELETE` | `/user/sessions` | Bearer | -- | Revoke all sessions |
| `GET` | `/user/devices` | Bearer | -- | List devices |
| `PATCH` | `/user/devices/{id}` | Bearer | -- | Rename device |
| `DELETE` | `/user/devices/{id}` | Bearer | -- | Remove device |
| `GET` | `/auth/2fa/status` | Bearer | -- | Get MFA status |
| `POST` | `/auth/2fa/totp/setup` | Bearer + Confirm | -- | Begin TOTP setup |
| `POST` | `/auth/2fa/totp/verify` | Bearer/Challenge | 5/5min | Verify TOTP code |
| `DELETE` | `/auth/2fa/totp` | Bearer + Confirm | -- | Disable TOTP |
| `POST` | `/auth/2fa/webauthn/register/begin` | Bearer + Confirm | -- | Begin WebAuthn registration |
| `POST` | `/auth/2fa/webauthn/register/finish` | Bearer + Confirm | -- | Complete WebAuthn registration |
| `POST` | `/auth/2fa/webauthn/verify/begin` | Bearer/Challenge | -- | Begin WebAuthn verification |
| `POST` | `/auth/2fa/webauthn/verify/finish` | Bearer/Challenge | -- | Complete WebAuthn verification |
| `GET` | `/auth/2fa/webauthn/credentials` | Bearer | -- | List WebAuthn credentials |
| `DELETE` | `/auth/2fa/webauthn/credentials/{id}` | Bearer + Confirm | -- | Delete WebAuthn credential |
| `POST` | `/auth/2fa/backup-codes` | Bearer + Confirm | -- | Generate backup codes |
| `POST` | `/auth/2fa/email-otp/verify` | Bearer/Challenge | 5/5min | Verify email OTP code |
| `POST` | `/auth/2fa/email-otp/resend` | Bearer/Challenge | 5/5min | Resend email OTP code |
| `GET` | `/user/identity` | Bearer | -- | Get identity profile |
| `PUT` | `/user/identity` | Bearer | -- | Upsert identity profile |
| `DELETE` | `/user/identity` | Bearer | -- | Delete identity profile |
| `POST` | `/user/blobs` | Bearer | -- | Upload encrypted blob |
| `GET` | `/user/blobs` | Bearer | -- | List blobs + quota |
| `GET` | `/user/blobs/{id}` | Bearer | -- | Download decrypted blob |
| `DELETE` | `/user/blobs/{id}` | Bearer | -- | Delete blob |
| `GET` | `/auth/oauth2/authorize` | None | -- | Start OAuth2 flow |
| `GET` | `/auth/oauth2/callback/{provider}` | None | -- | OAuth2 callback |
| `POST` | `/auth/oauth2/exchange` | None | -- | Exchange OAuth2 one-time code for tokens |
| `POST` | `/client/token` | Basic | 10/min | Client credentials grant |
| `GET` | `/.well-known/jwks.json` | None | -- | JWKS public keys |
| `GET` | `/.well-known/openid-configuration` | None | -- | OpenID Connect discovery |

**Auth column key:**
- **None** -- Public endpoint, no authentication required
- **Cookie** -- Requires `refresh_token` HttpOnly cookie
- **Bearer** -- Requires `Authorization: Bearer <token>` header with fingerprint verification
- **Bearer + Confirm** -- Requires Bearer token + recent password confirmation via `POST /auth/confirm`
- **Bearer/Challenge** -- Accepts both standard Bearer tokens and 2FA challenge tokens
- **Basic** -- HTTP Basic authentication with client credentials
- **Admin** -- Key management is handled by the admin gateway (mTLS + RBAC); not exposed on the main vault42 binary

---

## Cookie Reference

| Cookie | Path | Attributes | Set By | Cleared By |
|--------|------|------------|--------|------------|
| `refresh_token` | `/auth` | `HttpOnly`, `Secure` (when TLS), `SameSite=Strict` | Login, Refresh, TOTP Verify (MFA), WebAuthn Verify Finish (MFA), Email OTP Verify (MFA), OAuth2 Callback | Logout, Refresh (on error) |

The `Secure` flag is derived from the server's TLS configuration, not the profile name. In development with TLS enabled, cookies are still marked `Secure`.
