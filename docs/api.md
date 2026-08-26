# API Reference

> Vault42 -- JWT Authentication & Authorization Microservice
> **API v1 · document version 1.0.0**

## Overview

Vault42 is a production-grade Go authentication and authorization service. All endpoints are served over HTTPS with TLS 1.3 minimum. The API uses JSON for request and response bodies.

**Versioning.** There is no `/v1` path prefix and there will not be one: the release's major version *is* the API version, and the root paths are v1 permanently. [`spec.md` section 0](spec.md#0-api-stability-contract) is the normative stability contract -- what may change in a minor release, what costs a major one, and which surfaces (`risk_score`, DPoP-Nonce and refresh-token sender-binding, the admin HTML console, the `/metrics` body) are excluded from the promise entirely. Read it before building against anything here.

Two rules from that contract that change how a client is written:

- **Clients MUST ignore response fields they do not recognise.** New response fields are added in minor releases.
- **Clients MUST NOT feature-probe by sending an optional request field.** The main binary decodes with `DisallowUnknownFields()`, so an unknown key in a request body is a hard `400` and the whole request fails, not just the unknown part. Use `GET /auth/capabilities` instead. No endpoint reports the running version -- `GET /healthz` omits it deliberately, so as not to hand an attacker a version to match against a CVE -- which makes capability discovery the only in-band channel. The admin gateway is looser and ignores unknown keys; do not rely on either behaviour beyond what the contract states.

**Base URL convention:** `https://vault42.example.com`

**Common request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes (POST/PUT/PATCH) | Must be `application/json` |
| `Authorization` | Authenticated endpoints | `Bearer <access_token>` |
| `User-Agent` | Recommended | Included in device fingerprint computation |
| `Accept-Language` | Recommended | Included in device fingerprint computation |
| `X-Vault-App` | No | White-label tenant slug (`^[a-z0-9][a-z0-9_-]{0,63}$`), proxy-set only. Selects the per-app branding and template overrides applied to auth emails sent while handling the request. See [White-Label Tenant Selection](#white-label-tenant-selection). |

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

### White-Label Tenant Selection

`X-Vault-App` names the tenant whose app name, logo, primary colour, From display name and template overrides an auth email (verification, password reset, new device, email OTP, ...) is rendered with. An absent, malformed or unknown slug renders the global branding, and with no branding rows configured the header has no effect at all.

The endpoints that send those emails are unauthenticated by design, so the header is **not** a client-supplied value: it is only honoured when the request reaches Vault42 from a peer inside `TRUSTED_PROXIES`. The gateway or BFF in front of Vault42 sets it per tenant and overwrites whatever the client sent. A request arriving directly, or through an untrusted peer, selects no tenant and gets the global branding -- otherwise any outside caller could make a genuine password-reset email for a victim on one tenant arrive wearing a different tenant's identity.

The slug is validated for shape only; it is never an authorization decision, which is why the trust boundary is the proxy and not the value. There is no `?app=` query parameter: a proxy forwards the client's query string verbatim, so a query parameter can never be an operator-controlled channel.

---

## Authentication

### Bearer Token Authentication

Most endpoints require a valid JWT access token in the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

Access tokens are RS256-signed JWTs with a short TTL (typically 5-15 minutes). They are stateless and fingerprint-bound.

The `Bearer` scheme is accepted for any token that does not carry `cnf.jkt`. The `DPoP` scheme is rejected with `401 invalid_authorization` unless `VAULT_DPOP_ENABLED` is set. When the flag is on, a token issued with a DPoP proof carries `cnf.jkt` and must be presented as `Authorization: DPoP <token>` with a matching proof. A token issued without a proof stays an ordinary bearer token. See `spec.md` section 0.6.2.

### 2FA Challenge Tokens

When a user has MFA enabled, the login endpoint returns a `challenge_token` instead of a full access token. This short-lived token (5-minute TTL, `token_type: "2fa_challenge"`) must be presented to a 2FA verify endpoint to complete authentication: `POST /auth/2fa/totp/verify`, `POST /auth/2fa/webauthn/verify/begin`, `POST /auth/2fa/webauthn/verify/finish`, `POST /auth/2fa/backup-code/verify`, `POST /auth/2fa/email-otp/verify`, or `POST /auth/2fa/email-otp/resend`.

A challenge token is not accepted by any other endpoint, so it cannot be used for ordinary API access.

### Client Credentials (Basic Auth)

The `POST /client/token` endpoint accepts HTTP Basic authentication:

```http
Authorization: Basic base64(client_id:client_secret)
```

Alternatively, `client_id` and `client_secret` can be sent as form values in the request body.

### Password Confirmation (Elevated Access)

Sensitive operations require a recent password confirmation via `POST /auth/confirm`, which opens a 5-minute elevated window. The full set is TOTP setup and disable, WebAuthn registration and deletion, backup code generation, identity erasure (`DELETE /user/identity`), and both blob deletions (`DELETE /user/blobs/{id}` and `DELETE /user/blobs/named/{name}`) -- the last three are destructive and were missing from this list. Endpoints requiring confirmation return `403 requires_confirmation`.

The window is bound to the access token that opened it, not just to the user: the server records the confirming token's `jti` and refuses a request presenting any other token. Refreshing therefore closes the window, and a client that refreshes between the confirm and the delete has to confirm again.

---

## Device Fingerprint

The fingerprint is `SHA256(IP + User-Agent + Accept-Language + TLS-fingerprint)`, computed at issuance and carried in the access token as the `fingerprint` claim. The TLS-fingerprint component comes from the header named by `VAULT_TLS_FINGERPRINT_HEADER` (e.g. `X-TLS-Fingerprint`), which the TLS-terminating proxy must set; with that variable unset the component is empty and the other three still apply.

Whether a given request is actually checked turns on two conditions, and both of them have exceptions, so neither is worth stating as "authenticated requests are fingerprint-verified".

**1. The route has to run the check.** It is mounted on every authenticated end-user route in `internal/server/server.go`: through the `authed`, `confirmed` and `authedChallenge` wrappers, or inlined in the same order on the routes that carry their own rate limiter or confirmation gate. The machine endpoints deliberately do not run it, because a service client has no device to bind to:

<!-- BEGIN FINGERPRINT EXEMPTIONS -->

| Authenticated route | Fingerprint check |
|---------------------|-------------------|
| `POST /mint` | Not mounted -- machine endpoint |
| `POST /kms/unwrap` | Not mounted -- machine endpoint |
| `PUT /service/documents/{subject}/{key}` | Not mounted -- machine endpoint |
| `GET /service/documents/{subject}/{key}` | Not mounted -- machine endpoint |
| `DELETE /service/documents/{subject}/{key}` | Not mounted -- machine endpoint |
| `GET /service/documents/{subject}` | Not mounted -- machine endpoint |

<!-- END FINGERPRINT EXEMPTIONS -->

Every other authenticated route runs it. `tests/spec/fingerprint_docs_test.go` compares that table against the chain the server installs and fails if either side moves.

**2. The presented token has to carry the claim.** `middleware.Fingerprint` passes a request whose token has no `fingerprint` claim straight through rather than rejecting it (`internal/middleware/fingerprint.go`). Tokens issued by `POST /auth/login`, `POST /auth/refresh` and the 2FA challenge flow carry one. Tokens issued by `POST /client/token` and `POST /mint` do not -- both are issued with an empty fingerprint -- so a machine token presented to a user route is not fingerprint-checked, even on a route that mounts the check. That is the shipped behaviour and not an oversight: those tokens are constrained by scope and by DPoP, not by a device.

When both conditions hold and the recomputed value differs from the claim, the request is rejected with:

```json
{"error": "invalid_token"}
```

Status: `401 Unauthorized`

The per-endpoint sections below do not repeat any of this. They used to carry an unqualified `Fingerprint: Verified` line on 38 routes, which was true of the chain and not true of the request: it said nothing about condition 2 and nothing about the six routes above.

---

## Common Response Format

### Success responses

Success responses have an appropriate HTTP status code (200, 201) and a JSON body whose shape is endpoint-specific. Four conventions hold everywhere:

- **Field names are `snake_case`.** No response carries a Go field name or a camelCase key.
- **Timestamps are RFC 3339 in UTC.** Fractional seconds may be present, so parse RFC 3339 generally rather than matching a fixed layout.
- **A list field is always an array.** An empty collection is `[]`, never `null`. Changing that in either direction is a breaking change.
- **List responses carry `{<collection>, total, limit, offset}`** where the endpoint is paged. `total` is present even on an empty result. On the admin gateway `limit` defaults to 50 and is clamped to 100; an out-of-range value falls back to the default rather than erroring.
- **`total` does not imply pagination.** `GET /user/sessions` and `GET /user/devices` are unpaged and still return `total` alongside the collection, because the count is useful and costs nothing when the whole set is already in the response. `GET /user/backup-codes` and the WebAuthn credential list return the collection key alone. So read `limit` and `offset` to decide whether an endpoint pages, never `total` -- an earlier version of this page said unpaged collections return the collection key alone, which was never true of the two largest ones.

### Error responses

All errors follow a consistent shape:

```json
{"error": "error_code_here"}
```

Error codes are lowercase, underscore-separated strings (e.g., `invalid_credentials`, `rate_limit_exceeded`).

---

## Rate Limiting

Rate limits are enforced per-IP, per-user, or per-client depending on the endpoint. When rate limiting is active, the following headers are present on every response (including successful ones):

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum number of requests allowed in the window |
| `X-RateLimit-Remaining` | Number of requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

When the limit is exceeded:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: <window_seconds>
```

```json
{"error": "rate_limit_exceeded"}
```

**Behaviour when the cache backend is unavailable depends on the endpoint.** An ordinary limiter falls back to a per-process in-memory counter, so the limit stays enforced per pod and authentication does not fail merely because the cache is down. The limiters guarding credentials and key material do not take that fallback -- login, registration, both password-reset endpoints, account deletion, `POST /client/token`, the TOTP, backup-code and email-OTP verify endpoints, `POST /auth/2fa/email-otp/resend`, `POST /kms/unwrap` and `POST /mint` -- because a per-pod counter would multiply the effective limit by the replica count. Those reject instead:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: <window_seconds>
```

```json
{"error": "rate_limiter_unavailable"}
```

That list is the whole of the 2FA surface that is limited at all. `POST /auth/2fa/webauthn/verify/begin` and `POST /auth/2fa/webauthn/verify/finish` carry **no** rate limiter, fail-closed or otherwise, and a cache outage changes nothing for them. This page used to say every 2FA verify was fail-closed, which read as a stronger guarantee than the mux keeps. The asymmetry is deliberate and argued at `internal/server/server.go:641-656`: the other three cap a guessing budget over a six-digit code, while a WebAuthn assertion is a signature over a server-chosen challenge and has no budget to cap, and any per-IP bucket small enough to bound the work would sign a whole NAT out of its own second factor.

`spec.md` section 8.1 lists which limiter each endpoint carries, and omits the WebAuthn verify pair for the same reason.

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

Prometheus metrics in the text exposition format, when `VAULT_METRICS_ENABLED=true`.

**This endpoint is not on the API listener.** It has its own, bound to
`127.0.0.1:9090` by default and set by `VAULT_METRICS_ADDR`; the server refuses to
start if that address resolves to the same port the API is on. Requesting
`/metrics` from the API port is a 404 no matter how the feature toggle is set.

The separate listener is the access control, and it replaced advice that could not
work. This page used to tell operators to restrict `/metrics` with a Kubernetes
NetworkPolicy. A NetworkPolicy selects on namespace, pod and port and knows nothing
about paths, so on a shared listener it cannot admit `POST /auth/login` and refuse
`GET /metrics` through the same port -- it either allows both or blocks both. The
counters are process-global document read and write rates, which is a coarse
cross-client volume oracle to anything that can reach them, so the port had to be
the boundary. Bind `VAULT_METRICS_ADDR` where only your monitoring can reach it,
and put the NetworkPolicy on that port.

**Authentication:** None

**Feature toggle:** `VAULT_METRICS_ENABLED=true` (default: `false`). When disabled, the endpoint is not registered and returns 404.

**Response headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | `text/plain; version=0.0.4; charset=utf-8` |

**Success response (200 OK):**

```text
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

# HELP vault_audit_buffer_full_total Audit events that arrived to a full in-memory buffer
# TYPE vault_audit_buffer_full_total counter
vault_audit_buffer_full_total 0

# HELP vault_audit_events_dropped_total Buffered audit entries discarded because a rejected batch would not fit back into the buffer
# TYPE vault_audit_events_dropped_total counter
vault_audit_events_dropped_total 0
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
| `vault_audit_buffer_full_total` | Counter | Audit events that arrived to a full in-memory buffer. Non-critical events were discarded; critical event types were written straight to the store instead |
| `vault_audit_events_dropped_total` | Counter | Buffered audit entries discarded because the store rejected the batch and the retry would not fit back into the buffer |

**Audit loss alerting:**

Both audit counters mean records went missing, and both are worth an alert, but
they are answered differently and should not be summed into one rule.

`vault_audit_buffer_full_total` rising means the process is producing audit
events faster than `VAULT_AUDIT_FLUSH_INTERVAL` drains them. The store is
healthy. Raise `VAULT_AUDIT_BUFFER_SIZE`, shorten the flush interval, or shed
load. Sustained growth here can also be someone flooding an audited path to bury
activity in discarded events.

`vault_audit_events_dropped_total` rising means the audit store rejected a batch
and the retry had nowhere to put the entries. Those entries were already
reported to their callers as written, so each one is a hole in an append-only
trail that has no second copy. Treat any increase as a database incident.

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
  "status": "verification_email_sent",
  "message": "If this email is not already registered, a verification email has been sent."
}
```

This is the **only** body this endpoint returns on success, and it is byte-identical
whether the address was free or already registered -- that identity is the
anti-enumeration property, and it is why no identifier appears here. An earlier
version of this page showed a `{user_id, email}` body, which the handler has never
emitted: it discards the created user and writes the message above on both paths.
A client cannot learn the new user's id from registration, and must not be written
as though it can.

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
**Rate limit:** 5 requests per 15 minutes (per IP), fail-closed. A cache outage rejects with `503 rate_limiter_unavailable` rather than falling back to a per-pod counter.

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

The response also sets the refresh cookie: `__Host-refresh_token`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.

The `__Host-` prefix is not decoration and the name is not shortenable. A browser only accepts a cookie under that prefix if it is `Secure`, has `Path=/`, and carries no `Domain`, and it refuses the `Set-Cookie` outright otherwise -- which is what makes the cookie unsettable by a subdomain. This page previously called the cookie `refresh_token` and placed it on the `/auth` path; both were wrong, and the second is not a thing a `__Host-` cookie can be. Read it by its full name.

**Success response -- MFA required (200 OK):**

```json
{
  "requires_2fa": true,
  "challenge_token": "eyJhbGciOiJSUzI1NiIs...",
  "available_methods": ["totp", "webauthn", "backup_code"]
}
```

No refresh token cookie is set until MFA is completed.

**Field naming.** `mfa_methods` is the canonical name for this list, and `GET /auth/2fa/status` emits it. This endpoint still emits the pre-1.0.0 `available_methods` and `requires_2fa`. Clients SHOULD read `mfa_methods` where it is present and fall back to `available_methods`; both name the same list. The `mfa_` names are canonical because the product supports more than two factors, while the URL paths keep `2fa` (`/auth/2fa/*`) because renaming a route is a breaking change. `available_methods` is deprecated and will be removed at 2.0.0. See `spec.md` section 4.4.

Both fields carry `omitempty`, so on a non-MFA login they are absent rather than `null`.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Malformed JSON |
| 401 | `invalid_credentials` | Wrong email/password, an unverified/deleted/import-pending account, or a banned/disabled account without the correct password (identical response for anti-enumeration) |
| 403 | `account_locked` | The per-IP lockout tripped (IP-scoped; reveals nothing about any account). The per-user lockout answers 401 instead, so it cannot be used to enumerate. |
| 403 | `account_banned` | The account is banned. Returned only after a successful password verification, so a caller without the password cannot distinguish it from an unknown address. |
| 403 | `account_disabled` | The account is disabled. Returned only after a successful password verification, same anti-enumeration property as `account_banned`. |
| 403 | `password_reset_required` | A password reset was required and has been mailed. Not a credential the caller can correct by retrying; the code says a reset was mailed and nothing else -- not the address, not whether the password was right, which this branch never checked |
| 429 | `rate_limit_exceeded` | Login rate limit exceeded |
| 429 | `too_many_sessions` | The concurrent-session cap is full. The password was correct; no session was issued. Clears by revoking a session, not by waiting |
| 500 | `internal_error` | Server error |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |
| 503 | `rate_limiter_unavailable` | Cache backend down; the login limiter fails closed |

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

Exchange a refresh token (from the `__Host-refresh_token` cookie) for a new access token and a new refresh token. Implements single-use rotation with family-based replay detection.

**Authentication:** None (uses cookie)
**Rate limit:** 30 requests per minute (per IP)
**Cookie required:** `__Host-refresh_token` (set by login/previous refresh)

**Request body:** None

The refresh token is read from the `__Host-refresh_token` HttpOnly cookie, not from the request body.

**Success response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Sets a new `__Host-refresh_token` cookie (the old refresh token is invalidated).

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `missing_refresh_token` | No `__Host-refresh_token` cookie present |
| 401 | `replay_detected` | Refresh token reuse detected; entire token family revoked |
| 401 | `token_expired` | Refresh token has expired |
| 401 | `invalid_token` | Token not found, revoked, or fingerprint mismatch |
| 403 | `account_banned` | The account was banned since the token was issued |
| 403 | `account_disabled` | The account was disabled since the token was issued |
| 403 | `account_locked` | The account carries an operator lock |
| 500 | `internal_error` | Server error |

On any error, the `__Host-refresh_token` cookie is cleared.

The three `403`s are refusals by policy, not token failures: the refresh token
was valid and the account state rejected it. They are answered as `403` rather
than `500` so that a bulk ban does not read as a service fault, and the cookie is
cleared with them, because a refresh token belonging to a banned account is not
one the browser should keep presenting. A client MUST NOT retry these; they clear
only when an operator lifts the state.

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

**Request body:** None

**Success response (200 OK):**

```json
{"status": "logged_out"}
```

Clears the `__Host-refresh_token` cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `missing_authorization` | No Authorization header |
| 401 | `invalid_token` | Token invalid, expired, or device fingerprint mismatch |
| 401 | `unauthorized` | No claims on the request. A defensive guard behind the auth middleware, which answers `missing_authorization` or `invalid_authorization` first |
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
**Rate limit:** 5 requests per 15 minutes, keyed on the **authenticated user**, not the
IP. This route sits behind the auth middleware, so a token is always present and the
bucket is `user:<subject>`; the per-IP fallback in the key function is unreachable here.

**The bucket is shared with five other routes.** `POST /auth/confirm`,
`POST /user/password`, `DELETE /user/identity`, `DELETE /user/blobs/{id}`,
`DELETE /user/blobs/named/{name}` and `DELETE /user/social/{id}` all draw on the same
five-per-fifteen-minutes allowance. That is deliberate -- they are the operations that
sit around a password confirmation, and one budget across them is what stops the
confirmation window being spent elsewhere -- but it means a client that burns the budget
changing a password cannot then delete a blob, and the 429 it gets back will name the
blob route. Budget across the group rather than per endpoint.

**Sharing the bucket is not the same as being confirmation-gated.** Only three of
the six actually require a recent `POST /auth/confirm` and answer
`403 requires_confirmation` without one: `DELETE /user/identity`,
`DELETE /user/blobs/{id}` and `DELETE /user/blobs/named/{name}`. This endpoint is
the confirmation itself. `POST /user/password` takes the current password in its
own body instead. `DELETE /user/social/{id}` requires neither -- a valid access
token is enough to unlink a federated identity. Do not read the shared bucket as
evidence that a route re-checks the password.

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
| 401 | `invalid_token` | Device fingerprint mismatch |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 429 | `too_many_attempts` | Five wrong passwords against this endpoint locked the confirm counter for this user. Distinct from `rate_limit_exceeded`: that one is the shared six-route budget, this one is a per-account brute-force lock on confirmation itself, and it is checked before the password is read |
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
| 400 | `password_breached` | New password found in the HIBP breach database |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |
| 500 | `import_claim_failed` | The password was set but the account's `import_pending` flag could not be cleared. Fails closed rather than reporting success: the flag stands, so the next login re-issues a claim link and the account is recoverable |
| 500 | `forced_reset_clear_failed` | The password was set but the forced-reset flag could not be cleared. Same fail-closed reason: reporting success while the flag stands would tell the user they are finished when the next login will refuse them |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |
| 503 | `rate_limiter_unavailable` | Cache backend down; this limiter fails closed |

**The reset token is spent before the new password is validated.** It is consumed
by an atomic get-and-delete, deliberately, to close a reuse race -- so
`password_breached` and `password_recently_used` reject the request *after* the
token is already gone, and the same link cannot be retried with a better
password. Only `invalid_request` and `password_too_short` are checked ahead of
it. A client that lets the user pick a replacement password after one of those
`400`s must send them through `POST /auth/password/reset` again for a fresh link;
re-posting the old one returns `invalid_or_expired_token`.

The two `500`s are not generic faults either. In both, the new password **is
already in effect** and the token is likewise spent. The correct client response
is to attempt a login with the new password, not to restart the reset.

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
| 400 | `password_breached` | New password found in the HIBP breach database |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_current_password` | Wrong current password |
| 401 | `invalid_token` | Device fingerprint mismatch |
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

**Success response (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "display_name": "Jane Doe",
  "avatar_url": "https://cdn.example.com/avatars/jane.png",
  "locale": "en",
  "mfa_required": false,
  "mfa_enabled": true,
  "mfa_methods": ["totp"],
  "created_at": "2025-01-15T10:30:00Z"
}
```

`avatar_url` is readable here as well as writable through `PUT /user/profile`. Before 1.0.0 it was write-only: a client could set it and could only read it back through the GDPR export.

`mfa_methods` is always an array; a user with no configured factor gets `[]`, never `null`.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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

**Request body:**

```json
{
  "display_name": "Jane Smith",
  "avatar_url": "https://example.com/avatar.jpg",
  "locale": "sk"
}
```

All fields are optional (pointer semantics -- omitted fields are not modified):

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

List the authenticated user's active sessions. A session is a refresh-token
family, which is not the same thing as a device: a device can carry several
families, and a family whose device resolution failed at login carries none.

**Authentication:** Bearer token

**Success response (200 OK):**

```json
{
  "sessions": [
    {
      "id": "0f6c2a1e-9b3d-4c77-8a10-2b5e6d4f9c31",
      "device_id": "3d9a7b52-0c14-4e88-9f6a-71c2e5804db3",
      "friendly_name": "Chrome on Windows",
      "ip": "203.0.113.42",
      "user_agent": "Mozilla/5.0...",
      "trusted": false,
      "last_seen_at": "2025-06-15T14:30:00Z",
      "first_seen_at": "2025-06-01T08:00:00Z",
      "created_at": "2025-06-01T08:00:00Z",
      "expires_at": "2025-06-29T08:00:00Z"
    }
  ],
  "total": 1
}
```

`id` is the **refresh-token family** UUID and is what `DELETE
/user/sessions/{id}` addresses. It is not the device id, and this document
previously showed it as one. The distinction is the whole point of the field:
when `id` was the device UUID, a family carrying no device was invisible in this
list and could not be revoked at all, and two families sharing one fingerprint
collapsed into a single row that revoked only one of them.

`device_id` is the device the session is bound to, or `""` when device
resolution failed at login. Empty means a session with no device metadata, never
a session that does not exist -- so do not treat it as a key.

`trusted` is the remembered-device flag. Current issuance never sets it, so
`false` is the only value observed today. `last_seen_at` is null on a session
that has never been refreshed.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

**Success response (200 OK):**

```json
{"status": "all_sessions_revoked"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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

**Success response (200 OK):**

```json
{
  "devices": [
    {
      "id": "device-uuid-1",
      "friendly_name": "Chrome on Windows",
      "trusted": false,
      "ip": "203.0.113.42",
      "user_agent": "Mozilla/5.0...",
      "last_seen_at": "2025-06-15T14:30:00Z"
    }
  ],
  "total": 1
}
```

The device fingerprint hash is not returned. It is what the server matches a
device on, and handing it to a client would let one device present another
device's identity. `id` is the identifier every endpoint here addresses, and
the only one a client needs.

`trusted` is the remembered-device flag. Current issuance never sets it, so it
is `false` on every device today. `last_seen_at` is null only on a row that has
never been refreshed.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

### Account Lifecycle

Self-service erasure and data portability. Both are subject rights under the GDPR, and both are reachable by the account holder without an operator in the loop.

---

#### DELETE /user/account

Erase the authenticated user's account. **This is the most destructive endpoint in the API.** It is irreversible from the service's own side: the only path back is an offline recovery key that the server does not hold.

**Mounted only when an account-recovery repository is wired.** Where it is not, the route does not exist and answers a `text/plain` 404 rather than the JSON error envelope.

**Authentication:** Bearer token **and** the current password in the request body. A stolen access token alone cannot erase an account.
**Rate limit:** 3 requests per hour (per IP), fail-closed

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | string | Yes | The account's current password, re-entered |

**What is erased:** the identity profile, all blobs, devices, linked social accounts, password history, refresh tokens, TOTP secrets, WebAuthn credentials and backup codes. The user row is scrubbed and soft-deleted (tombstoned) so that foreign keys stay intact and the account stops authenticating immediately.

**What survives, and why:** the audit log and the recovery escrow. Both are append-only by database trigger, and both are bounded by a retention horizon instead of by the erasure cascade (`VAULT_AUDIT_RETENTION_DAYS`, `VAULT_RECOVERY_RETENTION_DAYS` / `vault cleanup-recovery`). `vault cleanup-audit` is retired and writes nothing. The escrow row holds the erased email RSA-encrypted to a key whose private half is offline, so a compromised server cannot read it back.

**Order matters:** escrow, then tombstone, then purge. The account stops authenticating before any PII is destroyed, so an interrupted erasure leaves an account that is dead but not yet fully purged -- never one that is still loginable but has already lost its second factors. Every step is idempotent; re-issuing the request finishes an interrupted erasure.

**Success response (200 OK):**

```json
{
  "status": "deleted"
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `password_required` | Body missing or `password` empty |
| 401 | `invalid_password` | Wrong password (audited as a failed login) |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
| 404 | `not_found` | Account already erased |
| 429 | `rate_limit_exceeded` | Deletion rate limit exceeded |
| 500 | `internal_error` | Erasure failed; the account may be tombstoned but not fully purged. Retry. |
| 503 | `server_busy` | Argon2id semaphore full (load shedding) |
| 503 | `rate_limiter_unavailable` | Cache backend down; this limiter fails closed |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/account \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{"password": "my-secure-passphrase-here"}'
```

---

#### GET /user/data-export

Return every category of personal data the service holds for the authenticated user, in one JSON document. Satisfies the right of access (GDPR Article 15) and the right to data portability (Article 20).

The endpoint aggregates the live repositories and stores nothing of its own, so an export cannot drift from what is actually held.

**Authentication:** Bearer token
**Rate limit:** 5 requests per minute (per IP)

**Success response (200 OK):**

```json
{
  "generated_at": "2026-08-10T12:00:00Z",
  "account": {
    "id": "user-uuid",
    "email": "user@example.com",
    "email_verified": true,
    "display_name": "Alice",
    "avatar_url": "",
    "locale": "en",
    "roles": ["user"],
    "mfa_required": true,
    "disabled": false,
    "banned": false,
    "created_at": "2026-01-04T09:12:00Z",
    "updated_at": "2026-08-01T18:40:00Z",
    "last_login_at": "2026-08-10T08:03:00Z"
  },
  "identity": { "given_name": "Alice", "family_name": "Example", "country": "SK" },
  "devices": [
    {"id": "device-uuid", "friendly_name": "Firefox on Linux", "trusted": false,
     "ip": "203.0.113.10", "user_agent": "Mozilla/5.0 ...",
     "first_seen_at": "2026-01-04T09:12:00Z", "last_seen_at": "2026-08-10T08:03:00Z"}
  ],
  "blobs": [
    {"id": "blob-uuid", "label": "notes", "named": false, "size_bytes": 2048,
     "checksum": "sha256:...", "created_at": "2026-03-02T11:00:00Z"}
  ],
  "social_accounts": [
    {"provider": "google", "provider_user_id": "1234567890",
     "email": "user@example.com", "created_at": "2026-01-04T09:14:00Z"}
  ],
  "audit_events": [
    {"timestamp": "2026-08-10T08:03:00Z", "event_type": "login_success",
     "ip": "203.0.113.10", "user_agent": "Mozilla/5.0 ..."}
  ],
  "service_documents": [
    {"key": "prefs.editor", "owner_id": "550e8400-e29b-41d4-a716-446655440000",
     "visibility": "private", "size_bytes": 84,
     "document": {"theme": "dark", "tab_width": 4},
     "created_at": "2026-02-11T10:20:00Z", "updated_at": "2026-07-19T13:05:00Z"}
  ],
  "audit_events_total": 4210,
  "audit_events_limit": 1000,
  "audit_events_truncated": true
}
```

**Blob contents are never included** -- only metadata (id, label, size, checksum, created_at). Provider access and refresh tokens on linked social accounts are excluded by design.

**Audit events are capped at 1000, most recent first.** Because a silently truncated export is indistinguishable from a complete one, the response always states the shape of the truncation: `audit_events_total` is how many exist, `audit_events_limit` is the cap, and `audit_events_truncated` says whether it was reached. A subject who sees `true` can ask the Operator for the remainder rather than assuming this is everything.

`identity` is `null` when the identity store is disabled or the user has set no profile. `blobs` is `[]` when blob storage is disabled.

**`service_documents` carries the document bodies in full**, unlike `blobs`, which carries metadata only. A service document is arbitrary caller-supplied JSON stored against the user, so it is personal data the subject is entitled to receive and there is no metadata-only form of it that would satisfy the request. This category was missing from this page entirely until 1.0.3, which understated what an export contains -- the wrong direction for a document a data-subject or a DPO reads to decide whether the export is complete. `owner` appears only when the document is owned by someone other than the exporting user.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
| 429 | `rate_limit_exceeded` | Export rate limit exceeded |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl https://vault42.example.com/user/data-export \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -o my-vault42-data.json
```

---

### Identity Store

Encrypted personal identity information (PII). All fields are encrypted at rest with AES-256-GCM and stored under a pseudonymous key derived via `HMAC-SHA256(userID + ":identity", hmac_secret)`.

---

#### GET /user/identity

Retrieve the authenticated user's identity profile. Returns decrypted fields.

**Authentication:** Bearer token

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

**Request body:**

| Field | Type | Max Length | Validation |
|-------|------|-----------|------------|
| `given_name` | string | 100 runes | Truncated if longer |
| `family_name` | string | 100 runes | Truncated if longer |
| `country` | string | 2 chars | ISO 3166-1 alpha-2 (`^[A-Z]{2}$`) |
| `date_of_birth` | string | -- | ISO 8601 date (`YYYY-MM-DD`), must not be in the future |
| `username` | string | 3--32 runes | Outside that range is `400 invalid_profile`, not a truncation |
| `state` | string | 3 runes | Subdivision code. Longer is `400 invalid_profile`, not a truncation |
| `sex` | string | -- | Closed vocabulary: `male`, `female`, or empty. Anything else is `400 invalid_profile` |
| `marketing_emails` | bool | -- | See Marketing Consent below. Omitting the key leaves the stored consent untouched; sending `false` withdraws it |
| `dynamic` | object | 64 KiB encoded | Namespaced opaque JSON, see below |
| `billing` | object | -- | Optional billing address |
| `billing.address_line_1` | string | 200 runes | Truncated if longer |
| `billing.address_line_2` | string | 200 runes | Truncated if longer |
| `billing.city` | string | 100 runes | Truncated if longer |
| `billing.postal_code` | string | 20 runes | Truncated if longer |
| `billing.country` | string | 2 chars | ISO 3166-1 alpha-2 (`^[A-Z]{2}$`) |
| `billing.vat_id` | string | 50 runes | Truncated if longer |

**`dynamic` is a per-user JSON store and its contents are never interpreted.** Keys must
match `^[a-z0-9]+(\.[a-z0-9]+)*$` and be at most 64 bytes; each value must be syntactically
valid JSON; the whole map must encode to 64 KiB or less. A violation of any of those is
`400 invalid_profile`. Sending `dynamic` replaces the stored object wholesale, and omitting
it or sending an empty object clears it, because `PUT` is a replace rather than a merge.

Two consequences worth stating, because this field was undocumented until 1.0.3 and its
shape invites the wrong assumption. It is caller-controlled storage that counts against
nothing else, so treat 64 KiB per user as the budget it is. And its contents go out in
full through `GET /user/data-export`, so anything written here is personal data the
subject receives verbatim -- do not put anything in it you would not hand back.

Note which limits truncate and which refuse. `given_name`, `family_name` and the `billing`
strings are cut to length silently. `username`, `state`, `sex`, `country` and
`date_of_birth` are validated, and a value outside their range is refused with
`400 invalid_profile` rather than trimmed.

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
| 400 | `invalid_profile` | The service-side profile validator rejected the document. Surfaced as a `400` rather than a `500` because that validator, not the handler, is the authoritative gate |
| 401 | `unauthorized` | Not authenticated |
| 409 | `concurrent_update` | The compare-and-set lost to a concurrent write -- typically `POST /user/marketing/unsubscribe` landing at the same moment. Nothing was written; re-read and retry |
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

**Authentication:** Bearer token, plus a password confirmation window. Call
`POST /auth/confirm` first; the window lasts 5 minutes and is bound to the access
token that opened it, so a refresh closes it.

**Success response (200 OK):**

```json
{"status": "deleted"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 403 | `requires_confirmation` | No open confirmation window, or it was opened by a different access token |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/identity \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

### Marketing Consent

The `marketing_emails` field on the identity profile is stored with its provenance: a consent
record carrying `granted`, `at`, `source` and (for imported accounts) `origin`. Only `registration`
and `profile` sources count as affirmative consent and authorise sending; `import` and `legacy`
preserve the value but do not (a migrated flag may be a default the user never saw — see
`docs/PRIVACY.md` §2.1). Every change writes a `consent_granted` / `consent_withdrawn` audit entry.

#### POST /user/marketing/unsubscribe

Withdraw consent for marketing email. Art. 7(3) requires withdrawal to be as easy as granting, so
this takes no body and has no confirmation step. Idempotent.

**Authentication:** Bearer token

**Success response (200 OK):**

```json
{"status": "unsubscribed"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 409 | `concurrent_update` | The compare-and-set lost to a concurrent profile write. The withdrawal was **not** recorded; retry. The compare-and-set is what stops a simultaneous `PUT /user/identity` from silently reverting it |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X POST https://vault42.example.com/user/marketing/unsubscribe \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

### Federated Identity Links

#### GET /user/social

List the caller's linked social/OIDC providers. The encrypted provider access and refresh tokens
are never returned.

**Authentication:** Bearer token

**Success response (200 OK):**

```json
{
  "accounts": [
    {"id": "3f2b...", "provider": "google", "email": "user@example.com", "created_at": "2026-07-14T09:12:00Z"}
  ]
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 500 | `internal_error` | Server error |

#### DELETE /user/social/{id}

Unlink a federated identity. Removes the link and the encrypted provider tokens stored with it.
Previously these tokens could only be removed by erasing the entire account.

The delete is scoped by user ID as well as link ID, so a caller cannot unlink another user's
provider. An ID that does not exist (or is not the caller's) reports success rather than 404 — the
response must not become an oracle for whether an ID belongs to somebody else.

**Authentication:** Bearer token

**Success response (200 OK):**

```json
{"status": "unlinked"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Empty `{id}` path segment |
| 401 | `unauthorized` | Not authenticated |
| 429 | `rate_limit_exceeded` | The shared five-per-fifteen-minutes confirmation bucket described under `POST /auth/confirm` |
| 500 | `internal_error` | Server error |

There is no `404`. An ID that does not exist, or belongs to another user, returns
`200 {"status": "unlinked"}` -- see the note above. This route draws on the
password-confirmation rate-limit bucket but does **not** itself require a recent
`POST /auth/confirm`.

---

### Encrypted Blob Storage

Encrypted file storage with per-user quotas. Blobs are compressed (DEFLATE), encrypted (AES-256-GCM), and stored under a pseudonymous key derived via `HMAC-SHA256(userID + ":objects", hmac_secret)`. Blobs are immutable -- they can be created and deleted but not updated.

**Feature toggle:** Set `VAULT_BLOB_QUOTA_BYTES=0` to disable blob storage entirely. When disabled, blob endpoints are not registered and return 404.

---

#### POST /user/blobs

Upload an encrypted blob. Accepts raw binary body or multipart form data.

**Authentication:** Bearer token

**Raw upload:**

| Header | Description |
|--------|-------------|
| `X-Blob-Label` | Optional label for the blob. Whitespace-trimmed, then **truncated** to 255 characters. See the note below the size limits |

Body: raw binary data

**Multipart upload:**

| Field | Description |
|-------|-------------|
| `file` | The file to upload (required) |
| `label` | Optional label. Whitespace-trimmed, then **truncated** to 255 characters. See the note below the size limits |

**Size limits:**

| Limit | Default | Config |
|-------|---------|--------|
| Minimum blob size | 0 (disabled) | `VAULT_BLOB_MIN_SIZE` |
| Maximum blob size | 10 MB | `VAULT_BLOB_MAX_SIZE` |
| Max files per user | 50 | `VAULT_BLOB_MAX_PER_USER` |
| Max total storage | 10 MB | `VAULT_BLOB_QUOTA_BYTES` |

**Permitted file types and extensions:** there are none to permit, and that is a
property of the feature rather than an omission. A blob is an opaque octet
stream: vault42 never parses it, never sniffs it, never decides a type for it,
and stores it encrypted, so there is no type for a policy to be about. Named
blobs are addressed by a reference from the `[a-zA-Z0-9_-]+` charset, which
excludes the dot, so a stored object has no extension either. Nothing is
extracted or unpacked, so the unpacked size equals the stored size.

**The label cap is 255 characters and it truncates.** It is counted in runes,
not bytes (`utf8.RuneCountInString`, `internal/handler/blob.go:92`), so a label
of 255 CJK characters is accepted at around 765 bytes on the wire. Over-length
is **not** an error: the label is silently cut to its first 255 runes and the
upload succeeds, so a client that does not read `label` back from the response
will not know it was shortened. This page previously gave the cap as 255 bytes,
which is wrong in both units and outcome. The only label input that is refused
is one containing a C0 control character, which is `400 invalid_label`. The
named-blob reference is a separate limit that does reject: over 255 characters
there is `400 name_too_long`.

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
| 400 | `invalid_label` | The label contains a C0 control character (U+0000-U+001F). Over-long labels are not an error: a label is truncated to 255 runes rather than rejected |
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

#### How stored objects are made safe to download

vault42 does not scan uploads for malicious content, and would have nothing to
scan: the bytes are encrypted at rest with a key the server holds and are never
interpreted. What it does instead is make sure a stored object cannot act on
retrieval.

- **Every download is scoped to the caller's own pseudonym.** `Download` and
  `DownloadNamed` resolve a blob by `(pseudonym, id)` and `(pseudonym, name)`,
  so an object is only ever served to the account that stored it. There is no
  sharing, no public URL and no cross-account read, so the case where one user's
  upload is delivered to another user does not exist.
- **`Content-Disposition: attachment`** is set on both download paths. A browser
  navigated straight at a blob URL saves the bytes rather than rendering them,
  so a stored HTML or SVG document cannot execute on vault42's origin.
- **The filename is chosen by the server, not by the caller.** It is the blob's
  own reference reduced to `[A-Za-z0-9._-]` and capped at 128 characters, with
  everything else dropped. A reference left with nothing usable becomes `blob`.
  Nothing a caller supplies can add a parameter to the header or a directory to
  the path.
- **`Content-Type: application/octet-stream` with `X-Content-Type-Options:
  nosniff`** on every response. Together they stop a browser inferring a type
  the response did not declare.
- **`Content-Security-Policy: default-src 'none'`** on API paths, which leaves
  nothing for a document served from one to load or execute.

A blob whose content is malicious is therefore returned intact to the one
account that uploaded it, as bytes, and no browser is asked to interpret it.

---

#### GET /user/blobs/{id}

Download a decrypted blob. Returns raw binary data.

**Authentication:** Bearer token

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Blob UUID |

**Response headers:**

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/octet-stream` |
| `Content-Disposition` | `attachment; filename="<id>"` -- see [How stored objects are made safe to download](#how-stored-objects-are-made-safe-to-download) |
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

**Authentication:** Bearer token, plus a password confirmation window. Call
`POST /auth/confirm` first; the window lasts 5 minutes and is bound to the access
token that opened it, so a refresh closes it.

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
| 403 | `requires_confirmation` | No open confirmation window, or it was opened by a different access token |
| 404 | `blob_not_found` | Blob not found or belongs to another user |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/blobs/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

#### PUT /user/blobs/named/{name}

Create or replace a **named blob**. Named blobs are addressed by a human-readable name (e.g. `session-data`, `preferences`) instead of a UUID. If a blob with the same name already exists for this user, it is replaced atomically (delete + insert). The name is stored as an HMAC hash in the database -- the plaintext name never touches persistent storage.

**Authentication:** Bearer token

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
| 400 | `invalid_name` | Name contains characters outside `[a-zA-Z0-9_-]` |
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

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Blob name |

**Response headers:**

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/octet-stream` |
| `Content-Disposition` | `attachment; filename="<name>"` -- see [How stored objects are made safe to download](#how-stored-objects-are-made-safe-to-download) |
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

**Authentication:** Bearer token, plus a password confirmation window. Call
`POST /auth/confirm` first; the window lasts 5 minutes and is bound to the access
token that opened it, so a refresh closes it.

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
| 403 | `requires_confirmation` | No open confirmation window, or it was opened by a different access token |
| 404 | `blob_not_found` | Named blob not found |
| 500 | `internal_error` | Server error |

**curl example:**

```bash
curl -X DELETE https://vault42.example.com/user/blobs/named/session-data \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

### Two-Factor Authentication

**Changing a second factor signs the user out everywhere, including the session
that made the change.** Five operations revoke every refresh-token family on the
account:

| Operation | Endpoint |
|---|---|
| TOTP enrolled | `POST /auth/2fa/totp/verify` |
| TOTP removed | `DELETE /auth/2fa/totp` |
| WebAuthn credential enrolled | `POST /auth/2fa/webauthn/register/finish` |
| WebAuthn credential removed | `DELETE /auth/2fa/webauthn/credentials/{id}` |
| Backup codes regenerated | `POST /auth/2fa/backup-codes` |

The reason is containment: if a factor is being changed by somebody who should
not be, the sessions they hold have to go with it, and a revocation that spared
the caller would spare the attacker in exactly the case that matters. Password
changes make the same trade.

The consequence for a client is that a `200` from any of these is immediately
followed by a dead refresh token. The access token keeps working until it
expires, so the failure surfaces later, at the next refresh, as a `401` that
looks unrelated to the enrolment that caused it. Treat these responses as a
sign-out: re-authenticate straight away rather than waiting to discover it.
Backup-code regeneration is the one people miss, because it reads like a
read-only operation and is not.

#### Errors shared by every 2FA verify endpoint

The four verify endpoints -- TOTP, WebAuthn, backup code and email OTP -- each
run two modes, and the second one has failures the first cannot produce. With an
ordinary Bearer token the endpoint confirms the factor and stops. With a
`2fa_challenge` token it goes on to complete the login through one shared code
path (`completeMFAIfChallenge`, `internal/handler/mfa_helper.go`), and that path
can refuse after the factor has already been proved.

The tables below mark these rows **challenge mode only**. They cannot occur when
verifying with an ordinary Bearer token:

| Status | Error | Meaning |
|--------|-------|---------|
| 401 | `challenge_consumed` | The challenge token's `jti` was already spent. Challenge tokens are single-use for five minutes; a retried request gets this rather than a second session |
| 401 | `invalid_token` | The fingerprint on the challenge does not match the presenting device, or the subject no longer resolves to a live account (deleted inside the challenge window) |
| 403 | `account_banned` | The account was banned after the password step and before this call |
| 403 | `account_disabled` | The account was disabled in the same window |
| 403 | `account_locked` | The account carries an operator lock, or the MFA-failure lockout tripped, in the same window |
| 429 | `too_many_sessions` | The concurrent-session cap is full. The factor was accepted; no session was issued |

Account state is deliberately re-read at completion rather than trusted from the
password step, because the challenge TTL is exactly the window in which an
operator reacting to a compromise bans, disables or locks the account. A `403`
here therefore means the second factor was correct and the platform refused the
session anyway. Do not retry it as if it were a bad code: it will not clear.

Note also what a `200` costs. The audit event for the verification is written
before the login is completed and regardless of how it ends, so a banned account
still records a successful second factor. That is intentional -- it is the trail
an investigator needs -- and it means an audit log showing `2fa_verify` is not
evidence a session was issued.

---

#### GET /auth/2fa/status

Retrieve the MFA status for the authenticated user, including which methods are configured.

**Authentication:** Bearer token

**Success response (200 OK):**

```json
{
  "totp_enabled": true,
  "webauthn_enabled": false,
  "backup_codes_remaining": 8,
  "mfa_methods": ["totp", "backup_code"],
  "available_methods": ["totp", "backup_code"],
  "mfa_required": false
}
```

`mfa_methods` and `available_methods` are the same list under two names. `mfa_methods` is canonical; `available_methods` is retained as a deprecated alias for clients written before 1.0.0 and will be removed at 2.0.0. New clients MUST read `mfa_methods`.

Both are always arrays. A user with no configured factor gets `[]`, never `null` -- the guarantee is enforced in `MFAStatus.MarshalJSON`, so it holds for every code path that returns a status, not only this one.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

Also sets the `__Host-refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_code` | Code is not exactly 6 digits |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_code` | TOTP code is incorrect |
| 401 | `invalid_token` | Device fingerprint mismatch; in challenge mode also a subject that no longer resolves |
| 401 | `challenge_consumed` | Challenge mode only -- see the shared table above |
| 403 | `account_banned` | Challenge mode only -- see the shared table above |
| 403 | `account_disabled` | Challenge mode only -- see the shared table above |
| 403 | `account_locked` | Challenge mode only. Account state refused the session after the code was accepted; distinct from the 429 of the same name below |
| 404 | `totp_not_setup` | TOTP has not been configured |
| 429 | `account_locked` | Too many MFA failures on this account. Shared with the other MFA factors and with password verification, so failures against any of them count toward the same lock. Checked before the code is read, so it does not consume an attempt |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 429 | `too_many_sessions` | Challenge mode only -- see the shared table above |
| 429 | `totp_code_already_used` | Same code used within the same 30-second time step (replay prevention) |
| 500 | `internal_error` | Server error |
| 503 | `rate_limiter_unavailable` | Cache backend down; this limiter fails closed |

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

**Request body:** None

**Success response (200 OK):**

```json
{"status": "totp_disabled"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

**Authentication:** Bearer token, plus a password confirmation window. Call
`POST /auth/confirm` first; the window lasts 5 minutes and is bound to the access
token that opened it, so a refresh closes it.

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
| 403 | `requires_confirmation` | No open confirmation window, or it was opened by a different access token |
| 401 | `invalid_token` | Device fingerprint mismatch |
| 401 | `unauthorized` | User not found |
| 409 | `credential_already_registered` | The credential ID is already enrolled on this or another account |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

Also sets the `__Host-refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `no_pending_verification` | No verification session found (expired or not started) |
| 401 | `unauthorized` | Not authenticated |
| 401 | `webauthn_verification_failed` | Authenticator assertion verification failed |
| 401 | `user_verification_required` | The credential was enrolled with user verification; the assertion carried none. Retry with the authenticator's PIN or biometric |
| 401 | `cloned_authenticator_detected` | The signature counter did not advance; every refresh-token family for the user is revoked |
| 401 | `invalid_token` | Device fingerprint mismatch; in challenge mode also a subject that no longer resolves |
| 401 | `unauthorized` | User not found |
| 401 | `challenge_consumed` | Challenge mode only -- see the shared table above |
| 403 | `account_banned` | Challenge mode only -- see the shared table above |
| 403 | `account_disabled` | Challenge mode only -- see the shared table above |
| 403 | `account_locked` | Challenge mode only -- see the shared table above |
| 429 | `too_many_sessions` | Challenge mode only -- see the shared table above |
| 501 | `webauthn_not_configured` | WebAuthn is not configured |
| 500 | `internal_error` | Server error |
| 500 | `webauthn_error` | The sign count or the stored authenticator flags could not be persisted. The assertion is refused rather than accepted, because a stale sign count is what the clone check reads |

This endpoint carries **no rate limit**. Unlike the TOTP, backup-code and
email-OTP verify endpoints it is not mounted behind a limiter at all, so it
returns neither `429 rate_limit_exceeded` nor `503 rate_limiter_unavailable`.
See the Rate Limiting section for why.

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
| 401 | `invalid_token` | Device fingerprint mismatch |
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
| 401 | `invalid_token` | Device fingerprint mismatch |
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

Generate a new set of 10 backup codes. Any existing backup codes are replaced. Requires recent password confirmation. Each code is 16 hex characters (64-bit entropy), stored as HMAC-SHA256 hashes.

**Authentication:** Bearer token + password confirmation

**Request body:** None

**Success response (200 OK):**

```json
{
  "codes": [
    "a1b2c3d4e5f60718",
    "7890abcdef123456",
    "3456789abcdef012",
    "f0123456789abcde",
    "bcdef0123456789a",
    "789abcdef0123456",
    "0f1e2d3c4b5a6978",
    "13579bdf02468ace",
    "fedcba9876543210",
    "0123456789abcdef"
  ],
  "warning": "Save these codes. They will not be shown again."
}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_token` | Device fingerprint mismatch |
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

#### POST /auth/2fa/backup-code/verify

Consume a single-use backup code. Like the TOTP and email-OTP verify endpoints, this has two modes:

1. **Standard verification:** with a normal Bearer token, confirms the code.
2. **Login MFA challenge:** with a `2fa_challenge` token from the login flow, completes authentication and issues full access and refresh tokens.

Codes are stored as HMAC-SHA256 hashes and compared in constant time. Consumption is atomic (compare-and-swap on `used`), so a code cannot be spent twice even under concurrent requests.

**Authentication:** Bearer token or 2FA challenge token
**Rate limit:** 5 requests per 5 minutes (per IP), fail-closed

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | One backup code from the set issued by `POST /auth/2fa/backup-codes` |

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

Sets the `__Host-refresh_token` cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `code_required` | Malformed JSON, or `code` absent or empty |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_backup_code` | Code is wrong or already used; records an MFA failure |
| 401 | `invalid_token` | Device fingerprint mismatch; in challenge mode also a subject that no longer resolves |
| 401 | `challenge_consumed` | Challenge mode only -- see the shared table above |
| 403 | `account_banned` | Challenge mode only -- see the shared table above |
| 403 | `account_disabled` | Challenge mode only -- see the shared table above |
| 403 | `account_locked` | Challenge mode only. Account state refused the session after the code was spent; distinct from the 429 of the same name below |
| 409 | `backup_code_already_used` | The compare-and-swap on `used` lost: another request spent this same code first. Only reachable when two requests race on one code -- a sequential retry of a spent code is `401 invalid_backup_code`, because a used code is no longer in the candidate set |
| 429 | `account_locked` | Too many MFA failures on this account; shared with the TOTP and password counters |
| 429 | `rate_limit_exceeded` | Verify rate limit exceeded |
| 429 | `too_many_sessions` | Challenge mode only -- see the shared table above |
| 500 | `internal_error` | Server error |
| 503 | `rate_limiter_unavailable` | Cache backend down; this limiter fails closed |

The three 429s mean different things and clear differently. `rate_limit_exceeded`
is per caller and expires on its own window. `account_locked` is the per-account
MFA lockout that backup codes share with TOTP and password verification, so
failures against any of the three count toward the same lock, and retrying a
different factor does not escape it. `too_many_sessions` is neither: the code was
accepted and the concurrent-session cap refused the session, so it clears by
revoking a session, not by waiting.

**curl example:**

```bash
curl -X POST https://vault42.example.com/auth/2fa/backup-code/verify \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -H "Accept-Language: en-US" \
  -d '{"code": "a1b2c3d4e5f6"}'
```

---

#### POST /auth/2fa/email-otp/verify

Verify an email one-time password code. Has two modes of operation:

1. **Standard verification:** When called with a standard Bearer token, confirms the email OTP code.
2. **Login MFA challenge:** When called with a `2fa_challenge` token (from the login flow), completes authentication and issues full access/refresh tokens.

An email OTP is automatically sent during login when the user's only available 2FA method is `email_otp`. Use `POST /auth/2fa/email-otp/resend` to request a new code.

**Authentication:** Bearer token or 2FA challenge token
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

Also sets the `__Host-refresh_token` HttpOnly cookie.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_code` | Code is not exactly 6 digits |
| 401 | `unauthorized` | Not authenticated |
| 401 | `invalid_code` | Email OTP code is incorrect or expired |
| 401 | `invalid_token` | Device fingerprint mismatch; in challenge mode also a subject that no longer resolves |
| 401 | `challenge_consumed` | Challenge mode only -- see the shared table above |
| 403 | `account_banned` | Challenge mode only -- see the shared table above |
| 403 | `account_disabled` | Challenge mode only -- see the shared table above |
| 403 | `account_locked` | Challenge mode only. Account state refused the session after the code was accepted; distinct from the 429 of the same name below |
| 429 | `account_locked` | Too many MFA failures on this account. Shared with the other MFA factors and with password verification, so failures against any of them count toward the same lock. Checked before the code is read, so it does not consume an attempt |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 429 | `too_many_sessions` | Challenge mode only -- see the shared table above |
| 500 | `internal_error` | Server error |
| 503 | `rate_limiter_unavailable` | Cache backend down; this limiter fails closed |

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
| 401 | `invalid_token` | Device fingerprint mismatch |
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
**Rate limit:** 10 requests per minute (per IP). Not fail-closed: a cache outage falls back to a per-pod counter.

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

Handle the OAuth2 callback from the identity provider. Validates the state parameter (HMAC-signed with expiry), exchanges the authorization code for tokens using PKCE, fetches user info, and either signs in an already-linked identity, links to an existing account, or creates a new account.

A first-time sign-in is auto-provisioned only when the provider proves the caller owns the address. A provider that publishes no per-address verification signal (Facebook) or an OIDC issuer that answers `email_verified:false` cannot prove ownership: the asserted address is attacker-supplied, so creating an account on it would squat a stranger's mailbox and the create-vs-refuse outcome would reveal whether the address is registered. For such providers a first-time callback (no existing linked identity) is refused with a neutral redirect to `{origin}/oauth/callback#error=verification_required`, identical whether or not the address is registered; no account is created and no mail is sent. An identity already linked by `(provider, provider_user_id)` still signs in normally.

If the user has MFA enabled, redirects to `{origin}/oauth/callback#requires_2fa=true&challenge_token=...` instead of issuing full tokens.

**DPoP:** this route is not wrapped in the DPoP middleware (`internal/server/server.go`). The identity provider redirects the browser with a GET, which cannot carry a `DPoP` proof, so the access or challenge token minted here never receives `cnf.jkt` even when `VAULT_DPOP_ENABLED` is on. `POST /auth/oauth2/exchange` returns that already-issued token. A later `POST /auth/2fa/*` verify *is* wrapped, so an MFA-completing federated login can still bind there. See `spec.md` section 0.6.2.

**Authentication:** None (callback from provider)
**Rate limit:** 10 requests per minute (per IP). Not fail-closed: a cache outage falls back to a per-pod counter rather than `503 rate_limiter_unavailable`. The callback used to share the login bucket (5 per 15 minutes, fail-closed). It does not any more. Reaching the handler already takes an HMAC-valid state, a matching `__Host-oauth_state` cookie and a single-use PKCE verifier, so this is not a guessing surface, and sharing `loginRL` let one office or VPN exit spend social login with five garbage login bodies.

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

Also sets the `__Host-refresh_token` HttpOnly cookie. The `code` is a one-time exchange code (60-second TTL) -- call `POST /auth/oauth2/exchange` to retrieve the access token.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `unknown_provider` | Provider not configured |
| 400 | `provider_denied` | The provider redirected back with an `error` query parameter (RFC 6749 §4.1.2.1) -- typically the user declining consent. The provider's own code and description are logged, not returned |
| 400 | `missing_state` | No state parameter in callback |
| 400 | `invalid_state` | State signature validation failed |
| 400 | `state_expired` | State parameter has expired (10-minute window) |
| 400 | `invalid_or_reused_state` | PKCE verifier not found or already consumed |
| 400 | `missing_code` | No authorization code in callback |
| 400 | `unable_to_identify_user` | Could not determine user from provider response |
| 403 | `account_unavailable` | The resolved account does not exist or is deleted |
| 403 | `account_banned` | The resolved account is banned |
| 403 | `account_disabled` | The resolved account is disabled |
| 403 | `account_locked` | The account carries an operator lock, or the shared MFA-failure lockout is active. Refused before the account is claimed and before any challenge token is issued |
| 409 | `email_already_registered` | A verified provider asserted an address held by an account whose own email is unverified; linking is refused to prevent takeover. Unverified providers are refused earlier via the `#error=verification_required` redirect. |
| 429 | `session_limit_reached` | The concurrent-session cap is full. Raised either by the pre-check or by the capped insert, which is the one that holds under concurrent callbacks |
| 502 | `provider_error` | Token exchange or user info request failed |
| 500 | `internal_error` | Server error |

The four `403`s are the same account-state gate `POST /auth/login` and
`POST /auth/refresh` apply, enforced here so federated login cannot become a way
round it: an attacker holding a linked social identity would otherwise complete a
callback and collect a fresh refresh-token family after an operator had already
locked the account. They are returned as a JSON error, not as a redirect, so a
browser sitting on the provider's redirect sees the error envelope rather than
landing back on `{origin}/oauth/callback`.

**curl example:**

```bash
# This endpoint is called by the OAuth2 provider's redirect, not directly by clients.
curl -v "https://vault42.example.com/auth/oauth2/callback/google?state=...&code=..."
```

---

#### POST /auth/oauth2/exchange

Exchange a one-time code from the OAuth2 callback redirect for the access token. The code is valid for 60 seconds and can only be used once (atomic get-and-delete).

**Authentication:** None
**Rate limit:** 10 requests per minute (per IP). Not fail-closed: a cache outage falls back to a per-pod counter.

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
| 500 | `internal_error` | The stored exchange payload could not be decoded. The code is already consumed at this point, so the callback must be repeated rather than the exchange retried |

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

**Two deviations from RFC 6749, both frozen until 2.0.0.** The endpoint does not read `grant_type` at all -- sending `grant_type=client_credentials` is harmless but not required -- and it reports `invalid_client_credentials` where RFC 6749 section 5.2 specifies `invalid_client`. Requiring the parameter and renaming the code are both breaking changes under the stability contract, so they wait for a major version. Write clients against what is documented here, not against the RFC.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_scope` | Requested scopes have no overlap with allowed scopes |
| 401 | `invalid_client_credentials` | Missing, malformed, or wrong client credentials, and also a client that has been deactivated. RFC 6749 calls this `invalid_client`; see above |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 503 | `server_busy` | Password hashing is saturated; retry |
| 500 | `internal_error` | Server error |

A deactivated client is answered with `invalid_client_credentials` and nothing
else, and the endpoint spends the same Argon2 verification on it that a live
client costs. That is deliberate: a distinct code, or a faster refusal, would
tell an attacker which client IDs exist and which of those have been revoked.
Do not write a client that branches on telling those cases apart, because the
server does not tell them apart.

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

### KMS

---

#### POST /kms/unwrap

KEK envelope-unwrap oracle. The caller presents a wrapped-key envelope and vault42 returns the unwrapped key. vault42 holds the Key-Encryption-Key (derived per `kid` from `KMS_ROOT_KEY_FILE` via HKDF-SHA256) and never releases it. Mounted **only** when `KMS_ROOT_KEY_FILE` is configured; otherwise the route does not exist (404).

**Authentication:** Bearer access token from `POST /client/token`, carrying the `kms:unwrap` scope. Sender-constraint follows the token rather than the route: `POST /client/token` **is** DPoP-wrapped (`internal/server/server.go:560`), so a client-credential token minted while presenting a valid proof carries `cnf.jkt`, and this route then refuses it without a matching proof under the `DPoP` scheme. A token minted without a proof stays an ordinary bearer token and this route demands none. Both cases need `VAULT_DPOP_ENABLED=true`; with the flag off, its default, no token carries `cnf.jkt` at all. For an unbound token, replay resistance rests on the short access-token TTL, TLS, and the fail-closed per-IP limit. See `spec.md` section 0.6.2.
**Rate limit:** per-IP, fail-closed (a cache/Redis outage rejects with 503 rather than degrading).

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kid` | string | Yes | Key identifier the envelope was wrapped under |
| `ciphertext` | string | Yes | Base64 (std) envelope: `nonce \|\| AES-256-GCM ciphertext`, with `kid` bound as AAD |

**Success response (200 OK):**

```json
{
  "plaintext": "TFVLU2VkLWtleS1tYXRlcmlhbC4uLg=="
}
```

`plaintext` is the base64 (std) unwrapped key.

**Error responses:**

Every post-authorization failure (malformed body, bad base64, empty `kid`, tampered ciphertext, wrong KEK) collapses to a single opaque response so the endpoint cannot be used as a decryption oracle:

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `unwrap_failed` | Any envelope that does not unwrap. The status, body, and audit outcome are identical across all failure modes. |
| 401 | `missing_authorization` | No `Authorization` header |
| 401 | `invalid_authorization` | Header is not `Bearer <token>` |
| 401 | `invalid_token` | Signature, issuer, audience or expiry check failed |
| 401 | `invalid_token_type` | The token's `token_type` claim is not `Bearer` |
| 401 | `invalid_dpop_proof` | A `DPoP` header was presented and failed validation (`VAULT_DPOP_ENABLED=true` only) |
| 401 | `dpop_proof_reused` | The proof's `jti` was seen before (`VAULT_DPOP_ENABLED=true` only) |
| 401 | `unauthorized` | Defensive: claims absent behind the auth middleware. Not reachable through the mounted chain |
| 403 | `insufficient_scope` | Token lacks the `kms:unwrap` scope |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 503 | `rate_limiter_unavailable` | Rate-limiter backing store is down (fail-closed) |

Every attempt is written synchronously to the audit log (`kid` and outcome only; key material is never logged). Use the `vault kms wrap` CLI to produce envelopes this endpoint accepts.

The `kid` on this endpoint is deliberately unconstrained: it is HKDF info and GCM
additional data, never a lookup key, and unwrap has to remain the exact inverse of
every wrap that ever ran, including envelopes sealed under a kid this service would
not choose today. `vault kms wrap` is stricter than the endpoint and refuses any
`--kid` outside `^[A-Za-z0-9][A-Za-z0-9._@-]*$` (128 bytes), because a kid carrying
a space, a control byte or a homoglyph produces an artifact that only opens under a
string an operator cannot read back off their terminal. Producing is where that is
worth catching; opening is not.

`vault kms wrap` also refuses an empty or whitespace-only plaintext. Sealing zero
bytes yields a well-formed envelope that unwraps to nothing, so a deploy step whose
input file was empty produced a valid looking artifact and exit 0, and the failure
surfaced later as an empty secret in a running service. `POST /kms/unwrap` still
opens such an envelope, since older tooling could produce one and an operator
holding it needs to confirm what it carries.

**curl example:**

```bash
curl -X POST https://vault42.example.com/kms/unwrap \
  -H "Authorization: Bearer $KMS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kid":"data-root-v1","ciphertext":"'"$ENVELOPE_B64"'"}'
```

---

### Mint

---

#### POST /mint

Subject-assertion signing oracle. The caller names a subject, and vault42 signs a token asserting it with the same key that signs every real one. **vault42 does not authenticate the subject and does not look it up.** The endpoint exists because eleven legacy services hold foreign-key copies of the legacy platform's own user ids, so the token subject has to stay that id rather than a vault42-native one; the alternative was rewriting every one of those tables.

Mounted **only** when `VAULT_MINT_ENABLED=true`; otherwise the route does not exist and `net/http.ServeMux` answers `404` in `text/plain`, not the JSON error envelope. `VAULT_MINT_AUDIENCE` is required alongside it and must differ from `VAULT_ORIGIN`, or the process refuses to start (`internal/config/config.go:771-775`). That check runs **ahead of the dev-profile short-circuit**, so it applies in every profile including dev: a dev deployment that teaches the wrong configuration gets copied.

**Authentication:** Bearer access token from `POST /client/token`, carrying the `mint:token` scope. The handler additionally requires a non-empty `client_id` claim, which no user token carries.
**Middleware chain (outermost first):** `authMw` -> rate limit -> `RequireScope("mint:token")` -> DPoP wrapper -> handler (`internal/server/server.go:832`). The limiter sits inside `authMw` because `ClientRateLimitKey` reads the client id from claims that do not exist until auth has run. No fingerprint verification: this is a machine endpoint.
**Rate limit:** 60 per minute per authenticated `client_id`, fail-closed (a cache/Redis outage rejects with `503` rather than degrading to a per-pod counter). The limiter is mounted **inside** the auth middleware, so the key function reads the client id from the validated claims and buckets by `client_id`; its source-IP fallback is unreachable here, because a request carrying no claims is rejected by the auth middleware before it reaches the limiter. Plan capacity as 60/min per client, not per source address.
**DPoP:** the wrapper is a no-op unless `VAULT_DPOP_ENABLED=true`. With the flag on, whether a proof is required here is decided by the token, not by this route: `POST /client/token` **is** a DPoP issuance path (`internal/server/server.go:560`), so a client-credential token minted with a proof carries `cnf.jkt` and is refused here without a matching one. A token minted without a proof carries no `cnf.jkt`, and a request presenting it with no `DPoP` header passes through. See `spec.md` section 0.6.2.
**Max body:** 8 KiB, applied twice -- the global cap (`/mint` carries no exemption) and an explicit reader in the handler.

**Request body:**

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `subject` | string | Yes | 1--128 bytes, `^[A-Za-z0-9][A-Za-z0-9._@-]*$` | The identifier being asserted. Held to a charset that cannot smuggle control characters, whitespace or delimiters, because it lands in a signed claim and in an audit row |
| `roles` | string[] | No | Every member must appear in `VAULT_MINT_ROLES` | Omit or send `[]` for no roles. The allow-list is empty by default, so a freshly enabled mint issues bare subject assertions |
| `scopes` | string[] | No | Every member must appear in `VAULT_MINT_SCOPES` | Same deny-by-default rule as `roles` |
| `ttl_seconds` | int | No | `0` or absent means `VAULT_MINT_TOKEN_TTL`; otherwise `0 < ttl <= VAULT_MINT_MAX_TTL`, itself capped at 900 in code | A value above the ceiling is **refused, not clamped**. Silently issuing something other than what was asked for hides a misconfigured caller until the day its tokens expire mid-flight |
| `email` | string | No | Requires `VAULT_MINT_ALLOW_EMAIL`; must pass the same validator as a registered address, at most 254 bytes | Lower-cased and trimmed before signing. Refused with `403 email_not_permitted` when the setting is off, rather than stripped. vault42 does not verify it and cannot: `/mint` asserts subjects it has never heard of, and the email is a claim about the same unknown subject |

Unknown keys are rejected (`DisallowUnknownFields`), so a typo in a field name fails the whole request with `400 invalid_request`.

**Success response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 300,
  "subject": "legacy-user-8814",
  "audience": "https://legacy.example.com",
  "issuer": "https://vault42.example.com",
  "roles": ["rider"],
  "scopes": ["orders:read"],
  "email": "legacy-user-8814@example.com",
  "kid": "4f1c9e60-2a77-4e0f-9a3e-9c2b7f0d51aa",
  "jti": "0f2b8c1d-6e4a-4c92-b8a1-2f7d3e5a90c4"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | The signed assertion (RS256 JWT) |
| `token_type` | string | Always `Bearer`. This is the RFC 6749 presentation scheme, **not** the JWT's own `token_type` claim, which is `mint` |
| `expires_in` | int | Lifetime in seconds, granted rather than requested |
| `subject` | string | Echo of the asserted subject |
| `audience` | string | `VAULT_MINT_AUDIENCE`, the `aud` claim on the token |
| `issuer` | string | `VAULT_ORIGIN`, the `iss` claim on the token |
| `roles` | string[] | Granted roles. Omitted when none were requested |
| `scopes` | string[] | Granted scopes. Omitted when none were requested |
| `email` | string | Echo of the asserted address as it was signed, lower-cased and trimmed. Omitted when the request carried none. Present so a caller can see what it actually asserted rather than what it meant to send |
| `kid` | string | Key id the assertion was signed under, resolvable against `GET /.well-known/jwks.json` |
| `jti` | string | The token's unique id, also recorded in the audit event so a downstream incident traces back to the exact assertion |

**Claims on the minted token:**

| Claim | Value |
|-------|-------|
| `iss` | `VAULT_ORIGIN` |
| `aud` | `VAULT_MINT_AUDIENCE` (single-element array) |
| `sub` | The caller-asserted subject, verbatim |
| `iat`, `nbf` | Issue time. The token is valid immediately |
| `exp` | Issue time plus the granted TTL |
| `jti` | Per-token UUID |
| `roles`, `scopes` | Granted values, omitted when empty |
| `token_type` | `mint` |
| `minted_by` | The `client_id` of the client that requested the mint. This is the attribution a relying party can act on: the `token_minted` audit event names the same client, but that row lives in vault42's database and an RP cannot read it |
| `client_id` | **Absent, deliberately.** A minted token must not look like an authenticated service caller. The service document store treats the presence of this claim as proof of one and uses it as the ownership axis, so a minted token carrying it would be admitted as the minting client. That is why the attribution claim is spelled `minted_by`. See the security notes below |
| `email` | The address the caller asserted, present only when `VAULT_MINT_ALLOW_EMAIL` is on and the request carried one. **Not verified.** vault42 never looked this subject up, so the claim is the caller's statement rather than vault42's. A relying party must not treat it as proof of address ownership, and no vault42-issued login token carries this claim at all |
| `fingerprint`, `cnf` | Absent. A minted token is not device-bound and not sender-constrained |

There is no refresh token and no stored session behind a minted token. It cannot be exchanged, rotated, extended or revoked; vault42 keeps no record of it beyond the audit event.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_request` | Body is not JSON, carries an unknown key, or exceeds 8 KiB |
| 400 | `invalid_subject` | `subject` is empty, longer than 128 bytes, or outside the charset |
| 400 | `invalid_ttl` | `ttl_seconds` is negative, or above `VAULT_MINT_MAX_TTL` |
| 401 | `missing_authorization` | No `Authorization` header |
| 401 | `invalid_authorization` | Header is not `Bearer <token>` |
| 401 | `invalid_token` | Signature, issuer, audience or expiry check failed |
| 401 | `invalid_token_type` | The token's `token_type` claim is not `Bearer`. This is what a minted token presented back to `/mint` hits |
| 401 | `invalid_dpop_proof` | A `DPoP` header was presented and failed validation (`VAULT_DPOP_ENABLED=true` only) |
| 401 | `dpop_proof_reused` | The proof's `jti` was seen before (`VAULT_DPOP_ENABLED=true` only) |
| 401 | `unauthorized` | Defensive: claims absent behind the auth middleware. Not reachable through the mounted chain |
| 403 | `insufficient_scope` | Token lacks the `mint:token` scope |
| 403 | `client_credentials_required` | Token has the scope but no `client_id` claim, so it is not a service client |
| 403 | `role_not_permitted` | A requested role is outside `VAULT_MINT_ROLES`, or is `admin` or `super_admin` in any casing |
| 403 | `email_not_permitted` | The request carried `email` and `VAULT_MINT_ALLOW_EMAIL` is off |
| 400 | `invalid_email` | The request carried an `email` the address validator rejected |
| 403 | `scope_not_permitted` | A requested scope is outside `VAULT_MINT_SCOPES`, or is one of the vault42 capability scopes |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Signing or UUID generation failed |
| 503 | `server_busy` | No signing key is currently available |
| 503 | `rate_limiter_unavailable` | Rate-limiter backing store is down (fail-closed) |

Roles and scopes are checked as whole sets: one bad member rejects the request rather than issuing a token with the rest. A signing oracle that quietly issues something other than what was requested hides the misconfiguration that produced the request.

**Audit.** Every path, accepted and refused, writes one `token_minted` event. `user_id` holds the asserted subject and `client_id` the service that asserted it, so the log answers "who was spoken for, and by whom". Accepted mints record the `jti`, `kid`, `audience`, roles, scopes and lifetime at risk score 30; refusals record only the reason at risk score 45, because a client probing for roles it cannot mint is the early signal that its credential has been taken. The token itself is never logged. `token_minted` is a distinct event type from `login_success`, `token_refresh` and `client_auth` on purpose: the signature on a minted token is indistinguishable from any other, so the log is the only place the difference is recorded.

`token_minted` is **not** in the critical-event set, so under a deployment that batches audit writes (`VAULT_AUDIT_FLUSH_INTERVAL > 0`, which is the embedded profile) a full buffer drops the event rather than writing it synchronously. On the default configuration the interval is `0` and every event is written inline. An operator who enables minting and batching together is choosing to lose mint attribution under load.

**curl example (happy path):**

```bash
MINT_TOKEN=$(curl -sS -X POST https://vault42.example.com/client/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" -d "scope=mint:token" | jq -r .access_token)

curl -X POST https://vault42.example.com/mint \
  -H "Authorization: Bearer $MINT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"legacy-user-8814","roles":["rider"],"ttl_seconds":300}'
```

**curl example (instructive failure).** Asking for a role the operator did not allow-list is refused outright, not silently stripped:

```bash
curl -i -X POST https://vault42.example.com/mint \
  -H "Authorization: Bearer $MINT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"legacy-user-8814","roles":["admin"]}'
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": "role_not_permitted"}
```

`admin` and `super_admin` are refused whatever `VAULT_MINT_ROLES` contains, and listing either one makes the process fail to start rather than fail at request time. The comparison folds ASCII case and ignores surrounding whitespace, so `Admin`, `ADMIN` and a trailing-space `super_admin` are refused on the same terms -- a relying party that gates on its own spelling of the name, as BeOn3 does with `Admin`, is protected by the same rule that protects vault42.

**What a caller must understand before integrating.**

- **This signs an assertion for a subject the caller merely claims.** Every other token vault42 issues follows an authentication vault42 performed: a password, a second factor, a social callback, a client secret. A minted token follows nothing. A verifier cannot tell the difference from the signature, so whoever holds the mint credential can speak as any subject to every service that trusts vault42's JWKS. Treat the credential as equivalent to the signing key's blast radius, not as an API key.
- **The audience must differ from the vault42 issuer, and startup enforces it.** A minted token carrying vault42's own audience would satisfy vault42's own audience validation, leaving `token_type` as the single control between a subject assertion and a session. `config.Validate()` refuses that configuration before the dev-profile short-circuit, and `service.NewMintService` refuses it again.
- **Minted tokens are structurally rejected by vault42 itself.** The `token_type` claim is `mint`, which is not in the allow-list vault42's own auth middleware accepts (`Bearer`, plus `2fa_challenge` on the 2FA verify routes), and the audience is not vault42's. Either check alone stops a minted token at vault42's door; both are enforced. Without this, a mint credential would be full account takeover of every vault42 user: mint for any subject, then read the identity profile, download the blobs, delete the account.
- **Admin-tier roles and vault42 capability scopes cannot be minted.** `admin` and `super_admin` are refused unconditionally, in any casing. So are `mint:token`, `kms:unwrap`, `svcdoc:read`, `svcdoc:write`, `admin`, `admin:read` and `admin:write` -- a minted token carrying one of those would let the holder pivot from "assert a subject downstream" into "operate vault42's privileged endpoints as that subject".
- **`client_id` is deliberately absent from the claims.** Setting it would make a minted token indistinguishable from a client-credentials token to any code that treats the claim's presence as proof of a service caller, including the service document store, which asserts exactly that. Attribution for the minting client lives in the audit event, where it cannot be replayed. A downstream verifier must therefore not use `client_id` to decide anything about a minted token, and must not assume its absence means "user token".
- **Lifetimes are the only revocation.** A minted token cannot be revoked before it expires. The hard ceiling is 15 minutes regardless of configuration, enforced in the service constructor rather than left to the operator, and the default is 5.
- **Downstream verifiers should pin all three.** Check `iss` against `VAULT_ORIGIN`, `aud` against your own resource identifier, and `token_type == "mint"` if you accept both minted and self-authenticated tokens. Accepting a token on signature and `iss` alone re-opens the confusion the separate audience and type exist to prevent.

---

### Service Documents

A namespaced JSON document store with an ownership axis: a registered service client writes documents scoped to the triple `(itself, a subject, a key)`, and by default nothing else can read them. It exists so a service can keep small structured records about a user without owning a schema migration for every new per-user boolean.

Mounted **only** when `VAULT_SVCDOC_ENABLED=true`; otherwise the four routes do not exist and `ServeMux` answers `404` in `text/plain`. Off by default because this is new surface reachable by every existing client-credentials holder, so enabling it is an explicit operator decision rather than a consequence of upgrading. The shared visibility tier is a second, separate switch (`VAULT_SVCDOC_SHARED_ENABLED`).

**Authentication:** Bearer access token from `POST /client/token`, carrying `svcdoc:read` (reads) or `svcdoc:write` (writes). Every handler additionally requires a non-empty `client_id` claim.
**Middleware chain (outermost first):** `authMw` -> rate limit -> `RequireScope("svcdoc:read" | "svcdoc:write")` -> DPoP wrapper -> handler (`internal/server/server.go:760-769`). No fingerprint verification: this is a machine endpoint.
**DPoP:** the wrapper is a no-op unless `VAULT_DPOP_ENABLED=true`. With the flag on, the token decides: `POST /client/token` **is** a DPoP issuance path (`internal/server/server.go:560`), so a client-credential token minted with a proof carries `cnf.jkt` and these routes refuse it without a matching one. A token minted without a proof carries no `cnf.jkt` and passes through with no `DPoP` header. See `spec.md` section 0.6.2.
**Rate limit:** 60 per minute on `PUT` and `DELETE`, 300 per minute on both `GET`s, keyed by the authenticated `client_id`. Not fail-closed: these routes release only what the caller itself wrote, and a cache blip must not take profile reads down across every consuming service. As with `POST /mint`, the limiter runs inside the auth middleware, so the bucket is the client id read from the validated claims; the per-client key function's source-IP fallback is unreachable, because the auth middleware rejects a claimless request first.
**Max body:** the `/service/documents` prefix is exempt from the global 8 KiB cap, so a 64 KiB document is not truncated mid-transfer with no useful error. `PUT` re-applies its own limit of `VAULT_SVCDOC_MAX_SIZE` + 1 KiB.

**Storage model.**

- Documents are AES-256-GCM encrypted at rest, never plaintext JSONB. The AAD is `svcdoc:<client_id>:<subject_hash>:<doc_key>`, so a row copied between clients, subjects or keys fails to decrypt rather than silently changing owner.
- The subject is stored as an HMAC pseudonym, never in the clear, so the table does not enumerate which users a service holds records about.
- One row per `(client_id, subject_hash, doc_key)`. A `PUT` to an existing triple is an `UPDATE`, never a second row.
- Ownership is a SQL predicate on every request-path read, not a comparison performed after fetching a row.
- Erasure of a vault42 account removes every document held about that subject across every owning service. `GET /user/data-export` returns them **decrypted, including private ones**: a service's privacy from other services is not privacy from the data subject. Documents under `_global` are excluded from the export, since they belong to no subject.

**Path parameters.**

| Parameter | Constraints | Description |
|-----------|-------------|-------------|
| `{subject}` | 1--128 bytes, `^[A-Za-z0-9][A-Za-z0-9._@-]*$`, or the literal `_global` | Who the document is about. Percent-encoded separators decode into this segment before validation, so `%2F` produces a `/` that the charset then rejects |
| `{key}` | 1--128 bytes, `^[a-z0-9]+([._-][a-z0-9]+)*$` | Lowercase segments joined by `.`, `_` or `-`. Mirrors the `CHECK` constraint in `migrations/014_service_documents.sql`, so a bad key is a `400` rather than a constraint violation surfacing as a `500`. It is the identity store's dynamic-namespace charset widened with `_` and `-`, so every identity key is a legal document key but not the reverse |

**`_global` is the sentinel subject** for documents that belong to a service rather than to any user: feature flags, per-service settings. It is a sentinel rather than a `NULL` subject because PostgreSQL treats `NULL`s as distinct in a unique index, so a nullable column would silently permit duplicate `(client_id, NULL, doc_key)` rows. It cannot collide with a real subject, because a real subject must start with an alphanumeric and this one starts with an underscore. Global documents are written to the audit log with an empty `user_id` rather than the sentinel, and are excluded from every subject's data export.

**Visibility** is a string enum, not a boolean, so a later tier (an explicit grantee allow-list) is an added value rather than a changed field type.

| Value | Meaning |
|-------|---------|
| `private` | Readable only by the writing client. The default on every write, including when the parameter is absent |
| `shared` | Readable by any client holding `svcdoc:read`, for the same subject and key. Rejected with `403 shared_visibility_disabled` unless `VAULT_SVCDOC_SHARED_ENABLED=true` |

**Quotas.**

| Limit | Default | Config | Scope |
|-------|---------|--------|-------|
| Bytes per document | 65536 | `VAULT_SVCDOC_MAX_SIZE` | Measured on the canonical encoding, checked before and after canonicalisation |
| Documents per subject | 32 | `VAULT_SVCDOC_MAX_PER_SUBJECT` | Per `(owning client, subject)`. Only charged when creating; a replacement does not consume a second slot |
| Stored bytes per subject | 1048576 | `VAULT_SVCDOC_QUOTA_BYTES` | Summed across **every** owning client, so one user's footprint is bounded no matter how many services write about them. Counts ciphertext, so it is slightly larger than the document body |

Quota is evaluated against the state the write would produce, so a replacement is not charged twice. Both checks run before the row is written; there is no compensating delete.

---

#### PUT /service/documents/{subject}/{key}

Create or replace a document. This is a full replace: there is no merge, so a caller changing one field reads, edits and writes the whole document.

**Authentication:** Bearer token with `svcdoc:write` and a `client_id` claim
**Rate limit:** 60 per minute

**Query parameters:**

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `visibility` | `private`, `shared` | `private` | An absent or empty value is `private`. Any other value is a `400` |

**Request body:** the document itself, `Content-Type: application/json`. It is not decoded through the strict decoder every other endpoint uses, because there is no fixed field set to reject unknown members against. It must instead satisfy:

- top level is a JSON **object**. An array or a scalar is rejected: it leaves no room for a future merge-patch endpoint and makes the stored shape unpredictable;
- valid UTF-8, checked on the raw bytes. The JSON decoder replaces invalid UTF-8 with U+FFFD as it reads, so by the time a token is in hand the evidence is gone and the document would round-trip differently than it was submitted;
- nesting **at most 32 levels**. `encoding/json` has no depth limit, and a 64 KiB body of `[` characters is roughly 32 thousand levels; unmarshalling it recurses that deep and takes the process down. Depth is therefore bounded on the token stream, before the decoder ever builds a value;
- **at most 1024 keys** in total across the whole document. This bounds decode cost independently of byte size: a document of tiny keys is cheap in bytes and expensive in allocations;
- **no duplicate keys** within any one object. `encoding/json` decodes a repeated key last-wins, so such a document round-trips differently than it was submitted;
- nothing after the closing brace. Trailing content is a second document, not whitespace.

The stored form is canonical: keys sorted, HTML escaping off (it would rewrite `<`, `>` and `&` inside string values into `\u00xx` forms, so a stored document would not match what the service submitted), and numbers carried as literals so a large integer or a high-precision decimal is stored exactly as written rather than round-tripped through a `float64`. `size_bytes` is measured on that canonical encoding, which may differ from the submitted byte count.

**Success response (201 Created on create, 200 OK on replace):**

```json
{
  "key": "loyalty",
  "owner_id": "c1f0a9d2-3b44-4a17-9f2e-7d0b6c8e5411",
  "visibility": "private",
  "size_bytes": 84,
  "stored_bytes": 112,
  "created_at": "2026-08-13T09:14:02Z",
  "updated_at": "2026-08-13T09:14:02Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Echo of `{key}` |
| `owner_id` | string | The writing client's id, always the caller |
| `visibility` | string | `private` or `shared` |
| `size_bytes` | int | Canonical plaintext size |
| `stored_bytes` | int | Ciphertext size, which is what the per-subject byte quota charges |
| `created_at` | string | First write of this triple, preserved across replacements |
| `updated_at` | string | This write |

The write response carries no `owner` name; only listings and exports resolve one.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_visibility` | `?visibility=` is neither `private`, `shared` nor empty |
| 400 | `invalid_key` | `{key}` is empty, over 128 bytes, or outside the key charset |
| 400 | `invalid_subject` | `{subject}` is over 128 bytes or outside the subject charset |
| 400 | `invalid_document` | Body is empty or whitespace, not valid UTF-8, not a JSON object, malformed, deeper than 32 levels, over 1024 keys, carries a duplicate key, or has trailing content |
| 400 | `missing_subject`, `missing_key` | Defensive: a path segment resolved empty. Not reachable through the mux, which redirects `//` and 404s an empty trailing segment |
| 401 | `missing_authorization`, `invalid_authorization`, `invalid_token`, `invalid_token_type` | Standard bearer-token failures |
| 403 | `insufficient_scope` | Token lacks `svcdoc:write` |
| 403 | `client_credentials_required` | Token has the scope but no `client_id` claim |
| 403 | `shared_visibility_disabled` | `?visibility=shared` while `VAULT_SVCDOC_SHARED_ENABLED` is off |
| 409 | `quota_exceeded` | Would breach the document count for this `(client, subject)` or the byte budget for this subject |
| 413 | `document_too_large` | Body exceeds `VAULT_SVCDOC_MAX_SIZE`, either at the reader or after canonicalisation |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Encryption, UUID generation or storage failed |

**curl example (happy path):**

```bash
SVC_TOKEN=$(curl -sS -X POST https://vault42.example.com/client/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode "scope=svcdoc:read svcdoc:write" | jq -r .access_token)
SUBJECT=user-8c1d4f   # the vault42 user id, or the literal _global

curl -X PUT "https://vault42.example.com/service/documents/$SUBJECT/loyalty" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tier":"gold","points":4210,"since":"2024-03-01"}'
```

**curl example (instructive failure).** A top-level array is not a document:

```bash
curl -i -X PUT "https://vault42.example.com/service/documents/$SUBJECT/loyalty" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"tier":"gold"}]'
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error": "invalid_document"}
```

`invalid_document` is deliberately one code for every structural rejection. A caller debugging a rejected body should check the six rules above in order rather than expect the server to say which one it broke.

Audited as `svcdoc_put`, recording the key, canonical size, visibility and whether the row was created. The body is never logged.

---

#### GET /service/documents/{subject}/{key}

Read a document body.

**Authentication:** Bearer token with `svcdoc:read` and a `client_id` claim
**Rate limit:** 300 per minute

**Query parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `owner` | No | The **registered name** of the publishing client, as it appears in a listing's `owner` field. Disambiguates when more than one service publishes a shared document at the same key |

**Resolution order.** Without `owner`: the caller's own document first, then a shared document published by another client. With `owner`: that client's row directly, which is returned only if it is the caller's own or is `shared`. Two clients sharing the same key and no `owner` given is `409 ambiguous_document` rather than an arbitrary pick.

**Success response (200 OK):** the stored document body, verbatim, as `application/json`. It is not wrapped in an envelope.

| Header | Description |
|--------|-------------|
| `X-Document-Owner` | The owning client's **id** (UUID), not its name |
| `X-Document-Visibility` | `private` or `shared` |

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_key`, `invalid_subject` | Path segment outside its charset or over 128 bytes |
| 401 | `missing_authorization`, `invalid_authorization`, `invalid_token`, `invalid_token_type` | Standard bearer-token failures |
| 403 | `insufficient_scope` | Token lacks `svcdoc:read` |
| 403 | `client_credentials_required` | Token has the scope but no `client_id` claim |
| 404 | `document_not_found` | No readable document at that triple. Also covers a private document owned by another client, and an `owner` that names no registered client |
| 409 | `ambiguous_document` | Two or more other clients publish a shared document at this key and no `owner` was named |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Decryption or storage failed |

**A document owned by another client and not shared reports as absent, never as forbidden.** Distinguishing the two would make the store an oracle for "does service X hold a record at key K about user U", which is exactly the question the pseudonymised subject exists to make unanswerable. An `owner` naming a client that does not exist collapses to the same `404` for the same reason.

**curl example:**

```bash
curl "https://vault42.example.com/service/documents/$SUBJECT/loyalty?owner=billing" \
  -H "Authorization: Bearer $SVC_TOKEN"
```

Audited as `svcdoc_get`, recording the key, the resolved owner id, and whether the document was the caller's own.

---

#### DELETE /service/documents/{subject}/{key}

Delete the caller's own document. A client can never delete another client's row, shared or not.

**Authentication:** Bearer token with `svcdoc:write` and a `client_id` claim
**Rate limit:** 60 per minute

**Success response (200 OK):**

```json
{"status": "deleted"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_key`, `invalid_subject` | Path segment outside its charset or over 128 bytes |
| 401 | `missing_authorization`, `invalid_authorization`, `invalid_token`, `invalid_token_type` | Standard bearer-token failures |
| 403 | `insufficient_scope` | Token lacks `svcdoc:write` |
| 403 | `client_credentials_required` | Token has the scope but no `client_id` claim |
| 404 | `document_not_found` | The caller holds no document at that triple. Another client's shared document at the same key is not deletable and reports the same way |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Storage failed |

The delete is not idempotent in its status code: a second `DELETE` of the same key returns `404 document_not_found`.

**curl example:**

```bash
curl -X DELETE "https://vault42.example.com/service/documents/$SUBJECT/loyalty" \
  -H "Authorization: Bearer $SVC_TOKEN"
```

Audited as `svcdoc_delete`.

---

#### GET /service/documents/{subject}

List the metadata of every document the caller may read for one subject, plus that subject's quota position. Bodies are never returned by a listing.

**Authentication:** Bearer token with `svcdoc:read` and a `client_id` claim
**Rate limit:** 300 per minute

**Success response (200 OK):**

```json
{
  "subject": "user-8c1d4f",
  "documents": [
    {
      "key": "loyalty",
      "owner": "billing",
      "owner_id": "c1f0a9d2-3b44-4a17-9f2e-7d0b6c8e5411",
      "visibility": "private",
      "size_bytes": 84,
      "stored_bytes": 112,
      "mine": true,
      "created_at": "2026-08-13T09:14:02Z",
      "updated_at": "2026-08-13T09:14:02Z"
    }
  ],
  "count": 1,
  "quota": {
    "used_bytes": 112,
    "max_bytes": 1048576,
    "used_count": 1,
    "max_count": 32
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Echo of `{subject}` |
| `documents` | array | The caller's own documents, then other clients' shared documents for the same subject. Always an array; `[]` when empty |
| `documents[].key` | string | Document key |
| `documents[].owner` | string | The owning client's registered name. **Omitted** when the client lookup fails, since the id is already present and the name is a convenience |
| `documents[].owner_id` | string | The owning client's id |
| `documents[].visibility` | string | `private` or `shared` |
| `documents[].mine` | bool | Whether the caller owns this document |
| `documents[].size_bytes` | int | Canonical plaintext size |
| `documents[].stored_bytes` | int | Ciphertext size |
| `documents[].created_at`, `documents[].updated_at` | string | RFC 3339 UTC, read back from the row |
| `count` | int | Length of `documents` |
| `quota.used_bytes` | int | Stored bytes held for this subject across **every** owning client |
| `quota.max_bytes` | int | `VAULT_SVCDOC_QUOTA_BYTES` |
| `quota.used_count` | int | Documents this caller holds for this subject, **not** the cross-client total |
| `quota.max_count` | int | `VAULT_SVCDOC_MAX_PER_SUBJECT` |

The two `used_` fields have different scopes on purpose, because the two limits do: the count is per `(client, subject)` and the byte budget is per subject. A caller that is well under `max_count` can still be refused with `quota_exceeded` because another service filled the byte budget.

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_subject` | `{subject}` is over 128 bytes or outside the subject charset |
| 400 | `missing_subject` | Defensive: the segment resolved empty. Not reachable through the mux |
| 401 | `missing_authorization`, `invalid_authorization`, `invalid_token`, `invalid_token_type` | Standard bearer-token failures |
| 403 | `insufficient_scope` | Token lacks `svcdoc:read` |
| 403 | `client_credentials_required` | Token has the scope but no `client_id` claim |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Storage failed |

A subject with no documents is `200` with an empty array, not `404`.

**curl example:**

```bash
curl "https://vault42.example.com/service/documents/$SUBJECT" \
  -H "Authorization: Bearer $SVC_TOKEN"
```

Listing is the only route that writes no audit event; it discloses no body and the read of a body is audited where it happens.

**What a caller must understand before integrating.**

- **Documents are private to the writing `client_id` by default.** Privacy is enforced as a SQL predicate on the request path, not as a check after fetching, and the failure mode is `404`, not `403`. Do not design around distinguishing "not there" from "not yours"; you cannot.
- **The handler asserts `claims.ClientID != ""` and does not rely on the scope check alone.** `RequireScope` looks only at the `scopes` array. Today a user token can never carry a `svcdoc` scope, because every user-token issuance site hardcodes `["read","write"]`, so the scope check happens to be sufficient. That is an accident of the current code and not an invariant: a change to user-scope issuance would otherwise silently open a service-owned store to end-user tokens. The ownership axis of this store is the client id, so the handler asserts it directly. It is also why a minted token carries no `client_id`: such a token is already refused at the auth middleware for its `token_type` and its audience, and this check would refuse it again.
- **`_global` is a real namespace, not a wildcard.** It is a subject like any other, with its own quota row, its own document count, and no relationship to any user. Writing user data under it removes that data from the subject's erasure cascade and from their data export.
- **Sharing is a two-key decision.** A `shared` write needs both the operator flag and the explicit `?visibility=shared` parameter. Neither implies the other, and switching the flag off later does not retroactively unshare existing rows: it only refuses new shared writes.
- **The 32-level depth bound and the 1024-key bound are validation, not tuning.** They are not operator-configurable and are not negotiable per client. A configuration document that needs 33 levels is a document that should be several documents.
- **A subject's documents are personal data.** They ride the erasure cascade and appear decrypted in that subject's GDPR export, private ones included. Write nothing under a real subject that you would not hand to that person.

---

### Admin Endpoints

> **Note:** Key management endpoints (`POST /admin/keys/rotate`, `GET /admin/keys`, `DELETE /admin/keys/{kid}`) have moved to the **admin gateway** (`cmd/admin-gateway/`), which provides mTLS + RBAC + session authentication with 6-layer local-only enforcement. See the admin gateway documentation for details.

The endpoints below are served by the admin gateway and require an authenticated admin session with the relevant RBAC permission.

#### POST /admin/users/import

Batch-import accounts (e.g. migrating from the legacy platform). Imported accounts are created **passwordless** and `import_pending`: legacy password hashes are never imported. On the user's first login with any password, a one-time magic reset link is emailed and completing it sets a fresh Argon2id password (clearing `import_pending`). Admin-tier role names in `roles` are stripped. Existing emails are skipped (not overwritten).

**Permission:** `users:import`

**Request body:**

```json
{
  "source": "legacy",
  "users": [
    {"email": "rider@example.com", "roles": ["user"], "legacy_id": "42", "locale": "sk",
     "disabled": false, "banned": false, "ban_reason": "", "marketing_emails": true}
  ]
}
```

**`marketing_emails`** (optional) carries the source system's marketing preference. It is stored
with `source=import` and `origin=<source>`, which is **not** treated as affirmative consent: a
migrated flag may be a default the user was never shown (a column defaulting to true, or a
pre-ticked consent checkbox, yields a `true` indistinguishable from a choice — Recital 32,
*Planet49* C-673/17). The value is preserved so the Operator can run a re-permission campaign
against it, but `IdentityService.MarketingAllowed` will return false for it, so it does not by
itself authorise sending. See `docs/PRIVACY.md` §2.1.

Requires the identity service to be wired (`HMAC_SECRET_FILE` + master key on the admin gateway).
Without it, accounts still import but the preference is dropped — which fails closed (no consent).

**Success response (200 OK):** per-user results.

```json
{"source": "legacy", "submitted": 1, "imported": 1, "consent_failed": 0,
 "results": [{"email": "rider@example.com", "status": "imported"}]}
```

`status` is `imported`, `skipped` (email already exists), or `error` (with an `error` code such as `invalid_email`, `create_failed`). `consent_failed` counts accounts that imported but whose marketing preference could not be persisted; a dropped preference fails closed.

#### GET /admin/roles

List the custom application-role catalog (`auth.app_roles`).

**Permission:** `roles:list`

**Success response (200 OK):**

```json
{"roles": [{"name": "moderator", "namespace": "forum", "description": "Forum moderator", "reserved": false, "created_at": "2026-06-19T00:00:00Z"}]}
```

#### POST /admin/roles

Create a custom application role. Reserved/admin-tier names are rejected (`role_reserved`).

**Permission:** `roles:create`

**Request body:**

```json
{"name": "moderator", "namespace": "forum", "description": "Forum moderator"}
```

#### DELETE /admin/roles/{name}

Delete a custom role from the catalog. Reserved roles cannot be deleted.

**Permission:** `roles:delete`

#### POST /admin/clients/{id}/rotate

Issue a new secret for a service client and invalidate the old one immediately. The new secret is returned once and never again; only its Argon2id hash is stored.

**Permission:** `clients:rotate`

The path is `/rotate`. It is **not** `/rotate-secret` -- that is the name of the CLI verb (`rotate-client-secret`), and it was documented as a path by mistake before 1.0.0. A request to `/rotate-secret` 404s.

**Success response (200 OK):**

```json
{"status": "rotated", "secret": "64-hex-character-secret"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_id` | No client id in the path |
| 404 | `client_not_found` | No such client |
| 500 | `internal_error` | Server error |

Audited as `admin_client_rotate`.

#### GET /admin/config

Read the runtime key-value configuration entries held in `auth.admin_config`. This is a small runtime store; environment variables remain the primary configuration mechanism and are not editable through it.

**Permission:** `config:read`

**Success response (200 OK):**

```json
{"entries": [{"key": "maintenance_banner", "value": "..."}]}
```

#### PUT /admin/config/{key}

Set one configuration key. The key is in the path and is shape-validated.

**Permission:** `config:write`

`PUT /admin/config` without a key is not a route and never was; it 404s.

**Request body:**

```json
{"value": "some-value"}
```

**Success response (200 OK):**

```json
{"status": "updated", "key": "maintenance_banner"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_key` | No key in the path |
| 400 | `invalid_key_format` | Key fails shape validation |
| 400 | `invalid_request` | Malformed JSON body |
| 500 | `internal_error` | Server error |

Audited as `admin_config_change`.

#### DELETE /admin/config/{key}

Delete one configuration key.

**Permission:** `config:write`

**Success response (200 OK):**

```json
{"status": "deleted", "key": "maintenance_banner"}
```

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `missing_key` | No key in the path |
| 500 | `internal_error` | Server error |

#### GET /admin/metrics

**Not implemented. Answers `501 not_implemented`.**

The route is mounted and gated on `metrics:read` with nothing behind it. It previously answered `200 OK` with a placeholder body while being documented as "get operational metrics", which is the worst of the available options: monitoring reads it as healthy and a caller cannot tell an empty feed from a working one.

Prometheus metrics for the main binary are at `GET /metrics`, gated on `VAULT_METRICS_ENABLED`. This endpoint is excluded from the stability contract (`spec.md` section 0.6), so implementing it later is not a breaking change.

**Permission:** `metrics:read`

### Admin Endpoints -- Email Branding

Nine routes managing per-app white-label branding and template overrides for outbound auth email. `spec.md` section 10.3 describes the resolution order; `spec.md` section 0.9 states, at length, what the per-app model does **not** guarantee -- it is a branding selector, not a tenancy boundary.

`email:read`, `email:write` and `email:delete` are service-wide permissions. They are not app-scoped: an admin who can edit one app's branding can edit every app's.

`{app}` is a slug matching `^[a-z0-9][a-z0-9_-]{0,63}$`. `{name}` is one of the seven template names: `verification`, `password_reset`, `new_device`, `account_locked`, `2fa_setup`, `suspicious_activity`, `email_otp`.

#### GET /admin/email-branding

List every stored branding row.

**Permission:** `email:read`

**Success response (200 OK):**

```json
{"branding": [
  {"app": "beon3", "app_name": "BeOn3", "logo_url": "https://cdn.example.com/beon3.png",
   "primary_color": "#00FF42", "from_name": "BeOn3 Security", "from_address": "no-reply@beon3.example",
   "updated_at": "2026-08-01T10:00:00Z", "updated_by": "admin@example.com"}
]}
```

#### GET /admin/email-branding/{app}

Read one app's branding row.

**Permission:** `email:read`

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_app` | Slug fails shape validation |
| 404 | `not_found` | No branding row for that app |

#### PUT /admin/email-branding/{app}

Create or replace one app's branding row. Any omitted or empty column falls back to the global branding at render time, so a partial row is valid.

**Permission:** `email:write`

**Request body:**

```json
{"app_name": "BeOn3", "logo_url": "https://cdn.example.com/beon3.png",
 "primary_color": "#00FF42", "from_name": "BeOn3 Security",
 "from_address": "no-reply@beon3.example"}
```

`from_address` is constrained by `VAULT_EMAIL_FROM_ALLOWED_DOMAINS`, so an admin cannot point a tenant's mail at a domain the deployment does not control.

**Success response (200 OK):** the stored row, in the shape `GET /admin/email-branding/{app}` returns.

#### DELETE /admin/email-branding/{app}

Remove one app's branding row. That app falls back to the global branding; there is no separate disable step.

**Permission:** `email:delete`

**Success response (200 OK):**

```json
{"status": "deleted"}
```

#### GET /admin/email-templates

List every stored template override across all apps.

**Permission:** `email:read`

**Success response (200 OK):**

```json
{"templates": [
  {"app": "beon3", "template_name": "verification", "subject": "Confirm your BeOn3 account",
   "html_content": "<p>...</p>", "text_content": "...", "enabled": true,
   "updated_at": "2026-08-01T10:00:00Z", "updated_by": "admin@example.com"}
]}
```

#### POST /admin/email-templates/preview

Validate candidate template content and render it against sample data. Stores nothing.

**Permission:** `email:write`

**Request body:**

```json
{"subject": "Confirm your {{.AppName}} account", "html_content": "<p>Hello {{.DisplayName}}</p>"}
```

**Success response (200 OK):**

```json
{"valid": true, "subject": "Confirm your BeOn3 account", "html": "<p>Hello Alice</p>", "text": "Hello Alice"}
```

Content that fails validation also returns `200`, with the failure in the body rather than as a status code -- this is a linter, not a write:

```json
{"valid": false, "error": "forbidden pattern: <script>"}
```

#### GET /admin/email-templates/{app}/{name}

Read one template override.

**Permission:** `email:read`

**Error responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `invalid_app` | Slug fails shape validation |
| 400 | `invalid_template` | Not one of the seven known template names |
| 404 | `not_found` | No override stored for that app and template |

#### PUT /admin/email-templates/{app}/{name}

Create or replace one template override.

**Permission:** `email:write`

**Request body:**

```json
{"subject": "Confirm your BeOn3 account", "html_content": "<p>...</p>",
 "text_content": "...", "enabled": true}
```

Content passes the same forbidden-pattern validation as filesystem overrides: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form action=...>`, `javascript:` URIs, `on*=` event handlers, and the Go template `call` and `js` directives are all rejected. Size is capped by `VAULT_MAX_EMAIL_TEMPLATE_SIZE`. `enabled` is a pointer field: omitting it leaves the current value unchanged.

**Success response (200 OK):** the stored override.

#### DELETE /admin/email-templates/{app}/{name}

Remove one template override. That app falls back to the embedded default for that template.

**Permission:** `email:delete`

**Success response (200 OK):**

```json
{"status": "deleted"}
```

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

Return the issuer metadata document.

**vault42 is not an OpenID Connect provider.** There is no authorization-code token endpoint, no ID token is issued to a relying party, `GET /user/profile` is not a UserInfo response, and `POST /auth/register` is end-user signup rather than RFC 7591 dynamic client registration. The document therefore states only what is true of this server, and is served at the conventional path so that a consumer looking for the key set finds it.

**Authentication:** None

**Success response (200 OK):**

```json
{
  "issuer": "https://vault42.example.com",
  "jwks_uri": "https://vault42.example.com/.well-known/jwks.json",
  "access_token_signing_alg_values_supported": ["RS256"]
}
```

`access_token_signing_alg_values_supported` is deliberately not named `id_token_signing_alg_values_supported`, because no ID token is ever issued. The algorithm is also published per key in the JWKS, which stays correct if a key of another algorithm is added; the summary key exists so a consumer can pin an expected algorithm before fetching the key set.

Keys that were previously advertised and are now absent -- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `registration_endpoint`, `scopes_supported`, `response_types_supported`, `grant_types_supported`, `subject_types_supported`, `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`, `dpop_signing_alg_values_supported` -- were each untrue of this server. `spec.md` section 20 lists why, one by one. They can be added back once the corresponding behaviour exists, which is an additive change; removing them later would not have been.

Clients that only need to verify a vault42-issued token should fetch `/.well-known/jwks.json` directly.

**curl example:**

```bash
curl https://vault42.example.com/.well-known/openid-configuration
```

---

## Endpoint Summary

**105 API routes: 62 on the main binary, 43 on the admin gateway.** This table is the complete set. `tests/spec/route_drift_test.go` parses the route registrations in `internal/server/server.go` and `internal/adminapi/router.go` with `go/ast` and fails the build if a row here has no route behind it, or if a route exists with no row. Adding an endpoint without a row is not possible.

The **Mounted when** column is the answer to "why does this endpoint 404 in production". A route in a group that is not mounted does not exist, and `net/http.ServeMux` answers `404` in `text/plain` -- not the JSON error envelope.

**Auth column key:**

- **None** -- public endpoint, no authentication required
- **Cookie** -- requires the `__Host-refresh_token` HttpOnly cookie
- **Basic** -- HTTP Basic authentication with client credentials
- **Bearer** -- requires `Authorization: Bearer <token>` with fingerprint verification
- **Bearer + Confirm** -- Bearer token plus a recent password confirmation via `POST /auth/confirm`
- **Bearer/Challenge** -- accepts both standard Bearer tokens and 2FA challenge tokens
- **Bearer + password** -- Bearer token plus the current password re-submitted in the request body
- **Scope `<name>`** -- Bearer client-credential token carrying that scope. `mint:token` and both `svcdoc:*` scopes additionally require the token to carry a `client_id` claim, which no user token does; without one the request is `403 client_credentials_required` even though the scope check passed
- **Session** -- admin gateway session cookie, behind mTLS and loopback-only enforcement. The permission the session's role must hold is in the Permission column.

**Rate limit column.** `POST /mint` and the `/service/documents/*` routes are keyed by the authenticated `client_id`, not by source IP: their limiters are mounted inside the authentication middleware, so the per-client key function reads the client from the validated claims. Its source-IP fallback is unreachable, because a claimless request is rejected by the auth middleware first. See the endpoint sections above.

<!-- BEGIN ENDPOINT SUMMARY -->

### Main binary

| Method | Path | Auth | Rate limit | Mounted when | Description |
|--------|------|------|------------|--------------|-------------|
| `GET` | `/healthz` | None | -- | Always | Liveness probe |
| `GET` | `/readyz` | None | -- | Always | Readiness probe (pings DB + cache) |
| `GET` | `/metrics` | None | -- | `VAULT_METRICS_ENABLED` | Prometheus metrics |
| `GET` | `/auth/capabilities` | None | -- | Always | Server capability discovery |
| `POST` | `/auth/register` | None | 3/hour | Always | Register a new user; `403 registration_disabled` unless enabled |
| `POST` | `/auth/login` | None | 5/15min | Always | Authenticate; may return a 2FA challenge |
| `POST` | `/auth/refresh` | Cookie | 30/min | Always | Rotate the refresh family |
| `POST` | `/auth/logout` | Bearer | -- | Always | Revoke every session |
| `GET` | `/auth/verify-email` | None | 10/hour | Always | Verify an email address |
| `POST` | `/auth/confirm` | Bearer | 5/15min | Always | Confirm password for elevated access |
| `POST` | `/auth/password/reset` | None | 3/hour | Always | Request a password reset |
| `POST` | `/auth/password/reset/confirm` | None | 3/hour | Always | Complete a password reset |
| `POST` | `/user/password` | Bearer | 5/15min | Always | Change password |
| `GET` | `/user/profile` | Bearer | -- | Always | Get user profile |
| `PUT` | `/user/profile` | Bearer | -- | Always | Partial profile update |
| `GET` | `/user/sessions` | Bearer | -- | Always | List active sessions |
| `DELETE` | `/user/sessions` | Bearer | -- | Always | Revoke all sessions |
| `DELETE` | `/user/sessions/{id}` | Bearer | -- | Always | Revoke one session |
| `GET` | `/user/devices` | Bearer | -- | Always | List devices |
| `PATCH` | `/user/devices/{id}` | Bearer | -- | Always | Rename a device |
| `DELETE` | `/user/devices/{id}` | Bearer | -- | Always | Remove a device |
| `DELETE` | `/user/account` | Bearer + password | 3/hour, fail-closed | Account-recovery repository wired | Self-service erasure with escrow |
| `GET` | `/user/data-export` | Bearer | 5/min | Always | GDPR Art. 15/20 data export |
| `GET` | `/user/social` | Bearer | -- | Always | List linked federated identities |
| `DELETE` | `/user/social/{id}` | Bearer | 5/15min | Always | Unlink a provider and its stored tokens |
| `GET` | `/auth/2fa/status` | Bearer | -- | Always | MFA status and `mfa_methods` |
| `POST` | `/auth/2fa/totp/setup` | Bearer + Confirm | -- | Always | Begin TOTP setup |
| `POST` | `/auth/2fa/totp/verify` | Bearer/Challenge | 5/5min, fail-closed | Always | Verify a TOTP code |
| `DELETE` | `/auth/2fa/totp` | Bearer + Confirm | -- | Always | Disable TOTP |
| `POST` | `/auth/2fa/webauthn/register/begin` | Bearer + Confirm | -- | Always | Begin WebAuthn registration |
| `POST` | `/auth/2fa/webauthn/register/finish` | Bearer + Confirm | -- | Always | Complete WebAuthn registration |
| `POST` | `/auth/2fa/webauthn/verify/begin` | Bearer/Challenge | -- | Always | Begin WebAuthn verification |
| `POST` | `/auth/2fa/webauthn/verify/finish` | Bearer/Challenge | -- | Always | Complete WebAuthn verification |
| `GET` | `/auth/2fa/webauthn/credentials` | Bearer | -- | Always | List WebAuthn credentials |
| `DELETE` | `/auth/2fa/webauthn/credentials/{id}` | Bearer + Confirm | -- | Always | Delete a WebAuthn credential |
| `POST` | `/auth/2fa/backup-codes` | Bearer + Confirm | -- | Always | Generate backup codes |
| `POST` | `/auth/2fa/backup-code/verify` | Bearer/Challenge | 5/5min, fail-closed | Always | Consume a backup code |
| `POST` | `/auth/2fa/email-otp/verify` | Bearer/Challenge | 5/5min, fail-closed | Always | Verify an email OTP code |
| `POST` | `/auth/2fa/email-otp/resend` | Bearer/Challenge | 5/5min, fail-closed | Always | Resend an email OTP code |
| `GET` | `/user/identity` | Bearer | 30/min | Identity store enabled | Get identity profile |
| `PUT` | `/user/identity` | Bearer | 10/min | Identity store enabled | Upsert identity profile |
| `DELETE` | `/user/identity` | Bearer + Confirm | 5/15min | Identity store enabled | Delete identity profile |
| `POST` | `/user/marketing/unsubscribe` | Bearer | 30/min | Identity store enabled | Withdraw marketing consent |
| `POST` | `/user/blobs` | Bearer | 10/min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Upload an encrypted blob |
| `GET` | `/user/blobs` | Bearer | 30/min | `VAULT_BLOB_QUOTA_BYTES` > 0 | List blobs and quota |
| `GET` | `/user/blobs/{id}` | Bearer | 30/min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Download a blob |
| `DELETE` | `/user/blobs/{id}` | Bearer + Confirm | 5/15min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Delete a blob |
| `PUT` | `/user/blobs/named/{name}` | Bearer | 10/min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Create or replace a named blob |
| `GET` | `/user/blobs/named/{name}` | Bearer | 30/min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Download a blob by name |
| `DELETE` | `/user/blobs/named/{name}` | Bearer + Confirm | 5/15min | `VAULT_BLOB_QUOTA_BYTES` > 0 | Delete a blob by name |
| `GET` | `/auth/oauth2/authorize` | None | 10/min | >= 1 provider configured | Start a social login |
| `GET` | `/auth/oauth2/callback/{provider}` | None | 10/min | >= 1 provider configured | Provider redirect target |
| `POST` | `/auth/oauth2/exchange` | None | 10/min | >= 1 provider configured | Exchange the one-time code for tokens |
| `POST` | `/client/token` | Basic | 10/min | Always | Client-credentials grant |
| `POST` | `/kms/unwrap` | Scope `kms:unwrap` | 30/min, fail-closed | `KMS_ROOT_KEY_FILE` set | KEK envelope-unwrap oracle |
| `POST` | `/mint` | Scope `mint:token` | 60/min per client, fail-closed | `VAULT_MINT_ENABLED` | Sign a token for a caller-asserted subject |
| `PUT` | `/service/documents/{subject}/{key}` | Scope `svcdoc:write` | 60/min per client | `VAULT_SVCDOC_ENABLED` | Store a service-scoped JSON document |
| `GET` | `/service/documents/{subject}/{key}` | Scope `svcdoc:read` | 300/min per client | `VAULT_SVCDOC_ENABLED` | Read a service-scoped JSON document |
| `DELETE` | `/service/documents/{subject}/{key}` | Scope `svcdoc:write` | 60/min per client | `VAULT_SVCDOC_ENABLED` | Delete a service-scoped JSON document |
| `GET` | `/service/documents/{subject}` | Scope `svcdoc:read` | 300/min per client | `VAULT_SVCDOC_ENABLED` | List documents visible to the caller for a subject |
| `GET` | `/.well-known/jwks.json` | None | -- | Always | JWKS public keys |
| `GET` | `/.well-known/openid-configuration` | None | -- | Always | Issuer metadata |

### Admin gateway

Served by `cmd/admin-gateway` only, never by the main binary. `admin-gateway.md` covers deployment, the killswitch and the full RBAC matrix.

| Method | Path | Auth | Permission | Mounted when | Description |
|--------|------|------|------------|--------------|-------------|
| `POST` | `/admin/auth/login` | None | -- | Always | Password + optional TOTP, 10/min/IP |
| `POST` | `/admin/auth/logout` | Session | -- | Always | Revoke the current admin session |
| `GET` | `/admin/status` | Session | -- | Always | Current admin identity and 2FA state |
| `POST` | `/admin/admins/me/totp/setup` | Session | -- | Always | Provision the caller's TOTP secret |
| `POST` | `/admin/admins/me/totp/verify` | Session | -- | Always | Verify and enable the caller's TOTP |
| `GET` | `/admin/keys` | Session | `keys:list` | Always | List signing key metadata |
| `POST` | `/admin/keys/rotate` | Session | `keys:rotate` | Always | Generate a key, retire the old one |
| `DELETE` | `/admin/keys/{kid}` | Session | `keys:revoke` | Always | Remove a key from the JWKS |
| `GET` | `/admin/users` | Session | `users:list` | Always | Look a user up by `?q=` (id or email) |
| `GET` | `/admin/users/{id}` | Session | `users:read` | Always | User detail |
| `POST` | `/admin/users/import` | Session | `users:import` | Always | Batch import, passwordless + `import_pending` |
| `POST` | `/admin/users/{id}/lock` | Session | `users:lock` | Always | Lock an account |
| `POST` | `/admin/users/{id}/unlock` | Session | `users:unlock` | Always | Unlock an account |
| `POST` | `/admin/users/{id}/require-password-reset` | Session | `users:reset` | Always | Force a password reset, revoking live sessions |
| `POST` | `/admin/users/{id}/clear-password-reset` | Session | `users:reset` | Always | Withdraw a forced password reset |
| `DELETE` | `/admin/users/{id}` | Session | `users:delete` | Always | Operator-initiated erasure |
| `GET` | `/admin/sessions` | Session | `admins:manage` | Always | List active **admin** sessions |
| `POST` | `/admin/sessions/revoke-all` | Session | `sessions:revoke` | Always | Revoke every session service-wide |
| `GET` | `/admin/audit` | Session | `audit:read` | Always | Query the audit log |
| `GET` | `/admin/clients` | Session | `clients:list` | Always | List service clients |
| `GET` | `/admin/clients/{id}` | Session | `clients:read` | Always | Client detail |
| `POST` | `/admin/clients` | Session | `clients:create` | Always | Create a client, secret shown once |
| `POST` | `/admin/clients/{id}/revoke` | Session | `clients:revoke` | Always | Deactivate a client |
| `POST` | `/admin/clients/{id}/rotate` | Session | `clients:rotate` | Always | Rotate the client secret |
| `GET` | `/admin/roles` | Session | `roles:list` | Always | Application-role catalog |
| `POST` | `/admin/roles` | Session | `roles:create` | Always | Create a custom application role |
| `DELETE` | `/admin/roles/{name}` | Session | `roles:delete` | Always | Delete a non-reserved role |
| `GET` | `/admin/email-branding` | Session | `email:read` | Always | All per-app branding rows |
| `GET` | `/admin/email-branding/{app}` | Session | `email:read` | Always | One app's branding |
| `PUT` | `/admin/email-branding/{app}` | Session | `email:write` | Always | Upsert one app's branding |
| `DELETE` | `/admin/email-branding/{app}` | Session | `email:delete` | Always | Drop back to global branding |
| `GET` | `/admin/email-templates` | Session | `email:read` | Always | All template overrides |
| `POST` | `/admin/email-templates/preview` | Session | `email:write` | Always | Validate and render against sample data |
| `GET` | `/admin/email-templates/{app}/{name}` | Session | `email:read` | Always | One template override |
| `PUT` | `/admin/email-templates/{app}/{name}` | Session | `email:write` | Always | Upsert one template override |
| `DELETE` | `/admin/email-templates/{app}/{name}` | Session | `email:delete` | Always | Drop back to the default template |
| `GET` | `/admin/config` | Session | `config:read` | Always | Read runtime config entries |
| `PUT` | `/admin/config/{key}` | Session | `config:write` | Always | Set one config key |
| `DELETE` | `/admin/config/{key}` | Session | `config:write` | Always | Delete one config key |
| `GET` | `/admin/metrics` | Session | `metrics:read` | Always | **Unimplemented; answers `501 not_implemented`** |
| `GET` | `/admin/admins` | Session | `admins:manage` | Always | List admin accounts |
| `POST` | `/admin/admins` | Session | `admins:create` | Always | Create an admin (20-char minimum password) |
| `POST` | `/admin/admins/{id}/revoke` | Session | `admins:revoke` | Always | Revoke an admin; self-revocation refused |

<!-- END ENDPOINT SUMMARY -->

### Surfaces that are not API routes

Thirteen further registrations exist and are outside this table and outside the stability contract: the embedded SPA catch-all `/` on the main binary (only when `VAULT_SERVE_FRONTEND` is set or the honeypot profile is active), and the admin gateway's ten HTML console pages plus `GET /admin/static/`. `spec.md` section 16.3 lists them.

---

## Cookie Reference

| Cookie | Path | Attributes | Set By | Cleared By |
|--------|------|------------|--------|------------|
| `__Host-refresh_token` | `/` | `HttpOnly`, `Secure` (when TLS), `SameSite=Strict` | Login, Refresh, TOTP Verify (MFA), WebAuthn Verify Finish (MFA), Email OTP Verify (MFA), OAuth2 Callback | Logout, Refresh (on error) |

The `Secure` flag is derived from the server's TLS configuration, not the profile name. In development with TLS enabled, cookies are still marked `Secure`.
