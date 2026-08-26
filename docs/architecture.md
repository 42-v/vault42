# Architecture

> Vault42 -- System Architecture & Auth Flows

## System Overview

Vault42 is a production-grade JWT authentication and authorization microservice
written in Go. It provides user registration, login, OAuth2 social login,
two-factor authentication (TOTP and WebAuthn/FIDO2), token management, password
reset, device tracking, and an admin CLI -- all backed by PostgreSQL with an
optional Redis cache layer.

The system is deployed via a single Helm chart to Kubernetes. It serves HTTPS by
default (TLS 1.3 minimum), enforces single-origin CORS, and runs as a statically
compiled binary inside a distroless container with no shell, no capabilities, and
a read-only filesystem.

### High-Level Request Flow

```text
                                 +-------------------+
                                 |   Kubernetes      |
                                 |   Ingress (nginx) |
                                 +--------+----------+
                                          |
                                    TLS termination
                                    or passthrough
                                          |
                                          v
+-------------------------------------------------------------------------+
|  Vault42 (Go process, port 8443)                                      |
|                                                                         |
|  +-- Recovery --------------------------------------------------------+ |
|  | +-- RequestID ---------------------------------------------------+ | |
|  | | +-- Logger ---------------------------------------------------+| | |
|  | | | +-- SecurityHeaders ---------------------------------------+|| | |
|  | | | | +-- CORS -----------------------------------------------+||| | |
|  | | | | | +-- MaxBody (8KB) -----------------------------------+|||| | |
|  | | | | | |                                                    ||||| | |
|  | | | | | |  http.ServeMux (Go 1.22+ pattern routing)          ||||| | |
|  | | | | | |                                                    ||||| | |
|  | | | | | |  Public routes:    /healthz, /auth/*, /.well-known ||||| | |
|  | | | | | |  Authed routes:    Auth -> Fingerprint            ||||| | |
|  | | | | | |  Confirmed routes: Auth -> Fingerprint -> Confirmed||||| | |
|  | | | | | |  Challenge routes: AuthChallenge -> Fingerprint    ||||| | |
|  | | | | | |                                                    ||||| | |
|  | | | | | +----------------------------------------------------+|||| | |
|  | | | | +--------------------------------------------------------+||| | |
|  | | | +------------------------------------------------------------+|| | |
|  | | +----------------------------------------------------------------+| | |
|  | +--------------------------------------------------------------------+ |
|  +----------------------------------------------------------------------+ |
|                                                                         |
|  Handler -> Service -> Repository -> PostgreSQL                         |
|                                                                         |
|  Cache (Redis / Memory / Postgres) -- rate limits, sessions, tokens     |
|  Audit Logger -> append-only audit_log table                            |
+-------------------------------------------------------------------------+
```

When `ServeFrontend` is enabled, the catch-all `/` route serves the embedded Vue
SPA from `internal/frontend/`. API routes take priority via Go 1.22+ ServeMux
pattern specificity (e.g., `POST /auth/login` is more specific than `/` and is
always matched first). This allows Vault42 to serve both the API and the UI
from a single binary without path conflicts.

## Project Layout

All application code lives under `internal/`, which Go enforces as non-importable
by external modules. This is intentional -- the service is not a library.

```text
cmd/vault/main.go            Entry point: config, migrations, wiring, server start
cmd/bridge/                  Honeypot bridge reverse proxy (standalone binary, stdlib only)
  main.go                    Entry point, config, graceful shutdown
  config.go                  Env var parsing (BRIDGE_* vars)
  proxy.go                   httputil.ReverseProxy routing (real vs honeypot)
  detection.go               Scoring: UA detection, rate tracking, login failures
  state.go                   Flagged IP state (sync.Map + inline RESP2 Redis)
  admin.go                   Admin API: flag/unflag/list IPs
  health.go                  /bridge/healthz, /bridge/readyz
  decoy.go                   Fake login pages for scanner paths
  decoys/                    go:embed HTML templates (wp-login, phpmyadmin, cpanel, admin)
internal/
  config/                    Environment + _FILE secret loading, profile system
    config.go                Config struct, Load(), env parsing
    profiles.go              Production / embedded / dev defaults
    secrets.go               LoadSecret() -- read from file, zero after read
  server/
    server.go                HTTP server, TLS, middleware chain, route registration
  middleware/
    recovery.go              Panic recovery -> 500
    requestid.go             X-Request-ID generation (crypto/rand hex)
    logger.go                Request logging with timing (silences health probes)
    security_headers.go      HSTS, CSP, X-Frame-Options, etc.
    cors.go                  Single-origin CORS (or allow-all in dev)
    maxbody.go               Request body size limit (8KB)
    auth.go                  JWT Bearer validation, challenge token support, RequireScope,
                             Confirmed (recent-password-confirmation gate)
    fingerprint.go           Device fingerprint verification against JWT claim
    ratelimit.go             Sliding window rate limiting via cache, trusted proxies
    dpop.go                  DPoP proof validation (RFC 9449). When VAULT_DPOP_ENABLED,
                             issuance stamps cnf.jkt on access and challenge tokens
                             on login, refresh and 2FA verify; /client/token and the
                             OAuth callback are not wrapped. Refresh tokens stay
                             unbound and there is no DPoP-Nonce
  handler/
    auth.go                  Register, Login, Refresh, Logout, VerifyEmail, ConfirmPassword
    oauth.go                 OAuth2 Authorize + Callback (Google, GitHub, Facebook)
    password.go              Password reset request/confirm, password change
    totp.go                  TOTP setup, verify, disable
    webauthn.go              WebAuthn register/verify begin/finish, credential management
    mfa.go                   MFA status endpoint
    backup_codes.go          Backup code generation
    client.go                Client credentials grant (service-to-service)
    user.go                  Profile, sessions, devices
    identity.go              Identity store: get, put (upsert), delete encrypted PII
    blob.go                  Blob storage: upload, list, download, delete encrypted files
    kms.go                   POST /kms/unwrap: KEK envelope unwrap, uniform opaque failure
    wellknown.go             /.well-known/jwks.json and openid-configuration
    health.go                /healthz (liveness) and /readyz (readiness)
    response.go              JSON response/error helpers
  service/
    auth.go                  AuthService: register, login, refresh, logout, MFA completion
    token.go                 TokenService: JWT issuance, challenge tokens, key rotation
    mfa.go                   MFAService: MFA policy decisions (required? which methods?)
    identity.go              IdentityService: encrypted PII with pseudonymous keys
    blob.go                  BlobService: compress + encrypt blob storage with quotas
    hibp.go                  HIBPClient: password breach checking via k-anonymity
  repository/
    repository.go            Interfaces for all domain entities (14 repository interfaces)
    postgres/                pgx/v5 implementations of every interface
  model/                     Domain structs: User, RefreshToken, Device, Client, IdentityProfile, Blob, etc.
  jwt/                       Stdlib-only JWT implementation (RS256 sign/verify, ES256 verify, parsing, claims)
  redis/                     Stdlib-only Redis RESP2 client with connection pooling (PING, GET, SET, DEL, GETDEL, INCR, EXPIRE, EXISTS)
  crypto/
    jwt.go                   JWKS serialization, PKCS#8 RSA loading (LoadSigningKeyPEM), KIDFromPublicKey
    argon2.go                HashPassword, VerifyPassword (Argon2id, constant-time, semaphore-limited to 4 concurrent ops)
    fingerprint.go           ComputeFingerprint (SHA256 over length-prefixed fields)
    totp.go                  TOTP generation/validation (RFC 6238, hand-rolled)
    aes.go                   AES-256-GCM encrypt/decrypt (TOTP secret encryption)
    hmac.go                  HMAC-SHA256 sign/verify (OAuth2 state)
    hash.go                  SHA256Hex helper
    random.go                RandomHex, RandomUUID, RandomToken (crypto/rand)
    constant.go              SecureCompare (constant-time string comparison)
    dpop.go                  DPoP proof generation/validation (RFC 9449)
  cache/
    cache.go                 Cache interface (Get, Set, Delete, Increment, Exists, etc.)
    factory.go               NewCache() factory: redis / memory / postgres
    redis.go                 Redis implementation (internal/redis client)
    memory.go                In-memory implementation (sync.RWMutex + TTL expiration)
    postgres.go              PostgreSQL fallback implementation
  migrate/
    migrate.go               SQL migration runner (~40 lines, hand-rolled)
  audit/
    audit.go                 Append-only audit logger with optional batching
  email/                     EmailSender interface + SMTP + SendGrid adapters
    templates/               HTML templates embedded via go:embed (verification, reset, etc.)
                             Override with filesystem templates via VAULT_EMAIL_TEMPLATES_DIR
  frontend/                  Embedded Vue SPA serving via go:embed
  honeypot/                  Honeypot mode alerting, fake tokens, and threat observation
  keystore/                  Database-backed signing key storage with AES-256-GCM encryption at rest (master key, kid as AAD). Supports key rotation, revocation, multi-pod refresh (60s default), and automatic cleanup of expired retired keys.
  kms/                       KEK envelope-unwrap oracle behind POST /kms/unwrap. Per-kid KEKs are derived from a KMS root secret (KMS_ROOT_KEY_FILE) via HKDF-SHA256 with a versioned, domain-separated info label, cryptographically separate from the master key. Wrap/Unwrap reuse the AES-256-GCM AEAD with kid as AAD; every unwrap failure collapses to one opaque error (oracle-resistant).
  metrics/                   Hand-rolled Prometheus text exposition format. Collector aggregates argon2 semaphore, login, and token counters. No external dependencies.
  oauth2/                    OAuth2/OIDC provider implementations (Google, GitHub, etc.)
  cli/                       Admin CLI commands (add-client, rotate-jwks, seed, cleanup-recovery, export-audit, etc.)
  seed/                      Declarative JSON seeding for clients and users (idempotent)
  httputil/                  Shared HTTP response helpers
  sanitize/                  Input sanitization (email, strings, URLs, locale)
  useragent/                 User-Agent parsing for device friendly names

charts/vault/                Helm chart (single chart for all environments)
migrations/                  SQL migration files (executed in sorted order)
web/                         Vue 3 + Vite + Tailwind frontend SPA
  src/__tests__/             Vitest + Vue Test Utils frontend tests
packages/vue/                @vault42/vue composable library with i18n plugin (38 locales)
tests/
  unit/                      Stdlib-only unit tests (47 test functions)
  attack/                    208 attack vector simulations (real server + testcontainers)
  compliance/                157 NIST SP 800-63B and OWASP ASVS verification checks
  fuzz/                      10 Go built-in fuzzing targets
  integration/               Integration tests with testcontainers (Postgres + Redis)
  browser/                   11 chromedp browser tests (separate go.mod)
  honeypot/                  Bridge + honeypot E2E tests (honeypot_e2e build tag)
  stress/                    12 load/stress tests across 3 tiers (stress build tag)
```

## Middleware Chain

The middleware chain is assembled in `internal/server/server.go` at `Start()`.
Middleware wraps from inside out, so the **execution order is the reverse of the
wrapping order**:

```text
Incoming request
  |
  v
1. Recovery          Catches panics, returns 500 JSON. Always outermost.
  |
  v
2. RequestID         Generates a 32-char hex ID (crypto/rand), sets X-Request-ID
                     header, stores in context under "request_id".
  |
  v
3. Logger            Wraps a statusRecorder around ResponseWriter. After the
                     request completes, logs: METHOD PATH STATUS DURATION [REQUEST_ID].
                     Health probes (/healthz, /readyz) are silenced.
  |
  v
4. SecurityHeaders   Sets response headers on every request:
                       Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
                       Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
                       X-Content-Type-Options: nosniff
                       X-Frame-Options: DENY
                       X-XSS-Protection: 0
                       Referrer-Policy: no-referrer
                       Cache-Control: no-store
                       Pragma: no-cache
  |
  v
5. IPAccess          IP allowlist/blocklist and geo-fencing enforcement.
                     Uses ClientIP() for resolution (respects REAL_IP_HEADER and
                     TRUSTED_PROXIES). Geo checks use the configured GEO_IP_HEADER.
                     Bypasses /healthz and /readyz. Zero-cost when no lists configured.
                     Blocklist supports runtime updates (atomic copy-on-write).
  |
  v
6. CORS              Sets Access-Control-Allow-Origin (single origin or reflected
                     origin in dev allow-all mode), Allow-Credentials: true.
                     OPTIONS preflight returns 204 and short-circuits.
  |
  v
7. MaxBody           Wraps r.Body with http.MaxBytesReader(8KB). Any read beyond
                     8KB returns an error to the handler.
  |
  v
8. [Route handler]   http.ServeMux dispatches to the matched route.
```

**Per-route middleware** is applied inside `setupRoutes()` using three wrapper
functions:

| Wrapper | Middleware Stack | Used For |
|---------|-----------------|----------|
| `authed(h)` | Auth -> Fingerprint -> h | Standard authenticated endpoints |
| `authedChallenge(h)` | AuthChallenge -> Fingerprint -> h | 2FA verify endpoints (accept `2fa_challenge` tokens) |
| `confirmed(h)` | Auth -> Fingerprint -> Confirmed -> h | Sensitive operations (TOTP setup/disable, WebAuthn register/delete, backup codes) |

There is no admin wrapper in `setupRoutes()`. Admin endpoints (key rotation,
revocation, user and client management) are not served by this mux at all: they
live on the separate admin gateway binary, whose router is built by
`adminapi.NewRouter` and whose authentication is `adminapi.SessionAuth` -- a
session-token gate backed by the `admin_sessions` table, not a static bearer
token. This table used to name an `admin(h)` wrapper over
`middleware.AdminAuth`; neither has been in a served request path.
`ADMIN_TOKEN_FILE` is not consulted per request: it seeds
`admin_config.admin_token_hash` on first boot, and that hash is what the admin
CLI verifies against. See [config.md](config.md#admin-token-provisioning) and
[admin-gateway.md](admin-gateway.md).

When `VAULT_KEY_ROTATION_DB` is enabled, `authed` and `authedChallenge` use
`AuthDynamic` / `AuthChallengeDynamic` variants that resolve signing keys from
the keystore's dynamic key provider instead of the static file-based key map.

**Scope gating (`RequireScope`).** Authentication answers "is this token valid"; it does not
answer "may this token do this". `middleware.RequireScope(scope)`
(`internal/middleware/auth.go`) reads the validated claims from context and returns
`403 insufficient_scope` unless `claims.Scopes` contains the exact string. It **must** be
chained after an `Auth` middleware -- absent claims are a `401`, never a pass -- and it is the
only per-route authorization primitive on the user-facing plane. JWT `roles` are advisory to
relying parties; no vault42 route authorizes on them.

Its one current consumer is the KMS unwrap oracle, which is also the longest chain in the
server and worth reading in full:

```text
POST /kms/unwrap                        mounted only when KMS_ROOT_KEY_FILE is set
  |
  v
kmsUnwrapRL          RateLimit(30/min, per IP, FailClosed: true)
  |                  Fail-closed like login/register/reset, unlike the OAuth
  |                  callback: a cache outage must not let the per-pod in-memory
  |                  fallback multiply the key-release rate across replicas (audit L4).
  v
authMw               Auth (or AuthDynamic under VAULT_KEY_ROTATION_DB). Resolves and
  |                  validates the client-credential token, puts claims in context.
  v
RequireScope("kms:unwrap")
  |                  403 insufficient_scope without the exact scope.
  v
dpopWrap             Identity when VAULT_DPOP_ENABLED=false. When true, the DPoP
  |                  middleware runs INSIDE the auth wrappers so it sees resolved
  |                  claims and enforces cnf.jkt. KMS tokens come from
  |                  POST /client/token, which is not a DPoP issuance path, so
  |                  they never carry cnf.jkt and a missing proof still passes.
  |                  GET /auth/oauth2/callback/{provider} is also unwrapped: the
  |                  provider redirects the browser with a GET.
  v
KMSHandler.Unwrap    Re-checks claims for nil (defense in depth), then unwraps.
                     Every post-authorization failure collapses to one opaque
                     400 unwrap_failed; the audit record carries kid + outcome only.
```

Wiring: the `POST /kms/unwrap` mount in `internal/server/server.go`. Rationale and threat
model: the `internal/kms` package doc and [Attack Cheatsheet §8](cheatsheet.md).

Rate limiting middleware is instantiated per-endpoint group with different limits
and key functions, then wraps the appropriate routes:

| Rate Limit | Limit | Window | Key | Endpoints | On cache outage |
|------------|-------|--------|-----|-----------|-----------------|
| `loginRL` | 5 | 15 min | IP | POST /auth/login | Closed |
| `registerRL` | 3 | 1 hour | IP | POST /auth/register | Closed |
| `refreshRL` | 30 | 1 min | IP | POST /auth/refresh | In-memory fallback |
| `passwordResetRL` | 3 | 1 hour | IP | POST /auth/password/reset, /reset/confirm | Closed |
| `totpRL` | 5 | 5 min | IP | POST /auth/2fa/{totp,backup-code,email-otp}/verify and email-otp/resend | Closed |
| `confirmRL` | 5 | 15 min | user ID | POST /auth/confirm (and the other confirmRL routes) | In-memory fallback |
| `clientTokenRL` | 10 | 1 min | IP | POST /client/token | Closed |
| `oauthCallbackRL` | 10 | 1 min | IP | GET /auth/oauth2/callback/{provider} | In-memory fallback |
| `authorizeRL` | 10 | 1 min | IP | GET /auth/oauth2/authorize | In-memory fallback |
| `oauthExchangeRL` | 10 | 1 min | IP | POST /auth/oauth2/exchange | In-memory fallback |
| `kmsUnwrapRL` | 30 | 1 min | IP | POST /kms/unwrap | Closed |
| `mintRL` | 60 | 1 min | client_id | POST /mint | Closed |

Rate limiting uses `cache.Increment()` with a fixed window. On cache failure an
ordinary limiter falls back to a per-process in-memory counter: the limit stays
enforced per pod, it is not lifted. A limiter marked Closed rejects with
`503 rate_limiter_unavailable` instead, because the per-pod fallback would
multiply the budget by the replica count. Login, register, password reset,
TOTP/backup/email-OTP verify, `POST /client/token`, account deletion,
`POST /kms/unwrap` and `POST /mint` are Closed. The OAuth callback is not:
it used to share `loginRL` and no longer does (`internal/server/server.go`).
A cache outage here is a per-pod 10/min, not a 503, and not "allow through".

See: `internal/server/server.go`, `internal/middleware/`

## Request Lifecycle

Trace of an authenticated `GET /user/profile` request:

```text
1. TCP connection arrives at the Go HTTP server (TLS 1.3 if enabled)
2. Recovery middleware installs panic handler via defer/recover
3. RequestID generates "a1b2c3d4..." and stores in context
4. Logger records start time, wraps ResponseWriter with statusRecorder
5. SecurityHeaders writes HSTS, CSP, etc. to response headers
6. CORS writes Access-Control-Allow-Origin header
7. MaxBody wraps request body (not relevant for GET, but always applied)
8. ServeMux matches "GET /user/profile" -> authed(userHandler.Profile)
9. Auth middleware:
   a. Extracts "Bearer <token>" from Authorization header
   b. Calls vaultcrypto.ParseAndValidate():
      - Checks token size <= 8KB
      - Enforces RS256 algorithm whitelist
      - Rejects jku/x5u/x5c/jwk headers
      - Validates kid format (UUID-safe characters only)
      - Looks up public key by kid from the in-memory key map
      - Validates exp, nbf, iss, aud claims
   c. Checks token_type is "Bearer" (not "2fa_challenge")
   d. Stores *VaultClaims in context under "claims" key
10. Fingerprint middleware:
    a. Reads claims from context
    b. Computes SHA256(len+IP | len+UserAgent | len+AcceptLanguage | len+TLS) (TLS field reserved, currently empty)
    c. Constant-time compares computed fingerprint against claims.Fingerprint
    d. Rejects on mismatch (or logs in soft mode)
11. userHandler.Profile():
    a. Reads claims from context via middleware.GetClaims(ctx)
    b. Calls userRepo.GetByID(ctx, claims.Subject)
    c. Returns JSON response with user profile fields
12. Logger records: "GET /user/profile 200 1.234ms [a1b2c3d4...]"
```

### Context Values

Values flow through the request context:

| Key | Type | Set By | Used By |
|-----|------|--------|---------|
| `"request_id"` | `string` | RequestID middleware | Logger, any handler |
| `"claims"` | `*vaultcrypto.VaultClaims` | Auth/AuthChallenge middleware | Fingerprint, Confirmed, all handlers |

## Auth Flows

> **0.8.0 additions**:
> account-state enforcement (`disabled`/`banned`/`deleted`) is applied on **every
> token-issuance path** -- password login, token refresh (revoking the family),
> and the OAuth callback -- so a ban takes effect across all of them. Imported
> accounts (`import_pending`, no password) are intercepted on first login to force
> a magic-link claim, or claimed via an OAuth-verified email. Any OpenID Connect
> issuer can act as an authority (JWKS-verified ID tokens), and custom application
> roles come from the `auth.app_roles` catalog.

### Registration Flow

```text
Client                           Vault42                         PostgreSQL
  |                                |                               |
  |  POST /auth/register           |                               |
  |  {email, password, ...}        |                               |
  |------------------------------->|                               |
  |                                |                               |
  |                   registerRL rate limit check                  |
  |                                |                               |
  |                   Validate email format                        |
  |                   Check password length >= 15 chars            |
  |                   Check HIBP breach database (k-anonymity)     |
  |                                |                               |
  |                                |  GetByEmail(email)            |
  |                                |------------------------------>|
  |                                |  nil (not found)              |
  |                                |<------------------------------|
  |                                |                               |
  |                   Hash password (Argon2id: 46MiB, 1 iter)     |
  |                   Generate UUID for user ID                    |
  |                                |                               |
  |                                |  Create(user)                 |
  |                                |------------------------------>|
  |                                |  OK                           |
  |                                |<------------------------------|
  |                                |                               |
  |                   Store password in history                    |
  |                   Log audit event (registration)               |
  |                   Send verification email (async goroutine)    |
  |                     -> store verify:<hash> in cache (24h TTL)  |
  |                                |                               |
  |  201 {user_id, email}          |                               |
  |<-------------------------------|                               |
```

If the email is already taken, the handler returns the **same 201 response** to
prevent user enumeration:
`{"status":"verification_email_sent","message":"If this email is not already registered..."}`.

See: `internal/handler/auth.go` Register(), `internal/service/auth.go` Register()

### Login Flow

```text
Client                           Vault42                         PostgreSQL
  |                                |                               |
  |  POST /auth/login              |                               |
  |  {email, password}             |                               |
  |------------------------------->|                               |
  |                                |                               |
  |                   loginRL rate limit check                     |
  |                                |                               |
  |                                |  GetByEmail(email)            |
  |                                |------------------------------>|
  |                                |  user (or nil)                |
  |                                |<------------------------------|
  |                                |                               |
  |                   If user is nil:                              |
  |                     VerifyPassword(pw, DummyHash)  <-- constant-time burn
  |                     Return "invalid_credentials"               |
  |                                |                               |
  |                   Check account lock (locked_until)            |
  |                   VerifyPassword(pw, user.PasswordHash)        |
  |                   If invalid: increment failed count, return error
  |                   Check email verified                         |
  |                   Reset failed login counter                   |
  |                                |                               |
  |                   Compute fingerprint (SHA256)                 |
  |                   Check MFA status via MFAService              |
  |                                |                               |
  |         [No MFA]               |           [MFA enabled]       |
  |                                |                               |
  |   Find/create device           |   Issue 2fa_challenge token   |
  |   IssueTokenPair (RS256 JWT)   |   (5 min TTL, limited scope) |
  |   Store refresh token (hashed) |                               |
  |   Set HttpOnly cookie          |                               |
  |                                |                               |
  |  200 {access_token, ...}       |  200 {requires_2fa: true,     |
  |  Set-Cookie: refresh_token     |       challenge_token,        |
  |<-------------------------------|       available_methods}      |
  |                                |<-------------------------------|
```

The "user not found" and "wrong password" paths both execute Argon2id computation
to prevent timing-based user enumeration. The same `ErrInvalidCredentials` error
is returned for both cases.

See: `internal/service/auth.go` Login()

### Login with 2FA

When the login response includes `requires_2fa: true`, the client must complete
a second factor before receiving real tokens.

```text
Client                           Vault42                         Cache
  |                                |                               |
  |  POST /auth/2fa/totp/verify    |                               |
  |  Authorization: Bearer <2fa_challenge_token>                   |
  |  {code: "123456"}             |                               |
  |------------------------------->|                               |
  |                                |                               |
  |                   AuthChallenge middleware:                     |
  |                     accepts "Bearer" and "2fa_challenge" types |
  |                   Fingerprint middleware:                       |
  |                     verifies device fingerprint                |
  |                                |                               |
  |                   Decrypt TOTP secret (AES-256-GCM)            |
  |                   ValidateTOTPCode (RFC 6238, +/- 1 step)      |
  |                                |                               |
  |                                |  Check totp_used:<user>:<step>|
  |                                |------------------------------>|
  |                                |  false (not replayed)         |
  |                                |<------------------------------|
  |                                |                               |
  |                                |  Set totp_used key (90s TTL)  |
  |                                |------------------------------>|
  |                                |                               |
  |                   claims.TokenType == "2fa_challenge"          |
  |                   -> CompleteMFALogin()                        |
  |                     -> IssueTokenPair (full Bearer tokens)     |
  |                     -> Store refresh token (hashed)            |
  |                                |                               |
  |  200 {access_token, ...}       |                               |
  |  Set-Cookie: refresh_token     |                               |
  |<-------------------------------|                               |
```

WebAuthn follows the same pattern: VerifyBegin returns a challenge, VerifyFinish
completes it. Both check `claims.TokenType == "2fa_challenge"` to decide whether
to issue full tokens.

See: `internal/handler/totp.go` Verify(), `internal/handler/webauthn.go` VerifyFinish()

### Token Refresh Flow

```text
Client                           Vault42                         PostgreSQL
  |                                |                               |
  |  POST /auth/refresh            |                               |
  |  Cookie: refresh_token=<token> |                               |
  |------------------------------->|                               |
  |                                |                               |
  |                   refreshRL rate limit check                   |
  |                   SHA256 hash the cookie value                 |
  |                                |                               |
  |                                |  GetByTokenHash(hash)         |
  |                                |------------------------------>|
  |                                |  stored refresh token         |
  |                                |<------------------------------|
  |                                |                               |
  |                   Check revoked -> reject                      |
  |                                |                               |
  |                   Check used (replay detection):               |
  |                     If used -> RevokeFamily(familyID)          |
  |                     Log replay detected (risk score 90)        |
  |                     Return "replay_detected"                   |
  |                                |                               |
  |                   Check expired -> reject                      |
  |                                |                               |
  |                   Verify fingerprint (recompute + compare)     |
  |                     If mismatch -> RevokeFamily + reject       |
  |                                |                               |
  |                   Atomically MarkUsed (CAS operation):         |
  |                     If CAS fails -> concurrent replay          |
  |                     -> RevokeFamily + reject                   |
  |                                |                               |
  |                   IssueTokenPair (same familyID)               |
  |                   Store new refresh token (hashed)             |
  |                                |                               |
  |  200 {access_token, ...}       |                               |
  |  Set-Cookie: refresh_token     |                               |
  |<-------------------------------|                               |
```

**Replay detection**: Every refresh token is single-use. When a token is
presented that has already been used, the entire token family is revoked. This
handles the scenario where an attacker steals a refresh token -- the legitimate
user's next refresh attempt detects the replay and nukes all tokens in that
family.

**CAS (Compare-And-Swap)**: `MarkUsed` returns a boolean indicating whether the
update succeeded. If two concurrent requests attempt to use the same token, only
one succeeds; the other triggers family revocation.

See: `internal/service/auth.go` Refresh()

### Logout Flow

```text
Client                           Vault42                         PostgreSQL
  |                                |                               |
  |  POST /auth/logout             |                               |
  |  Authorization: Bearer <token> |                               |
  |------------------------------->|                               |
  |                                |                               |
  |                   Auth + Fingerprint middleware                 |
  |                                |                               |
  |                                |  RevokeAllForUser(userID)     |
  |                                |------------------------------>|
  |                                |  OK                           |
  |                                |<------------------------------|
  |                                |                               |
  |                   Clear refresh_token cookie (MaxAge: -1)      |
  |                   Log audit event (token_revoke/logout)        |
  |                                |                               |
  |  200 {status: "logged_out"}    |                               |
  |  Set-Cookie: refresh_token=""  |                               |
  |<-------------------------------|                               |
```

See: `internal/handler/auth.go` Logout(), `internal/service/auth.go` Logout()

### Password Reset Flow

```text
Client                           Vault42                  Cache           Email
  |                                |                      |               |
  |  POST /auth/password/reset     |                      |               |
  |  {email: "user@example.com"}   |                      |               |
  |------------------------------->|                      |               |
  |                                |                      |               |
  |                   passwordResetRL rate limit check     |               |
  |                                |                      |               |
  |                   GetByEmail(email)                    |               |
  |                   If not found:                        |               |
  |                     VerifyPassword("dummy", DummyHash) |  <-- timing burn
  |                     Return same success response       |               |
  |                                |                      |               |
  |                   Generate random 64-char hex token    |               |
  |                                |                      |               |
  |                                | Set reset:<hash>=uid |               |
  |                                | (1 hour TTL)         |               |
  |                                |--------------------->|               |
  |                                |                      |               |
  |                                | Send reset email     |               |
  |                                |------------------------------------->|
  |                                |                      |               |
  |  200 "If that email exists..." |                      |               |
  |<-------------------------------|                      |               |
  |                                |                      |               |
  ~~ user clicks link ~~           |                      |               |
  |                                |                      |               |
  |  POST /auth/password/reset/confirm                    |               |
  |  {token: "abc...", password: "new-password"}           |               |
  |------------------------------->|                      |               |
  |                                |                      |               |
  |                   Validate password length >= 15       |               |
  |                                |                      |               |
  |                                | GetAndDelete         |               |
  |                                | reset:<hash>         |               |
  |                                |--------------------->|               |
  |                                | userID               |               |
  |                                |<---------------------|               |
  |                                |                      |               |
  |                   Check password history (last 5)      |               |
  |                   Hash new password (Argon2id)         |               |
  |                   Update password in DB                |               |
  |                   Record in password history           |               |
  |                   Revoke all refresh tokens            |               |
  |                                |                      |               |
  |  200 {status: "password_reset_complete"}               |               |
  |<-------------------------------|                      |               |
```

The reset token is stored as a SHA256 hash in the cache. `GetAndDelete` is
atomic to prevent TOCTOU races on token reuse. The password reset **always**
returns the same response regardless of whether the email exists, preventing
user enumeration.

See: `internal/handler/password.go`

### OAuth2 Flow

```text
Client                    Vault42                   Provider (Google/GitHub)
  |                         |                              |
  |  GET /auth/oauth2/authorize?provider=google            |
  |------------------------>|                              |
  |                         |                              |
  |         Generate PKCE verifier + S256 challenge        |
  |         Generate state: provider.nonce.expiry           |
  |         HMAC-sign the state payload                    |
  |         Store verifier in cache (10min TTL)            |
  |                         |                              |
  |  302 -> provider auth URL (with state, PKCE challenge) |
  |<------------------------|                              |
  |                         |                              |
  |  (user authenticates with provider)                    |
  |-------------------------------------------------------->
  |                         |                              |
  |  GET /auth/oauth2/callback/google?code=xxx&state=yyy   |
  |------------------------>|                              |
  |                         |                              |
  |         Verify HMAC signature on state                 |
  |         Check state expiry (10 min)                    |
  |         Atomic GetAndDelete of PKCE verifier from cache|
  |                         |                              |
  |                         |  Exchange code + verifier    |
  |                         |----------------------------->|
  |                         |  {access_token, id_token}    |
  |                         |<-----------------------------|
  |                         |                              |
  |                         |  Fetch user info             |
  |                         |----------------------------->|
  |                         |  {email, name, avatar, ...}  |
  |                         |<-----------------------------|
  |                         |                              |
  |         Look up social account by provider + provider_user_id
  |         OR match by email (only if BOTH sides are email-verified)
  |         OR create new user account                     |
  |         Link social account to user                    |
  |                         |                              |
  |         Check if user has MFA enabled                  |
  |         [No MFA]:  issue full tokens                   |
  |         [Has MFA]: issue 2fa_challenge token           |
  |                         |                              |
  |  302 -> origin/oauth/callback#access_token=xxx         |
  |  Set-Cookie: refresh_token                             |
  |<------------------------|                              |
```

**PKCE S256 enforcement**: Every OAuth2 flow generates a PKCE code verifier and
sends only the S256 challenge to the provider. The verifier is stored in the
cache and used during the code exchange. No OAuth2 flow works without PKCE.

**Account linking security**: When linking an OAuth account to an existing user
by email, BOTH the OAuth provider's email AND the existing account's email must
be verified. This prevents account takeover via unverified OAuth emails.

See: `internal/handler/oauth.go`

## Token Architecture

### Access Tokens

- **Format**: RS256-signed JWT (JSON Web Token)
- **TTL**: 15 minutes (configurable via `VAULT_ACCESS_TOKEN_TTL`)
- **Validation**: Stateless -- verified using the public key from JWKS
- **Claims**: issuer, audience, subject (user ID), roles, scopes, client_id,
  fingerprint hash, token_type ("Bearer"), jti (unique ID), exp, nbf, iat
- **Fingerprint binding**: SHA256(IP + User-Agent + Accept-Language + TLS fingerprint)
  is embedded in the token and verified on every authenticated request.
  The TLS fingerprint is read from the header specified by `VAULT_TLS_FINGERPRINT_HEADER`
  (set by the TLS-terminating proxy, e.g. JA4). Empty when not configured (backward compatible).
- **Algorithm whitelist**: Only RS256 is accepted. The parser explicitly rejects
  `none`, `HS256`, and all other algorithms at parse time.
- **Header restrictions**: `jku`, `x5u`, `x5c`, and `jwk` headers are rejected.
  Keys are loaded only from the in-memory key map, never from token headers.
- **Max size**: 8KB enforced before parsing

### Refresh Tokens

- **Format**: Opaque random token (32 bytes, hex-encoded)
- **TTL**: 7 days (production), 24 hours (dev), 30 days (remember-me)
- **Storage**: SHA256 hash stored in PostgreSQL `refresh_tokens` table. The raw
  token is never stored server-side.
- **Delivery**: HttpOnly, Secure, SameSite=Strict cookie, Path=/auth
- **Single-use**: Each refresh token can be used exactly once. After use, a new
  token is issued in the same family.
- **Family tracking**: Each token pair belongs to a family (UUID). Replay
  detection works at the family level -- if a used token is presented again,
  all tokens in that family are revoked.
- **Fingerprint binding**: The refresh token record stores the device
  fingerprint hash. On refresh, the current fingerprint is recomputed and
  compared. Mismatch triggers family revocation.

### 2FA Challenge Tokens

- **Format**: RS256 JWT with `token_type: "2fa_challenge"`
- **TTL**: 5 minutes (hardcoded)
- **Purpose**: Issued after successful password verification when the user has
  MFA enabled. Grants access only to 2FA verify endpoints.
- **Scope**: The `AuthChallenge` middleware accepts both `"Bearer"` and
  `"2fa_challenge"` token types. Standard `Auth` middleware rejects challenge
  tokens.

### Client Credentials Tokens

- **Format**: RS256 JWT (same as access tokens)
- **Subject**: Client ID (not a user ID)
- **Roles/Scopes**: Determined by the client's registered role and requested
  scope intersection
- **Auth**: HTTP Basic or form-encoded client_id + client_secret

See: `internal/crypto/jwt.go`, `internal/service/token.go`

## Key Rotation (JWKS)

```text
/.well-known/jwks.json  <--  Serves the current public key set

File-based keys (SIGNING_KEY_FILE; default):
  Generate an RSA-2048 PKCS#8 PEM (`BEGIN PRIVATE KEY`) with
  scripts/generate-secrets.sh or
  `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.
  Point SIGNING_KEY_FILE at that path and restart. There is no live swap.

  The kid the process advertises is KIDFromPublicKey: the first 16 hex
  characters of SHA-256 over the PKIX DER of the public key, formatted
  xxxxxxxx-xxxxxxxx. It is not a UUID you choose.

  vault rotate-jwks is not this path. It writes PKCS#1
  (`BEGIN RSA PRIVATE KEY`), prints a random UUID that LoadSigningKeyPEM
  never reads, and a SIGNING_KEY_FILE pointed at that file fails at
  startup with a parse error. Convert first
  (`openssl pkcs8 -topk8 -nocrypt`) if you already have a PKCS#1 file,
  then ignore the printed UUID and read the kid from
  GET /.well-known/jwks.json after restart.

DB-backed rotation (VAULT_KEY_ROTATION_DB=true):
  POST /admin/keys/rotate, or the VAULT_KEY_ROTATION_INTERVAL scheduler.
  The previously active key is retired and stays in JWKS until
  VAULT_KEY_RETENTION_PERIOD. The CLI verb does not drive this path.
```

The JWKS endpoint sets `Cache-Control: public, max-age=300` (5 minutes). During
a DB-backed rotation, both the old and new keys are available, so tokens signed
with the old key remain valid until they expire naturally.

The `WellKnownHandler` holds no lock. Its key map is written once by
`NewWellKnownHandler` and never again: rotation reaches the handler through
`keyProvider`, not by mutating the map, and the `UpdateKeys` method that once wrote it had
no caller. The comment at `internal/handler/wellknown.go` says why the lock went -- a lock
over a field with no writer reads as evidence of concurrent mutation that does not happen.

### File-Based Keys (Default)

At startup, key loading depends on configuration:

- **`SIGNING_KEY_FILE` set:** RSA-2048 private key loaded from PKCS#8 PEM (`x509.ParsePKCS8PrivateKey` in `LoadSigningKeyPEM`). Shared across all pods for horizontal scaling. Tokens survive restarts. PKCS#1 (`BEGIN RSA PRIVATE KEY`), including the file `vault rotate-jwks` writes, is a startup parse failure. `kid` is `KIDFromPublicKey`: the first 16 hex characters of SHA-256 over the PKIX DER encoding of the public key, formatted `xxxxxxxx-xxxxxxxx`. Hashing the modulus alone is not what the process does.
- **`SIGNING_KEY_FILE` not set (fallback):** ephemeral RSA-2048 key pair generated in memory. Tokens invalidated on restart. Suitable for single-pod deployments only.

This mode is backward compatible and requires no additional configuration.

### DB-Backed Keys (`VAULT_KEY_ROTATION_DB=true`)

When enabled, signing keys are stored in PostgreSQL and encrypted with
AES-256-GCM (master key, `kid` as AAD). This mode supports true multi-pod key
rotation without shared filesystem access.

- All pods refresh their key material from the database every 60 seconds
  (configurable via `VAULT_KEY_REFRESH_INTERVAL`).
- On rotation, the previously active key is marked **retired**. Retired keys
  remain in the JWKS response until their retention period expires (default:
  1 hour via `VAULT_KEY_RETENTION_PERIOD`), so existing tokens validate
  seamlessly.
- Live key management (rotate, list, revoke) is performed via the admin
  gateway (`cmd/admin-gateway/`). `vault rotate-jwks` writes a PKCS#1
  key file and a discarded UUID; it does not rotate the live store and
  cannot be mounted as `SIGNING_KEY_FILE`.
- Revoked keys are removed from JWKS immediately. Expired retired keys are
  cleaned up automatically during the refresh cycle.

See: `internal/keystore/`, `internal/handler/wellknown.go`, `internal/service/token.go` UpdateSigningKey()

## Service Layer

The service layer (`internal/service/`) contains all business logic. Handlers
never access repositories directly for core auth operations -- they delegate to
services.

```text
Handler                    Service                    Repository
  |                          |                           |
  |  AuthHandler.Login()     |                           |
  |  - decode JSON           |                           |
  |  - extract IP, UA        |                           |
  |  - call service          |                           |
  |------------------------->|                           |
  |                          |  AuthService.Login()      |
  |                          |  - validate email         |
  |                          |  - lookup user            |
  |                          |-------------------------->|
  |                          |  - verify password        |
  |                          |  - check MFA status       |
  |                          |  - issue tokens           |
  |                          |  - store refresh token    |
  |                          |-------------------------->|
  |                          |  - log audit event        |
  |                          |<--------------------------|
  |  - set cookies           |                           |
  |  - write JSON response   |                           |
  |<-------------------------|                           |
```

**Responsibilities**:

- **Handlers**: HTTP concerns only -- decode request, extract headers, call
  service, set cookies, write response. Handlers import services and repositories
  but never contain business logic.
- **Services**: Business logic -- validation, password hashing, token issuance,
  MFA policy, HIBP checking, audit logging. Services import repositories and
  crypto but never touch HTTP.
- **Repositories**: Data access only -- SQL queries, connection management.
  Repositories import only the model package.

Some handlers (user profile, devices, well-known) access repositories directly
when the operation is a simple CRUD with no business logic.

Three services coordinate the auth domain:

| Service | Responsibility |
|---------|---------------|
| `AuthService` | Registration, login, refresh, logout, MFA login completion |
| `TokenService` | JWT signing, challenge token issuance, key rotation |
| `MFAService` | MFA policy: which methods are enabled, whether MFA is required |

See: `internal/service/auth.go`, `internal/service/token.go`, `internal/service/mfa.go`

## Data Layer

### Repository Interface Pattern

All persistence is defined as Go interfaces in `internal/repository/repository.go`.
There are 14 repository interfaces:

| Interface | Domain |
|-----------|--------|
| `UserRepository` | Users (CRUD, password, lock, email verification) |
| `RefreshTokenRepository` | Refresh tokens (create, lookup by hash, mark used, revoke family) |
| `DeviceRepository` | Device fingerprints (create, lookup, trust, rename) |
| `ClientRepository` | Service clients for client_credentials grant |
| `TOTPRepository` | TOTP secrets (encrypted, with verified flag) |
| `WebAuthnRepository` | WebAuthn/FIDO2 credentials |
| `BackupCodeRepository` | One-time backup codes |
| `PasswordHistoryRepository` | Password reuse prevention (last 5 hashes) |
| `SocialAccountRepository` | OAuth2 social account links |
| `AuditRepository` | Append-only audit log entries |
| `RateLimitRepository` | Persistent rate limit state |
| `AdminConfigRepository` | Key-value admin configuration |
| `IdentityRepository` | Encrypted PII identity profiles (upsert, get, delete) |
| `BlobRepository` | Encrypted blob storage with per-user quotas |

The concrete PostgreSQL implementations live in `internal/repository/postgres/`
and use `pgx/v5` for connection pooling and query execution.

### Database Roles (Least Privilege)

Three PostgreSQL roles enforce separation of concerns:

```text
vault_mig (migration role)
  - Used ONLY at startup for schema migrations
  - Has DDL privileges (CREATE TABLE, ALTER, etc.)
  - Connection is opened, migrations run, connection CLOSED
  - Never used again during the server's lifetime

vault_app (application role)
  - Used for all runtime database operations
  - auth schema: SELECT, INSERT, UPDATE (no DELETE, no TRUNCATE, no DDL)
  - audit schema: INSERT, SELECT only (no UPDATE, no DELETE)
  - Cannot modify the schema, cannot delete audit records
  - The only holder of EXECUTE on audit.cleanup_old_entries(), because the
    retention sweeper runs in-process under this role

vault_admin (admin gateway role)
  - Used only by cmd/admin-gateway; see docs/admin-gateway.md for the table
  - No EXECUTE on the audit purge function
```

### Append-Only Audit Log

The audit log (`internal/audit/audit.go`) records security-relevant events:
login success/failure, registration, token refresh/revoke, password changes,
2FA events, OAuth2 flows, admin actions, fingerprint anomalies, and rate limit
hits.

Each entry includes: event type, user ID, client ID, IP, user agent, fingerprint
hash, device ID, scrubbed metadata, risk score, and timestamp.

**Security properties**:

- Append-only at the database level (vault_app has INSERT + SELECT only, and a
  trigger refuses DELETE and UPDATE regardless)
- The one function that can remove a row, `audit.cleanup_old_entries()`, is
  SECURITY DEFINER because it has to disable that trigger. EXECUTE is revoked
  from `PUBLIC` and granted only to `vault_app`, it runs with an explicit
  `search_path`, and it refuses any horizon shorter than a day -- so the purge
  cannot be turned into a wipe by a caller that reaches the database directly
- Sensitive metadata keys (password, token, secret, etc.) are automatically
  scrubbed before storage
- Optional batching for high-throughput deployments (configurable flush interval)
- Best-effort -- audit failures never block auth operations

**Retention** (`internal/audit/retention.go`): entries carry personal data (user ID,
IP, user agent, fingerprint hash), so they are bounded by time rather than by the
account lifecycle. Audit records are deliberately exempt from the erasure cascade --
Art. 17(3)(b)/(e) permits keeping security records past an erasure request -- which is
exactly why they need a purge of their own. A sweeper deletes entries older than
`VAULT_AUDIT_RETENTION_DAYS` at startup and every 6 hours. It is disabled by default:
silently deleting security logs is not a safe default, so the horizon is an explicit
operator choice. Because the log is append-only, this is the only sanctioned removal
path. `vault cleanup-audit` is retired and writes nothing.

**Recovery-escrow retention** (`internal/service/recovery_retention.go`): the
account-recovery escrow (`auth.account_recovery`) has the same shape as the audit log --
append-only at the database layer, exempt from the erasure cascade by design, and holding
personal data (an encrypted copy of the erased user's email, creation date, roles and
display name) -- so it is bounded the same way. A sweeper deletes records older than
`VAULT_RECOVERY_RETENTION_DAYS` at startup and every 6 hours, disabled by default, and
`vault cleanup-recovery` runs the same purge on demand. Both go through
`auth.cleanup_old_recovery()` (migration 011), a SECURITY DEFINER function that briefly
disables the append-only trigger: neither application role holds DELETE on the table, so
this is the only path that can remove an escrow record.

### Cache Interface

The cache (`internal/cache/cache.go`) is a pluggable key-value store used for:

- Rate limiting counters (fixed window via `Increment`)
- Email verification tokens (`verify:<hash>` -> user ID, 24h TTL)
- Password reset tokens (`reset:<hash>` -> user ID, 1h TTL)
- TOTP replay prevention (`totp_used:<user>:<step>` -> "1", 90s TTL)
- OAuth2 state/PKCE verifiers (`oauth_state:<nonce>` -> verifier, 10min TTL)
- WebAuthn session data (`webauthn_reg:<user>`, `webauthn_auth:<user>`, 5min TTL)
- Password confirmation windows (`confirm:<user>` -> "1", 5min TTL)

Three backends are available, selected by `CACHE_BACKEND` environment variable:

| Backend | Config Value | Use Case |
|---------|-------------|----------|
| Redis | `redis` | Production (default) |
| In-Memory | `memory` | Dev, embedded, testing |
| PostgreSQL | `postgres` | Fallback when Redis is unavailable |

The factory (`internal/cache/factory.go`) creates the appropriate backend. On
initialization failure, the server falls back to in-memory cache with a log
warning.

See: `internal/cache/`, `internal/repository/repository.go`

### Email Templates

Email templates (verification, password reset, etc.) are embedded into the binary
via `go:embed` from `internal/email/templates/*.html`. This ensures templates are
always available without external file dependencies.

For customization, the `VAULT_EMAIL_TEMPLATES_DIR` environment variable can point
to a filesystem directory containing override templates. When set, templates are
loaded from the filesystem first; if a template is missing there, the embedded
default is used as a fallback. This allows operators to customize email branding
without rebuilding the binary.

See: `internal/email/templates.go`

## Configuration & Profiles

### Profile System

Four deployment profiles control default configuration values:

| Setting | Production | Dev | Embedded | Honeypot |
|---------|-----------|-----|----------|----------|
| Listen address | :8443 | :8443 | :8443 | :8443 |
| TLS enabled | true | true | true | true |
| Cache backend | redis | (inherited) | memory | redis |
| DB max conns | 25 | 25 | 5 | 25 |
| Auto-migrate | false | true | true | true |
| CORS allow-all | false | true | false | false |
| Serve frontend | false | false | false | true |
| Access token TTL | 15min | 15min | 15min | 15min |
| Refresh token TTL | 7 days | 24 hours | 24 hours | 7 days |
| Remember-me TTL | 30 days | 30 days | 30 days | 30 days |
| Rate limiting | true | true | true | true |
| Shutdown timeout | 15s | 5s | 5s | 15s |

**Dev extends production** -- it starts from the production baseline and applies
minimal overrides (CORS allow-all, shorter refresh TTL, faster shutdown,
auto-migration). TLS, rate limits, listen address, and cache backend are all
inherited from production unless explicitly overridden via environment
<!-- loglevel-gate:begin -->
variables. There is no log-level control: `LOG_LEVEL` is read and ignored.
<!-- loglevel-gate:end -->

**Embedded** is tuned for resource-constrained environments (e.g., Raspberry Pi 5)
with in-memory cache, 5 DB connections, and auto-migration. Target memory
footprint: ~60-80MB.

### Secret Loading

All secrets use the `_FILE` suffix convention. For example, `MASTER_KEY_FILE`
contains a path to a file containing the master key. The `LoadSecret()` function
in `internal/config/secrets.go`:

1. Reads `<ENV_KEY>_FILE` to get the file path
2. Reads the file contents
3. Trims whitespace and returns the value
4. If `VAULT_SECRET_FILE_CONSUME=true` (exact string), zeros and removes the file. The default leaves the file intact.

`LoadSecret` is the vault path. `BRIDGE_ADMIN_TOKEN_FILE` always overwrites the file with zeros and ignores the flag. The admin gateway's own `loadSecret` never consumes; its `MASTER_KEY_FILE` still goes through `LoadSecretBinary`, so consume applies there.

Secrets are never passed as environment variables directly. This integrates with
Kubernetes secrets mounted as files.

See: `internal/config/config.go`, `internal/config/profiles.go`, `internal/config/secrets.go`

### Metrics

When `VAULT_METRICS_ENABLED=true`, the `/metrics` endpoint serves Prometheus
text exposition format. The collector (`internal/metrics/`) aggregates argon2
semaphore utilization, login success/failure counters, and token issuance
counters. No external dependencies -- the text format is hand-rolled.

The argon2 semaphore gauge (`vault_argon2_semaphore_in_use` /
`vault_argon2_semaphore_capacity`) is designed for HPA scaling: when utilization
approaches capacity, Kubernetes can scale out the pod count.

## Frontend & i18n Architecture

### Vue Frontend (`web/`)

The Vue 3 + Vite + Tailwind frontend provides the user-facing dashboard. It uses
the `@vault42/vue` package (`packages/vue/`) for all API interaction and i18n.

**Key files:**

- `web/src/App.vue` -- main layout, nav links (computed via `t()`), LanguageSwitcher
- `web/src/views/*.vue` -- 15 view components, all strings translated via `t()`
- `web/src/components/LanguageSwitcher.vue` -- searchable locale dropdown
- `web/src/composables/usePasswordStrength.ts` -- returns `labelKey` for i18n
- `web/src/__tests__/` -- Vitest + Vue Test Utils tests

### i18n System (`packages/vue/src/i18n/`)

Custom i18n plugin with no external dependencies:

- **38 locales** with flat key structure (`"nav.dashboard": "Dashboard"`)
- **Locale detection**: browser language → `localStorage('vault42-locale')` → `'en'`
- **Reactive**: `t()` reads from a `computed` ref on `locale.value`, ensuring Vue
  re-renders all translated text when the locale changes
- **Interpolation**: `t('key', { name: value })` replaces `{name}` placeholders
- **Utilities**: `formatDate(date, options?)` and `formatNumber(n, options?)` use
  `Intl.DateTimeFormat` / `Intl.NumberFormat` with the current locale
- **Plugin**: `createI18nPlugin({ locale, fallbackLocale, messages })` provides
  `useT()` composable to all components via Vue's `provide`/`inject`

### LanguageSwitcher

Custom searchable dropdown (not a native `<select>`):

- Trigger button shows current locale's native name
- Opens upward as a popover with search input
- Filters by locale code and native name
- Click-outside-to-close via `mousedown` listener
- Persists selection to `localStorage('vault42-locale')`

### Build Pipeline

```text
packages/vue/  →  pnpm build (tsup)  →  dist/vault42-vue.js
web/           →  pnpm build (Vite)  →  dist/ (index.html + assets)
scripts/build-all.sh  →  copies web/dist → internal/frontend/dist (go:embed)
                      →  go build (embeds frontend into binary)
                      →  docker build
```

## Deployment Architecture

### Single Helm Chart

The Helm chart at `charts/vault/` serves all environments via value overlays:

```text
charts/vault/
  values.yaml              Production defaults
  values-dev.yaml          Dev overlay (single replica, local images, in-cluster services)
  templates/
    deployment.yaml        Vault42 backend (with optional TLS volume mount)
    service.yaml           ClusterIP service
    ingress.yaml           Split routing: API paths -> vault42, / -> frontend
    configmap.yaml         Environment variables
    postgres.yaml          Optional in-cluster PostgreSQL (dev only, off by default)
    redis.yaml             Optional in-cluster Redis (dev only)
    frontend.yaml          Optional Vue frontend deployment
    mailpit.yaml           Optional dev email server
    init-db.yaml           Database role/schema initialization job
    networkpolicy.yaml     Network segmentation
    pdb.yaml               Pod disruption budget
    hpa.yaml               Horizontal pod autoscaler
    serviceaccount.yaml    Service account with RBAC
```

### Local Development

A single command deploys the full stack locally:

```text
scripts/deploy-dev.sh
  1. Generate mkcert TLS certificates for vault.localhost
  2. Build Docker images: vault42:dev, vault42-frontend:dev
  3. Create vault42-dev namespace
  4. Create TLS secret + vault42 secrets
  5. helm upgrade --install vault42 charts/vault -n vault42-dev -f charts/vault/values-dev.yaml
```

Access at `https://vault.localhost` via nginx ingress controller. Requires:
`mkcert`, `docker`, `kubectl`, `helm`, and an nginx-ingress controller.

### Container Image

Multi-stage Dockerfile:

- **Builder**: `golang:1.24-alpine` -- compiles static binary with `CGO_ENABLED=0`
- **Runtime**: `gcr.io/distroless/static-debian12:nonroot` -- no shell, no
  package manager, non-root user, read-only filesystem, all capabilities dropped

ARM64 cross-compilation uses Go's native `GOARCH` instead of QEMU emulation,
avoiding ~10x build overhead for ARM targets.

See: `charts/vault/`, `scripts/deploy-dev.sh`, `Dockerfile`
