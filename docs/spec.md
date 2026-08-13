# Vault42 -- Specification

**Version 1.0.0.**

Section 0 is the normative API stability contract: what a caller may rely on across a 1.x release,
what costs a major version, and what is excluded from the promise entirely. It uses RFC 2119
keywords and they mean what RFC 2119 says they mean. Sections 1 onward are descriptive and cite the
source that implements what they describe.

**This document is checked against the code.** `tests/spec/route_drift_test.go` parses the route
registrations in `internal/server/server.go` and `internal/adminapi/router.go` with `go/ast` and
fails the build whenever the inventory in section 16 and the source disagree in either direction --
a route that exists and is not written down, or a route written down that nothing serves. The
previous edition of this file carried an "as of" date that three commits falsified without touching
it, leaving a document nobody could tell the current parts of from the stale ones. The endpoint
inventory can no longer rot silently. The prose can, so it is dated by the release rather than by
hand and is re-verified against source at each tag.

**What this file is authoritative for:** the stability contract and the endpoint inventory.
[`api.md`](api.md) is authoritative for request and response bodies, [`admin-gateway.md`](admin-gateway.md)
for the admin gateway's deployment and RBAC model, and [`config.md`](config.md) for environment
variables. `spec-draft.md` is a superseded planning document and is authoritative for nothing.

---

## 0. API Stability Contract

This section is normative. The rest of the document describes the system; this section states what
callers may build against.

### 0.1 Normative language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and
OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174, and only where they appear in
all capitals.

Where a descriptive section and this one disagree, this one wins and the description is a defect to
be reported.

### 0.2 The API version is the major version

vault42 serves its endpoints at the root. `POST /auth/login` is the path; there is no
`/v1/auth/login` and there will not be one.

That is a decision, not an oversight:

- BeOn3 has been live against the root paths since the 2026-08-10 GA. A prefix breaks every
  deployed caller and buys a string.
- Root-mounted authentication endpoints are the OAuth2 and OIDC convention, and RFC 8615 fixes
  `/.well-known/*` at the root regardless -- a prefix would split one surface across two namespaces.
- A path prefix only earns its keep when two incompatible versions are served at once. That is a
  routing decision and can be taken on the day it is needed, without moving anything that exists.

Therefore:

- The **major component of the release version is the API version**. Every 1.x.y release speaks
  API v1.
- The root paths **are** v1, permanently. An implementation MUST NOT relocate an existing route to
  a version-prefixed path within a major version.
- Should a second, incompatible shape ever be required, it MUST be mounted under its own prefix
  (`/v2/...`) alongside the root paths, and the root paths MUST continue to answer v1 for the
  remainder of the v1 support window.
- The `/admin/` surface served by the admin gateway carries the same version on the same terms.

### 0.3 Changes that are compatible

The following MAY appear in any minor or patch release, and clients MUST tolerate them:

- a new endpoint;
- a new field in a response body, or a new response header;
- a new **optional** field in a request body;
- a new member of an open enumeration -- `mfa_methods`, `oauth_providers`, token `scopes`, user
  `roles`, audit `event_type`, RBAC permission names;
- a new audit event type, a new email template, a new environment variable;
- a new error code on a status class an endpoint already documents;
- widening a validation rule so that input previously rejected is accepted.

### 0.4 Changes that require a major version

The following are breaking and MUST NOT appear in a minor or patch release:

- removing or renaming a route, or changing which method it answers on;
- removing or renaming a response field, or changing its JSON type (including `null` where an
  array was promised);
- removing or renaming an error code;
- changing the HTTP status code an outcome produces;
- making an optional request field required;
- narrowing a validation rule so that input previously accepted is rejected;
- removing a member of an enumeration, or changing what an existing member means;
- removing an environment variable, or changing a default such that an operator who set nothing
  gets different behaviour;
- lowering the maximum request body size.

Tightening a rate limit is compatible: exhaustion is already an observable outcome with a
documented shape (`429`, `Retry-After`, `X-RateLimit-*`).

One exemption, in one direction only: a change REQUIRED to close a security vulnerability MAY break
compatibility in a minor or patch release. Such a change MUST appear in `CHANGELOG.md` under an
explicit breaking-change heading, with the reason.

### 0.5 Client obligations, and the asymmetry in the other direction

Clients MUST ignore response fields they do not recognise. A client that errors, warns or drops a
response because it carries an unknown key is not conformant, and every rule in section 0.3 is
written assuming no such client exists.

**The server does not reciprocate, and callers must plan for that.**
`internal/handler/response.go:22-26` decodes request bodies with `DisallowUnknownFields()`:

- an unrecognised key in a request body is a hard `400`, not a warning;
- therefore a client MUST NOT feature-probe by sending an optional field to see whether it is
  accepted. Against a deployment that predates the field the entire request fails, including the
  parts that deployment does understand;
- to discover what a deployment supports, a client MUST use `GET /auth/capabilities` (section 2.10),
  never a trial request.

The strictness is deliberate -- a mistyped field name silently ignored is a bug report waiting to
happen -- but it is only safe because section 0.4 forbids removing a request field within a major
version and forbids ever promoting an optional field to required. Both halves are load-bearing.

No endpoint reports the running version: `GET /healthz` omits it deliberately, so as not to hand an
attacker a version to match against a CVE (`internal/handler/health.go:6`). `GET /auth/capabilities`
is therefore the only in-band discovery channel, and anything else a client needs to know about a
deployment comes from the operator out of band. That trade of convenience for attack surface is also
why section 0.3 keeps additions additive: a client has to work against an older deployment without
being able to ask it what it is.

The admin gateway is looser: `internal/adminapi` decodes without `DisallowUnknownFields()`, so
unknown request keys are ignored there. Clients MUST NOT rely on either behaviour beyond what is
written here. Tightening the gateway to match is a candidate for 2.0.0.

### 0.6 Surfaces outside this contract

These ship in 1.0.0 and are explicitly **not** covered. They MAY change or disappear in any
release, including a patch.

| Surface | Why it is excluded |
|---------|--------------------|
| `risk_score` on `GET /admin/audit` | An opaque severity tag, not a measurement. Section 0.6.1. |
| `VAULT_DPOP_ENABLED` and everything it gates | Experimental and unsupported. Section 0.6.2. |
| Admin gateway HTML pages (`GET /admin/`, `/admin/login`, `/admin/ui/*`, `/admin/static/*`) | A user interface, not an API. |
| The `GET /metrics` exposition body | The endpoint, its gate and its content type are stable; the metric names, labels and cardinality track the code. |
| `GET /admin/metrics` | Mounted and permission-gated with nothing behind it; answers `501 not_implemented`. Section 21.10. |
| Log output and its format | Diagnostics. |
| Error **messages** | Error **codes** are in the contract. Human-readable prose is not. |
| Anything this document or `api.md` labels experimental | Said plainly at the point of use. |

#### 0.6.1 `risk_score`

`risk_score` is public on `GET /admin/audit`. It is a **hardcoded per-event-type severity tag**,
not a computed or adaptive score (`internal/audit/audit.go` call sites pass a constant). Two
consequences, both normative:

- values are **not comparable across event types**. A 70 on one event and a 70 on another mean only
  that the catalog assigns both a 70;
- values MAY change for any event type, and new values MAY appear, without a major bump.

Clients MUST NOT threshold, sum, average, sort or alert on it. Treat it as an opaque label. When
adaptive scoring lands the range and meaning will change, and that will not be a breaking change.
`GET /admin/audit` deliberately does not expose `fingerprint_hash`, which correlates events across
accounts; `device_id` identifies the same device without being a cross-account correlator.

#### 0.6.2 DPoP

`VAULT_DPOP_ENABLED` gates an RFC 9449 proof validator (`internal/crypto/dpop.go`,
`internal/middleware/dpop.go`) that is complete and correct. **Nothing in vault42 issues a
DPoP-bound token.** The `cnf.jkt` confirmation claim is declared in `internal/crypto/jwt.go` and
never populated, so a presented proof is validated against nothing and the flag buys no
sender-constraint in either position. It is a dark launch, not a feature.

At 1.0.0, therefore:

- the discovery document MUST NOT advertise DPoP support, and does not
  (`internal/handler/wellknown.go`);
- the `DPoP` authentication scheme on the `Authorization` header MUST be rejected while no token is
  sender-constrained, and it is, unconditionally. `internal/middleware/auth.go` accepts only
  `Bearer` unless `WithDPoPScheme(true)` is passed, and `internal/server/server.go:240-248` never
  passes it, flag or no flag. RFC 9449 section 7.1 reserves that scheme for sender-constrained
  tokens, and silently degrading it to `Bearer` is the exact confusion the separate scheme exists
  to prevent. A caller that sends `Authorization: DPoP <token>` gets `401 invalid_authorization` on
  every deployment, including one with the flag on;
- **the flag makes no DPoP proof mandatory anywhere.** `internal/middleware/dpop.go:31-40` passes a
  request carrying no `DPoP` header straight through, because it demands a proof only from a token
  whose `cnf.jkt` is set, and nothing sets one. A proof that *is* presented is validated in full
  (`typ`, `alg`, `jwk`, `htm`, `htu`, `iat`, single-use `jti`, `ath`) and then compared against no
  thumbprint, so it constrains nothing and can be dropped at will. Any statement that the flag adds
  a required proof to `POST /kms/unwrap` or `POST /mint` is a defect: both accept a bare `Bearer`
  request with the flag on;
- operators SHOULD leave the flag off.

DPoP issuance -- a proof-carrying `POST /auth/login` that binds `cnf.jkt` into the token, plus the
KMS client integration -- has its own request and token surface and belongs to a later release.
Nothing about the flag's present behaviour is covered by sections 0.3 or 0.4.

### 0.7 Deprecation

Within a major version, a route or field to be withdrawn MUST first be marked deprecated in this
document and in `api.md`, in a release that still supports it, and MUST keep working until the next
major version. There is no shorter window and no silent removal.

There is no `Deprecation` or `Sunset` response header today. Adding one would be additive under
section 0.3.

### 0.8 Scope and non-goals

vault42 authenticates end users and service clients, issues and rotates the tokens other services
verify, and holds a bounded amount of encrypted per-user data (identity profile, blobs) so that PII
need not live in those services.

The following are **not** goals at 1.0.0. Each is stated so that an integrator does not plan around
a capability that is absent:

- **Not an OpenID Connect provider.** The discovery document publishes only what is true of this
  server: `issuer`, `jwks_uri`, and the access-token signing algorithm. There is no
  authorization-code token endpoint, no ID token is issued to a relying party, `GET /user/profile`
  is not a UserInfo response, and `POST /auth/register` is end-user signup rather than RFC 7591
  dynamic client registration. Section 20.
- **Not an OAuth2 authorization server.** vault42 is an OAuth2 *client* of Google, GitHub, Facebook
  and any generic OIDC issuer (section 2.11). Its own `POST /client/token` is a client-credentials
  grant that does not read `grant_type` and reports `invalid_client_credentials` where RFC 6749
  section 5.2 specifies `invalid_client`. Section 0.4 freezes both until 2.0.0.
- **Not multi-tenant.** Section 0.9.
- **No SIEM streaming.** The audit log is queryable (`GET /admin/audit`) and exportable
  (`export-audit`). There is no push, no syslog sink, and no webhook other than the honeypot
  alerter.
- **No server-rendered auth pages.** Per-app white-label branding applies to outbound email only
  (section 10.3). The embedded SPA is a convenience, not a themed server-side render.
- **No multi-region or multi-writer topology, no read replicas, no connection pooler, no row-level
  security.** One PostgreSQL primary.
- **No ACME.** Bring your own certificate; dev uses mkcert.
- **No mTLS on the main binary.** The admin gateway requires it; vault42 itself does not offer
  service-to-service mTLS.
- **No progressive login delay.** Rate limiting is fixed-window and fails closed on the
  authentication endpoints; account lockout is absolute rather than graduated. Adding backoff later
  changes latency and `Retry-After` values, both already in the contract, so it is compatible.

### 0.9 Tenancy: what `X-Vault-App` does and does not guarantee

`X-Vault-App` is a public request header carrying a tenant slug, and nine admin routes are
namespaced by `{app}`. A reader can reasonably infer multi-tenancy from that. **There is none.** A
tenant *concept* exists, with exactly one job.

**What `app` does.** It selects which branding row and which template overrides an outbound
authentication email is rendered with: app name, logo URL, primary colour, From display name, From
address, and per-template subject, HTML and text (section 10.3). It is honoured only when the
request reaches vault42 from a peer inside `TRUSTED_PROXIES`; a request arriving directly, or
through an untrusted peer, selects no app and gets the global branding
(`internal/middleware/appcontext.go`).

**What `app` does not do.** It is not a security boundary. vault42 guarantees none of the
following, and MUST NOT be deployed as though it did:

- **no data isolation** -- one `auth.users` table, one identity store, one blob store. There is no
  per-app partition and no per-app query filter anywhere in `internal/repository/`;
- **no per-app user namespace** -- an email address identifies exactly one account service-wide.
  Two apps cannot each hold their own `alice@example.com`;
- **no per-app signing keys, issuer or audience** -- one JWKS, one `iss`, one `aud`. A token minted
  while serving app A verifies identically for app B, and nothing in the token records which app
  was in context;
- **no per-app rate limits or lockout** -- every limiter keys on IP or user, never on app. Traffic
  against one app consumes the budget of all of them;
- **no per-app audit partitioning** -- one `audit.audit_log` with no `app` column. An admin holding
  `audit:read` sees every app's events;
- **no per-app configuration, role catalog or admin scoping** -- `GET /admin/config`, the
  application-role catalog and the whole RBAC model are service-wide. `email:write` is not
  app-scoped, so an admin who can write branding for one app can write it for every app;
- **no authorization meaning of any kind** -- the slug is shape-validated
  (`^[a-z0-9][a-z0-9_-]{0,63}$`) and never checked against a registry at request time. That is
  precisely why the trust boundary is the proxy and not the value.

Real multi-tenancy is post-1.0. It would change the token shape (an app claim), the schema (an app
axis on user identity), and the RBAC model, which makes it a major-version change under
section 0.4.

---

## 1. Overview

Vault42 is a production-grade authentication and authorization microservice built in Go. It is PostgreSQL-backed, deployed via Kubernetes (Helm chart), HTTPS-only, and single-origin. It implements stateless JWT access tokens (RS256), stateful refresh tokens with family-based replay detection, TOTP and WebAuthn/FIDO2 two-factor authentication, OAuth2 social login (Google, GitHub, Facebook) plus generic OpenID Connect issuers, device fingerprinting, an encrypted identity store for PII, encrypted blob storage with per-user quotas, self-service account erasure with recoverable escrow, GDPR data export, per-app white-label email branding, a KEK envelope-unwrap oracle, an opt-in subject-assertion signing oracle, an opt-in service-scoped encrypted JSON document store, and an append-only audit log.

The product is two binaries. `cmd/vault` serves the 62-route public API. `cmd/admin-gateway` serves the 41-route administrative API plus its HTML console, behind mTLS, RBAC and loopback-only enforcement, and is never exposed alongside the public API. Section 16 inventories both.

**Key properties:**
- Go 1.26, 3 direct runtime dependencies (+ test-only dependencies)
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
   - Response includes `requires_2fa: true`, `challenge_token`, and `available_methods` (section 4.4 on naming)
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

### 2.10 Capability Discovery

**Endpoint:** `GET /auth/capabilities` (public, no auth, no rate limit)

The only supported way for a client to learn what a deployment permits before it tries. Section 0.5
forbids feature-probing with trial requests, so this endpoint carries the load.

Returns three fields, all always present:

| Field | Type | Meaning |
|-------|------|---------|
| `registration_enabled` | bool | `POST /auth/register` creates accounts. When false the route is still mounted and answers `403 registration_disabled`, so a 404 never has to be interpreted. |
| `mfa_required` | bool | `VAULT_MFA_REQUIRED` -- every user must hold a second factor, with email OTP as the fallback for users who have configured none. |
| `oauth_providers` | array of string | Configured social and OIDC provider keys, e.g. `["google","github","okta"]`. Empty array when none are configured; never `null`. |

The response is built once at startup and is byte-identical for every caller: it depends on
configuration only, never on the requester. New capability fields are additive under section 0.3, so
clients MUST ignore keys they do not know.

**Source:** `internal/handler/capabilities.go`, `internal/server/server.go:320`

### 2.11 Generic OpenID Connect Providers

Beyond the three hardcoded social providers, any OIDC issuer can be registered at boot. This is
distinct from section 20: vault42 is an OIDC **client** here, not a provider.

**Configuration:** `VAULT_OIDC_PROVIDERS` is a comma-separated list of provider keys. For each key
`NAME`, vault42 reads `VAULT_OIDC_<NAME>_ISSUER`, `VAULT_OIDC_<NAME>_CLIENT_ID`,
`VAULT_OIDC_<NAME>_SCOPES` (optional; defaults to `openid email profile`) and the client secret via
the `_FILE` convention (`VAULT_OIDC_<NAME>_CLIENT_SECRET[_FILE]`). A provider missing an issuer or
client id is skipped rather than failing the boot.

**Discovery:** on first use the provider fetches `{issuer}/.well-known/openid-configuration`, caps
the response at 1 MiB, and caches the parsed document for the process lifetime. The authorization,
token, userinfo and JWKS endpoints all come from that document; nothing is hardcoded per issuer.

**Flow:** identical to section 2.3 -- HMAC-signed state, PKCE S256, single-use cache-backed verifier,
one-time exchange code. Registered providers appear in `oauth_providers` on `GET /auth/capabilities`
and are addressed by their key on `GET /auth/oauth2/callback/{provider}`.

**Source:** `internal/oauth2/oidc.go`, `internal/oauth2/oidc_idtoken.go`,
`internal/config/config.go` (`loadOIDCProviders`)

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
  - `cnf.jkt` -- declared for DPoP binding and **never populated**. No code path assigns it, so it is
    absent from every token vault42 issues. Section 0.6.2.
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
- **Session limit:** new family creation is blocked when a user has `VAULT_MAX_SESSIONS_PER_USER` (default 10) active families. Returns `429 too_many_sessions`.
  - **On a count-query error the behaviour is configurable and defaults to fail-open:** the login is allowed. `VAULT_STRICT_SESSION_LIMIT=true` (`internal/config/config.go:337`, `internal/service/auth.go:136-140`) makes it fail closed instead, rejecting the login and writing an audit event. Operators who treat the session cap as a control rather than a courtesy SHOULD set it; the default is the compatible one, because flipping it would turn a database blip into a service outage for an operator who set nothing.
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

Implemented via the `go-webauthn/webauthn` library.

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
- Returns: `totp_enabled`, `webauthn_enabled`, `backup_codes_remaining`, `mfa_methods`,
  `available_methods` (deprecated alias of `mfa_methods`), `mfa_required`

**Policy:**
- MFA is required at login if the user has any verified 2FA method configured
- `VAULT_MFA_REQUIRED` (default: `true`) forces all users to set up MFA
- Trusted devices can skip MFA (within trust window, checked via `RequiresMFA`)

**Naming: `mfa_` in JSON, `2fa` in paths.** The product supports more than two factors, so
`mfa_methods` is the canonical name for the configured-factor list, alongside `mfa_required` and
`mfa_enabled`. The URL paths keep `2fa` (`/auth/2fa/*`) because they are load-bearing for deployed
callers and renaming a route is a major-version change under section 0.4.

Before 1.0.0 the same list, from the same call site, went out under two names: `available_methods` on
`POST /auth/login` and `GET /auth/2fa/status`, `mfa_methods` on `GET /user/profile`. The 1.0.0
position:

- `GET /auth/2fa/status` emits **both** keys. `mfa_methods` is canonical; `available_methods` is a
  deprecated alias kept for clients written against it, and is scheduled for removal at 2.0.0 under
  section 0.7. Removing it inside 1.x would be breaking.
- `POST /auth/login` still emits `requires_2fa` and `available_methods` only. Adding `mfa_methods`
  there is additive under section 0.3 and is expected in a 1.x release.
- New clients MUST read `mfa_methods` where present and SHOULD fall back to `available_methods`.
  Both name the same list, and a client that accepts either is correct across the whole window.

`mfa_methods` is always an array. A user with no configured factor gets `[]`, never `null`; the
guarantee lives in `MFAStatus.MarshalJSON` rather than at a call site, so it holds for every path
that returns a status. On `POST /auth/login` the field carries `omitempty` and is therefore absent
rather than null on a non-MFA login. See section 16.1.

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
| `revoke-client` | Retired: refuses and points at `POST /admin/clients/{id}/revoke` |
| `rotate-client-secret` | Retired: refuses and points at `POST /admin/clients/{id}/rotate` |
| `lock-user` | Retired: refuses and points at `POST /admin/users/{id}/lock` |
| `unlock-user` | Retired: refuses and points at `POST /admin/users/{id}/unlock` |
| `revoke-all-sessions` | Revoke all refresh tokens system-wide |
| `rotate-admin-token` | Rotate the admin token itself |
| `rotate-jwks` | Rotate the JWKS signing key |
| `seed` | Declarative client + user creation from JSON file |
| `cleanup-audit` | Delete audit entries older than N days |
| `cleanup-recovery` | Delete account-recovery escrow records older than N days |
| `export-audit` | Export audit log entries as JSONL to stdout |

**Admin token lifecycle:**
1. Taken from `ADMIN_TOKEN_FILE` on first boot when that is set, as either the token or its Argon2id hash. Otherwise generated (256-bit random) and displayed once to stdout.
2. Stored as Argon2id hash in `auth.admin_config` table
3. Verified with `VerifyPassword` (Argon2id) on every CLI command
4. Replaced by `rotate-admin-token`, after which `ADMIN_TOKEN_FILE` no longer applies and later boots keep the rotated hash

**Source:** `internal/cli/cli.go`

### 6.4 KMS Envelope-Unwrap Oracle

**Endpoint:** `POST /kms/unwrap` (mounted only when `KMS_ROOT_KEY_FILE` is configured)

A KEK envelope-unwrap oracle: a caller presents a wrapped-key envelope and vault42 returns the unwrapped key while holding the Key-Encryption-Key itself and never releasing it. Backs the life42 vault re-root.

- **Key derivation:** per-`kid` KEKs are derived from a single KMS root secret (`KMS_ROOT_KEY_FILE`, >= 32 bytes) via HKDF-SHA256 with a versioned, domain-separated info label (`vault42/kms/kek/v1/<kid>`). This keeps the KMS keyspace cryptographically separate from the master key that encrypts TOTP/identity/blob at rest, and supports rotation without provisioning a new secret per kid.
- **Envelope format:** `nonce || AES-256-GCM ciphertext`, with `kid` bound as GCM AAD, base64 (std) on the wire. Reuses `internal/crypto` AEAD; no new crypto.
- **Authorization:** requires a client-credential access token carrying the `kms:unwrap` scope (`middleware.RequireScope`). `VAULT_DPOP_ENABLED=true` adds nothing here: the DPoP middleware demands a proof only from a token carrying `cnf.jkt`, nothing issues one, so a request with no `DPoP` header passes through and a proof that is presented is compared against no thumbprint. Replay resistance rests on the short access-token TTL, TLS, and the fail-closed per-IP limit. Section 0.6.2.
- **Oracle resistance:** every failure mode (empty kid, malformed envelope, bad base64, tampered ciphertext, wrong KEK) collapses to a single opaque `400 unwrap_failed` with a byte-identical body and audit outcome. No branch reveals which check failed.
- **Rate limiting:** per-IP, fail-closed (a cache/Redis outage rejects with 503 rather than degrading to a weaker per-pod limiter).
- **Audit:** every attempt is written synchronously (never dropped under buffer pressure), recording `kid` and outcome only. Key material is never logged, and KEKs plus the root secret are wiped after use.
- **Tooling:** `vault kms wrap` produces envelopes the oracle accepts.

**Source:** `internal/kms/kms.go`, `internal/handler/kms.go`, `internal/server/server.go`, `cmd/vault/kms.go`

### 6.5 Subject-Assertion Signing Oracle

**Endpoint:** `POST /mint` (mounted only when `VAULT_MINT_ENABLED=true`). `api.md` is authoritative
for the request and response bodies; this section is the threat model and the mount conditions.

A registered client names a subject and vault42 signs a token asserting it, with the same key that
signs every real one. **vault42 does not authenticate the subject, does not look it up, and does
not require it to be a vault42 user.** It exists because eleven legacy services hold foreign-key
copies of the legacy platform's own user ids, so the token subject has to stay that id rather than a
vault42-native one; the alternative was rewriting every one of those tables.

The blast radius is the whole trust model: a verifier cannot tell a minted token from a real one by
its signature, so whoever holds the mint credential can speak as any subject to every service that
trusts vault42's JWKS. The controls are:

- **Off unless configured.** The route is not registered when `VAULT_MINT_ENABLED` is unset,
  following the `POST /kms/unwrap` precedent rather than a soft in-handler 403. A vanilla
  deployment has no mint, and a misconfiguration is an authentication bypass rather than a weakened
  control.
- **Startup validation ahead of the dev short-circuit.** `VAULT_MINT_AUDIENCE` is required and MUST
  differ from `VAULT_ORIGIN`; `config.Validate()` checks both before it returns early for the dev
  profile, and `service.NewMintService` checks the audience again. A minted token carrying
  vault42's own audience would satisfy vault42's own audience validation, leaving `token_type` as
  the single control between a subject assertion and a session, and a dev deployment that teaches
  the wrong configuration gets copied.
- **Its own scope.** `mint:token`, never `kms:unwrap`: a client authorized to unwrap an envelope
  must not thereby be authorized to forge a subject.
- **A client-credential assertion in the handler.** `RequireScope` checks only the scopes array;
  the handler additionally requires a non-empty `client_id` claim, because user tokens cannot carry
  `mint:token` today only by accident of the issuance sites hardcoding their scopes.
- **Structural rejection by vault42 itself.** The `token_type` claim is `mint`, which is outside the
  allow-list vault42's auth middleware accepts, and the audience is not vault42's. Either check
  alone stops a minted token at vault42's door; both are enforced. Without them a mint credential
  would be full account takeover of every vault42 user.
- **No credential-bearing claims.** No `client_id`, no `fingerprint`, no `cnf`, no refresh token and
  no stored session. Setting `client_id` would make a minted token indistinguishable from a
  client-credentials token to any code that treats the claim's presence as proof of a service
  caller, including the service document store (section 7.8), which asserts exactly that.
  Attribution lives in the audit event, where it cannot be replayed.
- **Deny-by-default roles and scopes.** Both allow-lists start empty, so a freshly enabled mint
  issues bare subject assertions. `admin` and `super_admin` are refused whatever the list says, as
  are the vault42 capability scopes `mint:token`, `kms:unwrap`, `svcdoc:read`, `svcdoc:write`,
  `admin`, `admin:read` and `admin:write`. A listed admin role or capability scope aborts startup.
- **Short, unclampable lifetimes.** A minted token cannot be revoked, because vault42 holds no
  record of it beyond the audit event, so its exposure window is its whole security story. The
  ceiling is 15 minutes, enforced in the constructor rather than left to configuration, and a
  request above the operator's cap is refused rather than clamped: silently issuing something other
  than what was asked for hides a misconfigured caller until the day its tokens expire mid-flight.
- **Rate limiting:** 60/min, fail-closed. The key function asks for the authenticated client, but
  the limiter sits outside the auth middleware, so in practice the bucket is the source IP.
- **Audit on every path.** One `token_minted` event per request, accepted or refused, recording the
  asserted subject and the asserting client. It is a distinct event type from `login_success`,
  `token_refresh` and `client_auth` because the signature is indistinguishable, so the log is the
  only place the difference is recorded. `token_minted` is not in the critical-event set of section
  9.3, so a deployment that batches audit writes can drop it under buffer pressure.

What is deliberately NOT checked: whether the subject exists in vault42. It usually does not, and
that is the point.

**Source:** `internal/service/mint.go`, `internal/handler/mint.go`, `internal/server/server.go`,
`internal/config/config.go`, `cmd/vault/main.go`

---

## 7. User Management

### 7.1 Profile

**Read:** `GET /user/profile` (authenticated)

Returns: `id`, `email`, `email_verified`, `display_name`, `avatar_url`, `locale`, `mfa_required`,
`mfa_enabled`, `mfa_methods`, `created_at`

`avatar_url` is readable as well as writable. Before 1.0.0 `PUT` accepted it and `GET` did not return
it, so a client could set the value and could only read it back through the GDPR export endpoint.

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

**Named blobs:** Addressed by a human-readable name (e.g. `session-data`) instead of UUID. The name is stored as HMAC hash -- the plaintext name never persists to the database. PUT replaces any existing blob with the same name (atomic delete + insert, preserving the immutability trigger). Names must match `[a-zA-Z0-9_-]+` (max 255 chars); an upload with a name outside that charset is rejected with 400 `invalid_name`.

**Response headers on download:** `Content-Type: application/octet-stream`, `X-Blob-Checksum`, `X-Blob-Label` (if set)

**Audit events:** `blob_upload`, `blob_upload_named`, `blob_download`, `blob_download_named`, `blob_delete`, `blob_delete_named`

Blob audit metadata records the blob id and a `named` flag, never the reference name or the label. The audit logger drops the `name`, `blob_name`, `ref_name` and `label` keys from any `blob_*` event so a future caller cannot reintroduce them.

**Source:** `internal/handler/blob.go`, `internal/service/blob.go`

### 7.6 Account Erasure and Recovery Escrow

**Endpoint:** `DELETE /user/account` (authenticated + password in body; mounted only when an
account-recovery repository is wired)

Self-service erasure under GDPR Article 17. This is the most destructive endpoint in the product: it
is irreversible from the service's own side, and the only route back is an offline key the server
does not hold.

**Authorization.** Bearer token **and** the current password re-submitted in the request body. A
stolen access token alone cannot erase an account. The password is verified with Argon2id and an
overloaded semaphore surfaces as `503 server_busy` rather than a wrong-password error, so the
failure modes stay indistinguishable from the ordinary login paths.

**Rate limit:** 3 per hour per IP, **fail closed** -- a cache outage rejects with 503 rather than
degrading to a per-pod counter that would multiply the effective limit across replicas.

**Order of operations** (`internal/service/erasure.go`). The cascade spans nine stores against a
pool-backed repository set, so there is no transaction to roll back with; what matters is which side
of a mid-cascade failure the account is left on.

1. **Escrow** an encrypted recovery record, when a recovery public key is configured. This is
   fail-closed: with escrow enabled, erasure MUST NOT proceed if the record cannot be written.
2. **Tombstone** -- scrub and soft-delete the user row. The account stops authenticating before any
   PII is destroyed. Scrubbing last would leave a failure window in which a still-loginable account
   had already lost its second factors: the user locked out of an account that was never erased.
3. **Purge** -- identity profile, blobs, devices, social links, password history, refresh tokens,
   TOTP secrets, WebAuthn credentials and backup codes. Every delete is keyed
   `WHERE user_id = ...` or by pseudonym, so all of them are idempotent and an interrupted erasure
   is finished by re-running it.

A re-run against an already-tombstoned account skips the escrow step, because the row now holds the
tombstone address and escrowing that would overwrite a good recovery record with useless data.

**Asymmetric escrow.** `auth.account_recovery` holds the erased user's real email and a minimal
profile, RSA-encrypted to `VAULT_RECOVERY_PUBLIC_KEY`. The server holds the public half only: it can
write records and cannot read them back. A compromised server or a dumped database therefore yields
no erased addresses, while the operator can still restore an account using the offline private key
via `cmd/recover`. The table is append-only on the same footing as the audit log -- `UPDATE` and
`DELETE` are blocked by triggers and `vault_app` holds `INSERT` + `SELECT` only -- so an attacker
who can write rows still cannot rewrite or erase escrow history. `pseudonym` is an HMAC-SHA256 of
the user id, which correlates a record to the soft-deleted row without storing a plaintext identity.

**Payload binding.** The escrowed payload is sealed to the row it belongs to: the record's primary key and
its `pseudonym` are the RSA-OAEP label and the AES-GCM AAD, and the payload itself carries the erased
user's id. Without that binding the two halves of a recovery record were independent -- `deleted_at`,
`deleted_by` and `reason` are ordinary columns beside the ciphertext -- so anyone able to write the table
could move a payload from one row to another and `cmd/recover` would report the move as fact. A moved
payload now fails at the key unwrap. `cmd/recover` rebuilds the binding from the row's own columns, which
is why it needs no HMAC secret to do so.

Records written before the binding existed remain readable, are labelled `escrow_format: "legacy"` in the
recovery output, and are reported on stderr as unverified attributions. `cmd/recover --allow-legacy=false`
refuses them; once the retention horizon has aged the last of them out, that read path can be removed.

**Retention.** The escrow log is exempt from the erasure cascade by construction, so it is bounded
by time instead (Article 5(1)(e)). `VAULT_RECOVERY_RETENTION_DAYS` sets the horizon and
`vault cleanup-recovery` sweeps it via a `SECURITY DEFINER` function that briefly disables the
append-only trigger. Nothing sweeps automatically: the variable is unset by default and the command
must be run.

**With escrow disabled** (`VAULT_RECOVERY_PUBLIC_KEY` unset) erasure still works. It is simply not
recoverable.

**Source:** `internal/handler/account.go`, `internal/service/erasure.go`,
`migrations/007_account_recovery.sql`, `migrations/011_recovery_retention.sql`, `cmd/recover/`

### 7.7 Data Export

**Endpoint:** `GET /user/data-export` (authenticated, 5/min/IP)

Satisfies the right of access (GDPR Article 15) and the right to data portability (Article 20) by
returning, as one JSON document, every category of personal data the service holds for the calling
user. It adds no storage of its own: it aggregates the existing repositories and services, so an
export cannot drift from what is actually stored.

Contents: account metadata, the decrypted identity profile (including marketing-consent
provenance), devices, blob **metadata only** -- id, label, size, checksum, never contents -- linked
social accounts with provider tokens deliberately excluded, and user-scoped audit events.

**Audit events are capped at 1000, most recent first.** An unbounded query would risk large
responses and memory pressure. Because a silently truncated export would be indistinguishable from a
complete one, the response always states the shape of the truncation: `audit_events_total`,
`audit_events_limit` and `audit_events_truncated`. A subject can therefore tell a partial export
from a whole one and ask the Operator for the remainder.

Degrades cleanly: when the identity store or blob storage is disabled the corresponding keys are
empty rather than absent.

This is not the same thing as the `export-audit` CLI verb (section 6.3), which dumps the whole audit
log for an operator.

**Source:** `internal/handler/data_export.go`, `internal/handler/response_types.go`

### 7.8 Service-Scoped JSON Documents

**Endpoints:** `PUT`, `GET`, `DELETE /service/documents/{subject}/{key}` and
`GET /service/documents/{subject}` (mounted only when `VAULT_SVCDOC_ENABLED=true`). `api.md` is
authoritative for the request and response bodies.

A namespaced arbitrary-JSON store with an ownership axis: a registered service client writes
documents scoped to `(itself, a subject, a key)`, and by default nothing else can read them. It
exists so a service can keep small structured records about a user without owning a schema migration
for every new per-user boolean. `IdentityData.Dynamic` had the right semantics and the wrong access
control -- one ciphertext, written by the user's own token, with no per-service isolation.

Off by default because this is new surface reachable by every existing client-credentials holder, so
enabling it is an explicit operator decision rather than a consequence of upgrading. The shared
visibility tier is a second, separate switch.

**Architecture:**
- Schema: `objects.service_documents(id UUID PK, client_id UUID FK -> auth.clients, subject_hash
  VARCHAR(128), doc_key VARCHAR(128), visibility SMALLINT, data_enc BYTEA, size_bytes INT,
  stored_bytes INT, version INT, created_at, updated_at)`, `migrations/014_service_documents.sql`
- Unique index on `(client_id, subject_hash, doc_key)`: a replacement is an `UPDATE` through that
  index, never a second row. A partial index on `(subject_hash, doc_key) WHERE visibility = 1` keeps
  the cross-service read off the private majority
- AES-256-GCM at rest, never plaintext JSONB. These documents hold data a service wrote about a
  user; a plaintext column here would be the product's first plaintext personal-data column
- **AAD binding:** `svcdoc:<client_id>:<subject_hash>:<doc_key>`, a superset of the blob AAD. A row
  copied between clients, subjects or keys fails to decrypt rather than silently changing owner. The
  surrogate id is deliberately absent so a replacement keeps its identity without a re-key
- Subject stored as `HMAC-SHA256(userID + ":svcdoc", hmac_secret)`, so the table does not enumerate
  which users a service holds records about. The erasure cascade derives the same value
- `visibility` is a `CHECK`-constrained enum (`0` private, `1` shared) rather than a boolean, so a
  third tier (an explicit grantee allow-list) is a constraint widening plus a new table rather than
  a column type change and a wire break
- Ownership is a SQL predicate on every request-path read, not a comparison performed after fetching
- Deliberately not a column on `objects.blobs`: blob ownership has no client dimension, the blob
  routes authenticate a user JWT, blob `DELETE` requires a password re-confirmation no service can
  satisfy, and the blob prefix carries a body-cap exemption sized for 10 MiB uploads
- Roles: `vault_app` gets `SELECT, INSERT, UPDATE, DELETE` explicitly, because migration 001's
  `ALTER DEFAULT PRIVILEGES IN SCHEMA objects` grants only `SELECT, INSERT, DELETE` and an inherited
  default would leave replacement failing with `42501` at runtime and invisible to the integration
  suite. `vault_admin` gets `SELECT, DELETE` for the admin-gateway erasure cascade

**The `_global` sentinel subject** holds documents that belong to a service rather than to any user:
feature flags, per-service settings. It is a sentinel rather than a `NULL` subject because
PostgreSQL treats `NULL`s as distinct in a unique index, so a nullable column would silently permit
duplicate `(client_id, NULL, doc_key)` rows. It cannot collide with a real subject, which must start
with an alphanumeric. Global documents are audited with an empty `user_id` rather than the sentinel,
and are excluded from every subject's data export: they are attached to no subject, and exporting
them would hand one service's configuration to every user who asks.

**Validation.** A document body is walked on the token stream before any unmarshal, because
`encoding/json` has no depth limit and no duplicate-key rejection. A 64 KiB body of `[` characters
is roughly 32 thousand nesting levels; unmarshalling it recurses that deep and takes the process
down, so depth is bounded before the decoder ever builds a value. The bounds are a JSON object at
top level, at most 32 levels deep, at most 1024 keys in total, no duplicate key within an object,
valid UTF-8 checked on the raw bytes, and nothing after the closing brace. A repeated key decodes
last-wins, so a document carrying one round-trips differently than it was submitted -- a correctness
bug on its own and a signature-bypass primitive if anything downstream ever verifies a body it also
parses. None of these bounds are operator-tunable.

**Quotas:** `VAULT_SVCDOC_MAX_SIZE` (default 64 KiB) per document, measured on the canonical
encoding; `VAULT_SVCDOC_MAX_PER_SUBJECT` (default 32) documents per `(client, subject)`; and
`VAULT_SVCDOC_QUOTA_BYTES` (default 1 MiB) stored bytes per subject summed across every owning
client, so one user's footprint is bounded no matter how many services write about them. Quota is
evaluated against the state the write would produce, so a replacement is not charged twice and does
not consume a document slot it already holds.

**Access control:**
- `svcdoc:write` on `PUT` and `DELETE`, `svcdoc:read` on both `GET`s, via `middleware.RequireScope`
- Every handler additionally asserts a non-empty `client_id` claim. `RequireScope` checks only the
  scopes array, and a user token can never carry a `svcdoc` scope today only because every
  user-token issuance site hardcodes `["read","write"]`. That is an accident of the current code and
  not an invariant: a change to user-scope issuance would otherwise silently open a service-owned
  store to end-user tokens. The ownership axis of this store is the client id, so the handler
  asserts it directly. It is also why a minted token (section 6.5) carries no `client_id`
- A document owned by another client that is not shared is reported as **absent, never forbidden**.
  The alternative turns the store into an oracle for "does service X hold a record at key K about
  user U", which is exactly the question the pseudonymised subject exists to make unanswerable. An
  `?owner=` naming an unregistered client collapses to the same `404`
- `DELETE` only ever removes the caller's own row, shared or not

**Rate limiting:** 60/min on writes, 300/min on reads, not fail-closed -- these routes release only
what the caller itself wrote, and a cache blip must not take profile reads down across every
consuming service. The key function asks for the authenticated client, but the limiter sits outside
the auth middleware, so in practice the bucket is the source IP.

**Body cap:** the `/service/documents` prefix is exempt from the global 8 KiB cap so a 64 KiB
document is not truncated mid-transfer with no useful error. `PUT` re-applies its own limit of
`VAULT_SVCDOC_MAX_SIZE` + 1 KiB, because an exemption without a reader of its own is an
unbounded-body hole.

**Audit events:** `svcdoc_put`, `svcdoc_get`, `svcdoc_delete`. Metadata is limited to the key, the
size, the visibility and the outcome; a body is never logged. Listing writes no event. The actor
split differs from `client_auth` and `kms_unwrap`, which file the client id in both fields because
those events have no user: here there genuinely is one, and filing it under `user_id` is what puts
the event in that user's data export.

**GDPR:** documents ride the erasure cascade across every owning service, and `GET
/user/data-export` returns them **decrypted, including private ones** -- a service's privacy from
other services is not privacy from the data subject. A document that fails to decrypt is skipped
rather than failing the whole export, so one unreadable row does not deny a subject the rest of
their data.

**Source:** `internal/service/servicedoc.go`, `internal/handler/servicedoc.go`,
`internal/repository/postgres/servicedoc.go`, `migrations/014_service_documents.sql`

---

## 8. Rate Limiting

### 8.1 Endpoint Tiers

"Closed" in the last column means the limiter rejects with `503 rate_limiter_unavailable` when the
distributed cache is down, instead of falling back to the per-process in-memory counter. The
fallback is per-pod, so under a cache outage it would multiply the effective limit by the replica
count -- acceptable for a read endpoint, not for anything that guards a credential or releases key
material.

| Endpoint | Limit | Window | Key | On cache outage |
|----------|-------|--------|-----|-----------------|
| `POST /auth/login` | 5 | 15 min | IP | Closed |
| `GET /auth/oauth2/callback/{provider}` | 5 | 15 min | IP | Closed |
| `POST /auth/register` | 3 | 1 hour | IP | Closed |
| `POST /auth/password/reset` | 3 | 1 hour | IP | Closed |
| `POST /auth/password/reset/confirm` | 3 | 1 hour | IP | Closed |
| `DELETE /user/account` | 3 | 1 hour | IP | Closed |
| `POST /auth/2fa/totp/verify` | 5 | 5 min | IP | Closed |
| `POST /auth/2fa/backup-code/verify` | 5 | 5 min | IP | Closed |
| `POST /auth/2fa/email-otp/verify` | 5 | 5 min | IP | Closed |
| `POST /auth/2fa/email-otp/resend` | 5 | 5 min | IP | Closed |
| `POST /kms/unwrap` | 30 | 1 min | IP | Closed |
| `POST /mint` | 60 | 1 min | IP (see below) | Closed |
| `POST /auth/refresh` | 30 | 1 min | IP | In-memory fallback |
| `GET /auth/verify-email` | 10 | 1 hour | IP | In-memory fallback |
| `POST /client/token` | 10 | 1 min | IP | In-memory fallback |
| `GET /auth/oauth2/authorize` | 10 | 1 min | IP | In-memory fallback |
| `POST /auth/oauth2/exchange` | 10 | 1 min | IP | In-memory fallback |
| `POST /auth/confirm` | 5 | 15 min | user ID | In-memory fallback |
| `POST /user/password` | 5 | 15 min | user ID | In-memory fallback |
| `DELETE /user/identity` | 5 | 15 min | user ID | In-memory fallback |
| `DELETE /user/blobs/{id}` | 5 | 15 min | user ID | In-memory fallback |
| `DELETE /user/blobs/named/{name}` | 5 | 15 min | user ID | In-memory fallback |
| `DELETE /user/social/{id}` | 5 | 15 min | user ID | In-memory fallback |
| `GET /user/identity` | 30 | 1 min | IP | In-memory fallback |
| `POST /user/marketing/unsubscribe` | 30 | 1 min | IP | In-memory fallback |
| `PUT /user/identity` | 10 | 1 min | IP | In-memory fallback |
| `POST /user/blobs` | 10 | 1 min | IP | In-memory fallback |
| `PUT /user/blobs/named/{name}` | 10 | 1 min | IP | In-memory fallback |
| `GET /user/blobs` | 30 | 1 min | IP | In-memory fallback |
| `GET /user/blobs/{id}` | 30 | 1 min | IP | In-memory fallback |
| `GET /user/blobs/named/{name}` | 30 | 1 min | IP | In-memory fallback |
| `GET /user/data-export` | 5 | 1 min | IP | In-memory fallback |
| `PUT /service/documents/{subject}/{key}` | 60 | 1 min | IP (see below) | In-memory fallback |
| `DELETE /service/documents/{subject}/{key}` | 60 | 1 min | IP (see below) | In-memory fallback |
| `GET /service/documents/{subject}/{key}` | 300 | 1 min | IP (see below) | In-memory fallback |
| `GET /service/documents/{subject}` | 300 | 1 min | IP (see below) | In-memory fallback |
| `POST /admin/auth/login` | 10 | 1 min | IP | n/a (in-process) |

**"IP (see below)"** marks the five routes configured with `handler.ClientRateLimitKey`, which
buckets by the authenticated `client_id` and falls back to the source address when the request
carries no claims. Every one of those limiters is mounted **outside** `authMw`
(`internal/server/server.go:509-518, 564-570`), so the claims are never in context when the key is
computed and the fallback is always taken. The effective bucket is the source IP. A caller behind a
single in-cluster pod therefore shares one budget across its whole fleet, which is the outcome the
client key was introduced to avoid; treat the numbers above as per-address until the chain order
changes. That change would loosen a limit, which section 0.3 permits in a minor release.

Every other route is unlimited at the middleware layer. `POST /user/marketing/unsubscribe` carries
the *read* limit rather than the write one on purpose: withdrawing consent must be no harder than
granting it (Article 7(3)), so unlike identity deletion it has neither a confirmation step nor a
tighter budget.

Rate limiting is enabled by default (`VAULT_RATE_LIMIT_ENABLED=true`). The dev profile inherits this
from production and only disables it if explicitly overridden. `VAULT_ALLOW_RATE_LIMIT_DISABLED` is
the escape hatch that permits turning it off in a production profile at all; see `config.md`.

### 8.2 Response Headers

All rate-limited responses include:
- `X-RateLimit-Limit` -- maximum requests in window
- `X-RateLimit-Remaining` -- remaining requests
- `X-RateLimit-Reset` -- Unix timestamp when window resets

Rate-limited requests return `429 Too Many Requests` with a `Retry-After` header.

### 8.3 Cache Backend

Rate limit counters use the cache interface (`Increment` with TTL). If the cache is unreachable, an
ordinary limiter falls back to an in-memory counter (`localRateLimiter`, `sync.Mutex` + map): the
limit stays enforced per pod, and authentication does not fail merely because the cache is down.

A limiter marked `FailClosed` does not take that fallback. It rejects with
`503 rate_limiter_unavailable` and a `Retry-After` header, and logs one warning per process. The
tradeoff is deliberate and asymmetric: an outage that degrades a read endpoint is a nuisance, while
an outage that multiplies the brute-force budget by the replica count is a security regression.

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
| `kms_unwrap` | `KMSUnwrap` | KEK envelope-unwrap attempt (`kid` and outcome only) |
| `token_minted` | `handler.AuditTokenMinted` | Token signed for a caller-asserted subject via `POST /mint` (section 6.5). Emitted on refusal as well as success |
| `svcdoc_put` | `handler.AuditSvcDocPut` | Service document created or replaced (section 7.8) |
| `svcdoc_get` | `handler.AuditSvcDocGet` | Service document read |
| `svcdoc_delete` | `handler.AuditSvcDocDelete` | Service document deleted |
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
- **Buffer overflow protection:** configurable buffer size (`VAULT_AUDIT_BUFFER_SIZE`, default 1000). When the buffer is full, the critical event set bypasses the buffer and writes synchronously; everything else is dropped, counted and logged. The set is exactly `login_failure`, `password_change`, `password_reset`, `token_revoke`, `admin_action` and `kms_unwrap` (`isCriticalEvent`). Notably `token_minted` and the `svcdoc_*` events are **not** in it, so a deployment that both enables minting and batches audit writes can lose mint attribution under load. Batching is off by default (`VAULT_AUDIT_FLUSH_INTERVAL=0`, immediate write) and on in the embedded profile.

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

### 10.3 Per-App White-Label Branding

`VAULT_APP_NAME`, `VAULT_LOGO_URL` and `VAULT_PRIMARY_COLOR` set the global branding. On top of
that, branding and template overrides can be stored per app, so one vault42 deployment sends
verification and reset emails that wear the identity of whichever product the user is actually
using. This is email only: there is no server-rendered themed auth page (section 0.8).

**Selecting an app.** `middleware.AppContext` reads the `X-Vault-App` request header, shape-validates
the slug against `^[a-z0-9][a-z0-9_-]{0,63}$`, and puts it in the request context for the email layer.
Read section 0.9 before deploying this: it is a branding selector and nothing else, and it carries no
isolation guarantee whatsoever.

**It is a proxy-set header, not a client value.** Every endpoint that sends one of these emails is
unauthenticated by design, so the slug is honoured only when the direct peer is inside
`TRUSTED_PROXIES`. The gateway in front of vault42 sets it per tenant and overwrites whatever the
client sent. A request arriving directly, or through an untrusted peer, selects no app and renders
the global branding. Without that rule any outside caller could make a genuine password-reset email
for a victim on one product arrive wearing another product's identity. There is deliberately no
`?app=` query fallback: a proxy forwards the client's query string verbatim, so a query parameter can
never be an operator-controlled channel.

**Branding** (`auth.email_branding`, one row per app): `app_name`, `logo_url`, `primary_color`,
`from_name`, `from_address`. Any unset column falls back to the global value, so a partial row is
valid.

**Template overrides** (`auth.email_templates`, unique on `(app, template_name)`): `subject`,
`html_content`, `text_content` and an `enabled` flag, for any of the seven template names in
section 10.1. Overrides pass the same forbidden-pattern validation as filesystem overrides -- no
`<script>`, `<iframe>`, `<object>`, `<embed>`, `<form action>`, `javascript:` URI, `on*=` handler, or
Go template `call`/`js` directive -- and are capped by `VAULT_MAX_EMAIL_TEMPLATE_SIZE`.
`VAULT_EMAIL_FROM_ALLOWED_DOMAINS` constrains what `from_address` may be set to, so an admin cannot
point a tenant's mail at a domain the deployment does not control.

Resolution order for a rendered email: per-app template override, then per-app branding, then the
filesystem override directory, then the embedded default.

Both tables are managed through nine admin gateway routes (section 21.8). `email:write` is not
app-scoped: an admin who can edit one app's branding can edit every app's.

**Source:** `internal/middleware/appcontext.go`, `internal/email/mailer.go`,
`internal/email/branding.go`, `internal/adminapi/email.go`, `migrations/008_email_branding.sql`

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

Cache failures are mostly non-fatal: TOTP replay prevention and MFA challenge storage degrade
gracefully, and an ordinary rate limiter falls back to a per-process counter.

The exception is deliberate. The limiters listed as fail-closed in section 8.1 reject with
`503 rate_limiter_unavailable` during a cache outage rather than fall back, because a per-pod
counter would multiply the brute-force budget by the replica count. On those endpoints -- login, the
OAuth2 callback, registration, password reset, account deletion, the 2FA verify and resend routes,
and `POST /kms/unwrap` -- authentication does fail when the cache is down, and that is the intended
behaviour.

---

## 12. Database

### 12.1 Schema

Four schemas: `auth` (user data), `audit` (append-only logs), `identity` (encrypted PII), and `objects` (encrypted blobs and service documents).

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
| `webauthn_credentials` | WebAuthn credential IDs, public keys, sign counts, authenticator flags |
| `backup_codes` | HMAC-SHA256-hashed single-use backup codes |
| `rate_limits` | Rate limit counters (PostgreSQL cache fallback) |
| `admin_config` | Key-value admin settings (admin token hash) |
| `signing_keys` | Encrypted signing keys (AES-256-GCM private key, DER public key, status lifecycle) |
| `admin_roles` | RBAC admin roles reference table (`viewer`, `operator`, `super_admin`) |
| `admin_users` | Admin gateway accounts (Argon2id password, TOTP, role FK, lockout tracking) |
| `admin_sessions` | Admin gateway sessions (SHA256 token hash, CASCADE delete on admin revoke) |
| `cache` | Key-value cache with TTL (PostgreSQL cache backend) |
| `app_roles` | Custom application-role catalog (name, namespace, description, reserved flag) |
| `account_recovery` | Append-only erasure escrow: RSA-encrypted recovery payload keyed by HMAC pseudonym. `UPDATE`/`DELETE` blocked by trigger |
| `email_branding` | Per-app white-label branding (one row per app slug) |
| `email_templates` | Per-app template overrides, unique on `(app, template_name)` |

**Tables in `audit` schema:**

| Table | Purpose |
|-------|---------|
| `audit_log` | Append-only security event log (triggers prevent UPDATE/DELETE) |

**Table in `identity` schema:**

| Table | Purpose |
|-------|---------|
| `profiles` | Encrypted PII (pseudonymous key, AES-256-GCM encrypted JSON, version tracking) |

**Tables in `objects` schema:**

| Table | Purpose |
|-------|---------|
| `blobs` | Encrypted files (pseudonymous key, compressed+encrypted data, immutable via trigger) |
| `service_documents` | Service-scoped encrypted JSON (section 7.8). Unique on `(client_id, subject_hash, doc_key)`; mutable, unlike `blobs` |

**Source:** `migrations/001_initial_schema.sql` for the baseline; `migrations/003`--`014` add user
roles, account flags, the app-role catalog, account import, the recovery escrow and its retention
sweeper, email branding, erasure grants, WebAuthn credential flags, audit-function hardening, the
refresh-family lifetime column, and the service document store.

### 12.2 Roles

- **`vault_mig`:** DDL privileges, used only at startup for migrations, then connection closed
- **`vault_app`:** `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `auth` schema; `INSERT`, `SELECT` only on `audit` schema; `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `identity` schema; `SELECT`, `INSERT`, `DELETE` by default on `objects` schema, with `objects.blobs` immutable by trigger as well and `objects.service_documents` granted `UPDATE` explicitly by migration 014 because replacing a document is an `UPDATE`; NO `TRUNCATE`, NO DDL
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

[`config.md`](config.md) is authoritative for the full variable set, including defaults, validation
rules and profile interactions. What follows is the summary a reader of this specification needs;
where the two differ, `config.md` is right and this table is a defect.

**Security escape hatches.** Three variables disable a fail-closed guarantee. They exist because
some environments genuinely need them, and an operator who cannot find them will reach for something
worse:

| Variable | Default | What it turns off |
|----------|---------|-------------------|
| `VAULT_ALLOW_PLAINTEXT` | `false` | The refusal to run without TLS in a production profile |
| `VAULT_ALLOW_RATE_LIMIT_DISABLED` | `false` | The refusal to start with rate limiting off in a production profile |
| `VAULT_STRICT_SESSION_LIMIT` | `false` | Inverted: setting it makes the concurrent-session check fail **closed** on a count-query error (section 3.2) |

**Core:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_PROFILE` | `production` | Deployment profile |
| `LISTEN_ADDR` | `:8443` | Listen address |
| `VAULT_ORIGIN` | (required) | Public-facing URL |
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
| `VAULT_STRICT_SESSION_LIMIT` | `false` | Fail closed when the session-count query errors (section 3.2) |
| `VAULT_REGISTRATION_ENABLED` | `true` | When false, `POST /auth/register` answers `403 registration_disabled` |
| `VAULT_DPOP_ENABLED` | `false` | **Experimental and unsupported.** Enables the RFC 9449 proof validator and the `DPoP` auth scheme. Binds nothing; section 0.6.2 |
| `VAULT_FORCE_SECURE_COOKIES` | `false` | Force Secure flag on cookies regardless of TLS state |
| `VAULT_TLS_FINGERPRINT_HEADER` | (optional) | Header the TLS-terminating proxy puts a JA4 fingerprint in (section 5.1) |
| `VAULT_PEPPER_FILE` | (optional) | Server-side password pepper (`_FILE` convention) |

**Account Recovery (erasure escrow):**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_RECOVERY_PUBLIC_KEY_FILE` | (optional) | RSA public key that erasure escrow records are encrypted to. Unset means erasure works but is not recoverable, and the server logs a warning at boot |
| `VAULT_RECOVERY_RETENTION_DAYS` | `0` (disabled) | Retention horizon for `auth.account_recovery`. Nothing is swept until `vault cleanup-recovery` runs |

**KMS:**

| Variable | Default | Description |
|----------|---------|-------------|
| `KMS_ROOT_KEY_FILE` | (optional) | KMS root secret (>= 32 bytes). Unset means `POST /kms/unwrap` is not mounted at all |

**Email:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_EMAIL_PROVIDER` | `smtp` | Email backend (`smtp` or `sendgrid`) |
| `SMTP_HOST` | (optional) | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `VAULT_EMAIL_FROM` | (optional) | Sender address |
| `VAULT_EMAIL_FROM_NAME` | (optional) | Sender display name (global default; per-app override in section 10.3) |
| `VAULT_EMAIL_FROM_ALLOWED_DOMAINS` | (optional) | Domains a per-app `from_address` may use. Stops an admin pointing a tenant's mail at a domain the deployment does not control |
| `VAULT_EMAIL_TEMPLATES_DIR` | (optional) | Directory for custom email template overrides |
| `VAULT_MAX_EMAIL_TEMPLATE_SIZE` | (see `config.md`) | Byte cap on a stored template override |

**OAuth2 and OpenID Connect:**

| Variable | Description |
|----------|-------------|
| `VAULT_OAUTH_GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `VAULT_OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth2 client ID |
| `VAULT_OAUTH_FACEBOOK_CLIENT_ID` | Facebook OAuth2 client ID |
| `VAULT_OIDC_PROVIDERS` | Comma-separated keys for generic OIDC issuers (section 2.11) |
| `VAULT_OIDC_<NAME>_ISSUER` | Issuer base URL; discovery fetches `{issuer}/.well-known/openid-configuration` |
| `VAULT_OIDC_<NAME>_CLIENT_ID` | Client ID for that issuer |
| `VAULT_OIDC_<NAME>_CLIENT_SECRET_FILE` | Client secret (`_FILE` convention) |
| `VAULT_OIDC_<NAME>_SCOPES` | Optional, space-delimited. Defaults to `openid email profile` |

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

**On the prefix.** Four conventions coexist: unprefixed, `VAULT_`, `ADMIN_GW_` (admin gateway) and
`BRIDGE_` (honeypot bridge). The unprefixed set includes generically-named variables --
`LISTEN_ADDR`, `MASTER_KEY`, `HMAC_SECRET`, `ADMIN_TOKEN`, `ISSUER`, `CLIENT_ID`,
`CLIENT_SECRET`, `SCOPES`, `REDIS_ADDR`, `CACHE_BACKEND`, `DB_*`, `SMTP_*`, `CORS_*`, `IP_*`,
`GEO_*`, `TRUSTED_PROXIES`, `REAL_IP_HEADER`, `KMS_ROOT_KEY`, `SENDGRID_API_KEY` -- several of
which are exactly the names an OIDC-adjacent deployment is likely to have already set for something
else. Operators SHOULD scope vault42's environment rather than share one.

Renaming these is a breaking configuration change under section 0.4, so it cannot happen inside 1.x.
The compatible path is to accept `VAULT_`-prefixed aliases alongside the bare names in a 1.x
release and to drop the bare names at 2.0.0.

<!-- loglevel-gate:begin -->
**On log verbosity.** vault42 has no log-verbosity control, and `LOG_LEVEL` is not configuration.
Before 1.0.0 it was parsed into a config field and given a per-profile default while no binary read
it, so `LOG_LEVEL=error` and `LOG_LEVEL=debug` produced byte-for-byte identical output. Advertising
a control the server does not implement is worse than having no control, so 1.0.0 removes the
variable; section 0.4 permits that only at a major version, which makes 1.0.0 the point to do it.

The server still looks for `LOG_LEVEL` in its environment and logs one line at startup stating that
it is ignored. It does not refuse to start, because `LOG_LEVEL` is precisely the kind of
generically-named variable the paragraph above warns about: in a shared environment it is likely to
have been set for some other process, and rejecting it would convert a harmless inherited value into
a boot loop. Every log line is emitted regardless of what `LOG_LEVEL` says. Operators who need to
reduce log volume should filter at the collector.
<!-- loglevel-gate:end -->

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
| `ADMIN_TOKEN_FILE` | Admin CLI token, or its Argon2id hash |
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

Multi-stage build, every stage pinned by digest:
1. **Frontend:** `node:22-alpine` -- builds the Vue SPA for embedding
2. **Builder:** `golang:1.26.6-alpine` -- builds the static binary (`CGO_ENABLED=0`)
3. **Runtime:** `gcr.io/distroless/static-debian12:nonroot`

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

**Location:** `charts/vault/`

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

## 16. Endpoint Inventory

**103 API routes: 62 on the main binary, 41 on the admin gateway.** This inventory is the complete
set. `tests/spec/route_drift_test.go` parses `internal/server/server.go` and
`internal/adminapi/router.go` with `go/ast` and fails the build if a route here does not exist, or
if a route exists that is not here. Adding an endpoint without a row is not possible.

### 16.1 Response conventions

Normative for every endpoint in this inventory.

- **Field names are `snake_case`.** No response body carries a Go field name or a camelCase key.
- **Timestamps are RFC 3339 in UTC.** Fractional seconds MAY be present on any of them, so clients
  MUST parse RFC 3339 generally rather than matching a fixed layout. Most are marshalled Go
  `time.Time` values and carry nanoseconds; `updated_at` on the identity profile is formatted to
  second precision. Both are valid RFC 3339, which is why the rule is stated as a parsing
  obligation rather than as a promised layout.
- **A list field is always an array.** A field typed as an array in this specification MUST be `[]`
  when empty and MUST NOT be `null`. Changing an array to `null`, or the reverse, is a JSON type
  change and therefore breaking under section 0.4.
- **List responses carry `{<collection>, total, limit, offset}`.** `total` is present even on an
  empty result, so a client never has to distinguish "no matches" from "this endpoint does not
  report a total". On the admin gateway `limit` defaults to 50 and is clamped to 100
  (`internal/adminapi/handler.go:391-392`); an out-of-range or unparsable value falls back to the
  default rather than erroring. Unpaged collections on the main binary return the collection key
  alone; adding paging to them later is additive under section 0.3, precisely because the envelope
  key never changes.
- **Errors are `{"error": "code"}`** with a lowercase underscore-separated code. Codes are in the
  contract; any accompanying human-readable text is not (section 0.6).
- **Request bodies reject unknown fields on the main binary and ignore them on the admin gateway.**
  Section 0.5.

### 16.2 Mount conditions

Nine route groups are conditionally mounted. When a group is not mounted its routes do not exist:
`net/http.ServeMux` answers `404` in `text/plain`, which is not the JSON error envelope and is
easily mistaken for a bad path. This column is the answer to "why does this endpoint 404 in
production".

`GET /auth/capabilities` reports registration and provider availability, but it does not enumerate
the conditional groups. An integrator MUST take the mount conditions from configuration, not by
probing.

<!-- BEGIN ROUTE INVENTORY -->

#### Main binary -- public (no authentication)

| Method | Path | Auth | Rate limit | Mounted when | Purpose |
|--------|------|------|------------|--------------|---------|
| `GET` | `/healthz` | None | -- | Always | Liveness probe |
| `GET` | `/readyz` | None | -- | Always | Readiness probe (pings DB + cache) |
| `GET` | `/metrics` | None | -- | `VAULT_METRICS_ENABLED` | Prometheus exposition (protect with a NetworkPolicy) |
| `GET` | `/auth/capabilities` | None | -- | Always | Capability discovery (2.10) |
| `POST` | `/auth/register` | None | 3/h IP | Always | Registration. Answers `403 registration_disabled` unless `VAULT_REGISTRATION_ENABLED` |
| `POST` | `/auth/login` | None | 5/15m IP | Always | Password login; may return a 2FA challenge |
| `POST` | `/auth/refresh` | Cookie | 30/m IP | Always | Rotate the refresh family |
| `GET` | `/auth/verify-email` | None | 10/h IP | Always | Consume an email verification token |
| `POST` | `/auth/password/reset` | None | 3/h IP | Always | Request a reset link |
| `POST` | `/auth/password/reset/confirm` | None | 3/h IP | Always | Complete a reset |
| `POST` | `/client/token` | Basic | 10/m IP | Always | Client-credentials grant |
| `GET` | `/.well-known/jwks.json` | None | -- | Always | JWKS public keys |
| `GET` | `/.well-known/openid-configuration` | None | -- | Always | Issuer metadata (20) |
| `GET` | `/auth/oauth2/authorize` | None | 10/m IP | >= 1 OAuth or OIDC provider configured | Start a social login |
| `GET` | `/auth/oauth2/callback/{provider}` | None | 5/15m IP | >= 1 OAuth or OIDC provider configured | Provider redirect target |
| `POST` | `/auth/oauth2/exchange` | None | 10/m IP | >= 1 OAuth or OIDC provider configured | Exchange the one-time code for tokens |

#### Main binary -- authenticated

| Method | Path | Auth | Rate limit | Mounted when | Purpose |
|--------|------|------|------------|--------------|---------|
| `POST` | `/auth/logout` | Bearer | -- | Always | Revoke every refresh token for the user |
| `POST` | `/auth/confirm` | Bearer | 5/15m user | Always | Open the 5-minute password-confirmation window |
| `GET` | `/auth/2fa/status` | Bearer | -- | Always | MFA status and `mfa_methods` |
| `POST` | `/auth/2fa/totp/setup` | Bearer + Confirmed | -- | Always | Provision a TOTP secret |
| `POST` | `/auth/2fa/totp/verify` | Bearer or Challenge | 5/5m IP | Always | Verify a TOTP code |
| `DELETE` | `/auth/2fa/totp` | Bearer + Confirmed | -- | Always | Disable TOTP |
| `POST` | `/auth/2fa/webauthn/register/begin` | Bearer + Confirmed | -- | Always | WebAuthn attestation options |
| `POST` | `/auth/2fa/webauthn/register/finish` | Bearer + Confirmed | -- | Always | Store a WebAuthn credential |
| `POST` | `/auth/2fa/webauthn/verify/begin` | Bearer or Challenge | -- | Always | WebAuthn assertion options |
| `POST` | `/auth/2fa/webauthn/verify/finish` | Bearer or Challenge | -- | Always | Verify a WebAuthn assertion |
| `GET` | `/auth/2fa/webauthn/credentials` | Bearer | -- | Always | List WebAuthn credentials |
| `DELETE` | `/auth/2fa/webauthn/credentials/{id}` | Bearer + Confirmed | -- | Always | Delete a WebAuthn credential |
| `POST` | `/auth/2fa/backup-codes` | Bearer + Confirmed | -- | Always | Generate 10 single-use codes |
| `POST` | `/auth/2fa/backup-code/verify` | Bearer or Challenge | 5/5m IP | Always | Consume a backup code |
| `POST` | `/auth/2fa/email-otp/verify` | Bearer or Challenge | 5/5m IP | Always | Verify an email OTP |
| `POST` | `/auth/2fa/email-otp/resend` | Bearer or Challenge | 5/5m IP | Always | Resend an email OTP |
| `GET` | `/user/profile` | Bearer | -- | Always | Read the profile |
| `PUT` | `/user/profile` | Bearer | -- | Always | Partial profile update (pointer semantics) |
| `GET` | `/user/sessions` | Bearer | -- | Always | List sessions and devices |
| `DELETE` | `/user/sessions` | Bearer | -- | Always | Revoke every session |
| `DELETE` | `/user/sessions/{id}` | Bearer | -- | Always | Revoke one session |
| `GET` | `/user/devices` | Bearer | -- | Always | List devices |
| `PATCH` | `/user/devices/{id}` | Bearer | -- | Always | Rename a device |
| `DELETE` | `/user/devices/{id}` | Bearer | -- | Always | Remove a device and its tokens |
| `POST` | `/user/password` | Bearer | 5/15m user | Always | Change the password |
| `DELETE` | `/user/account` | Bearer + password in body | 3/h IP, fail-closed | Account-recovery repository wired | Self-service erasure with escrow (7.6) |
| `GET` | `/user/data-export` | Bearer | 5/m IP | Always | GDPR Art. 15/20 export (7.7) |
| `GET` | `/user/social` | Bearer | -- | Always | List linked federated identities |
| `DELETE` | `/user/social/{id}` | Bearer | 5/15m user | Always | Unlink a provider and its stored tokens |
| `GET` | `/user/identity` | Bearer | 30/m IP | Identity store enabled | Read the decrypted identity profile |
| `PUT` | `/user/identity` | Bearer | 10/m IP | Identity store enabled | Upsert the identity profile |
| `DELETE` | `/user/identity` | Bearer + Confirmed | 5/15m user | Identity store enabled | Delete the identity profile |
| `POST` | `/user/marketing/unsubscribe` | Bearer | 30/m IP | Identity store enabled | Withdraw marketing consent (Art. 7(3)) |
| `POST` | `/user/blobs` | Bearer | 10/m IP | `VAULT_BLOB_QUOTA_BYTES` > 0 | Upload an encrypted blob |
| `GET` | `/user/blobs` | Bearer | 30/m IP | `VAULT_BLOB_QUOTA_BYTES` > 0 | List blobs and quota |
| `GET` | `/user/blobs/{id}` | Bearer | 30/m IP | `VAULT_BLOB_QUOTA_BYTES` > 0 | Download a blob |
| `DELETE` | `/user/blobs/{id}` | Bearer + Confirmed | 5/15m user | `VAULT_BLOB_QUOTA_BYTES` > 0 | Delete a blob |
| `PUT` | `/user/blobs/named/{name}` | Bearer | 10/m IP | `VAULT_BLOB_QUOTA_BYTES` > 0 | Create or replace a named blob |
| `GET` | `/user/blobs/named/{name}` | Bearer | 30/m IP | `VAULT_BLOB_QUOTA_BYTES` > 0 | Download a blob by name |
| `DELETE` | `/user/blobs/named/{name}` | Bearer + Confirmed | 5/15m user | `VAULT_BLOB_QUOTA_BYTES` > 0 | Delete a blob by name |
| `POST` | `/kms/unwrap` | Bearer + scope `kms:unwrap` | 30/m IP, fail-closed | `KMS_ROOT_KEY_FILE` set | KEK envelope-unwrap oracle (6.4) |
| `POST` | `/mint` | Bearer + scope `mint:token` | 60/m IP, fail-closed | `VAULT_MINT_ENABLED` | Sign a token for a caller-asserted subject (6.5) |
| `PUT` | `/service/documents/{subject}/{key}` | Bearer + scope `svcdoc:write` | 60/m IP | `VAULT_SVCDOC_ENABLED` | Store a service-scoped JSON document (7.8) |
| `GET` | `/service/documents/{subject}/{key}` | Bearer + scope `svcdoc:read` | 300/m IP | `VAULT_SVCDOC_ENABLED` | Read a service-scoped JSON document (7.8) |
| `DELETE` | `/service/documents/{subject}/{key}` | Bearer + scope `svcdoc:write` | 60/m IP | `VAULT_SVCDOC_ENABLED` | Delete a service-scoped JSON document (7.8) |
| `GET` | `/service/documents/{subject}` | Bearer + scope `svcdoc:read` | 300/m IP | `VAULT_SVCDOC_ENABLED` | List documents visible to the caller for a subject (7.8) |

#### Admin gateway

Served by `cmd/admin-gateway` only, never by the main binary. Every route sits behind mTLS,
loopback-only enforcement and a session cookie; the RBAC column names the permission the session's
role must hold. Section 21 describes the behaviour.

| Method | Path | Auth | RBAC permission | Mounted when | Purpose |
|--------|------|------|-----------------|--------------|---------|
| `POST` | `/admin/auth/login` | None | -- | Always | Password + optional TOTP, 10/min/IP |
| `POST` | `/admin/auth/logout` | Session | -- | Always | Revoke the current admin session |
| `GET` | `/admin/status` | Session | -- | Always | Current admin identity and 2FA state |
| `POST` | `/admin/admins/me/totp/setup` | Session | -- | Always | Provision the caller's TOTP secret |
| `POST` | `/admin/admins/me/totp/verify` | Session | -- | Always | Verify and enable the caller's TOTP |
| `GET` | `/admin/keys` | Session | `keys:list` | Always | Signing key metadata |
| `POST` | `/admin/keys/rotate` | Session | `keys:rotate` | Always | Generate a key, retire the old one |
| `DELETE` | `/admin/keys/{kid}` | Session | `keys:revoke` | Always | Remove a key from the JWKS immediately |
| `GET` | `/admin/users` | Session | `users:list` | Always | Look a user up by `?q=` (id or email) |
| `GET` | `/admin/users/{id}` | Session | `users:read` | Always | User detail |
| `POST` | `/admin/users/import` | Session | `users:import` | Always | Batch import, passwordless + `import_pending` |
| `POST` | `/admin/users/{id}/lock` | Session | `users:lock` | Always | Lock an account |
| `POST` | `/admin/users/{id}/unlock` | Session | `users:unlock` | Always | Unlock an account |
| `DELETE` | `/admin/users/{id}` | Session | `users:delete` | Always | Operator-initiated erasure |
| `GET` | `/admin/sessions` | Session | `sessions:list` | Always | Active refresh families |
| `POST` | `/admin/sessions/revoke-all` | Session | `sessions:revoke` | Always | Revoke every session service-wide |
| `GET` | `/admin/audit` | Session | `audit:read` | Always | Query the audit log (21.4) |
| `GET` | `/admin/clients` | Session | `clients:list` | Always | List service clients |
| `GET` | `/admin/clients/{id}` | Session | `clients:read` | Always | Client detail |
| `POST` | `/admin/clients` | Session | `clients:create` | Always | Create a client, secret shown once |
| `POST` | `/admin/clients/{id}/revoke` | Session | `clients:revoke` | Always | Deactivate a client |
| `POST` | `/admin/clients/{id}/rotate` | Session | `clients:rotate` | Always | Issue a new secret, invalidate the old |
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
| `GET` | `/admin/metrics` | Session | `metrics:read` | Always | **Unimplemented. Answers `501 not_implemented`** (21.10) |
| `GET` | `/admin/admins` | Session | `admins:manage` | Always | List admin accounts |
| `POST` | `/admin/admins` | Session | `admins:create` | Always | Create an admin (20-char minimum password) |
| `POST` | `/admin/admins/{id}/revoke` | Session | `admins:revoke` | Always | Revoke an admin; self-revocation refused |

<!-- END ROUTE INVENTORY -->

### 16.3 Surfaces that are not API routes

Thirteen further registrations exist and are deliberately outside the inventory and outside the
stability contract (section 0.6). The drift test classifies them by handler rather than by path, so a
new page is recognised without anyone remembering to update a list.

| Registration | Served by | Note |
|--------------|-----------|------|
| `/` (catch-all) | Main binary | Embedded Vue SPA. Only when `VAULT_SERVE_FRONTEND` is set or the honeypot profile is active. API routes win by `ServeMux` specificity. |
| `GET /admin/`, `/admin/login`, `/admin/ui/*` (10 pages) | Admin gateway | Static HTML shells with no secrets. No server-side auth on page routes: browsers send `GET` without an `Authorization` header, so session auth would answer a JSON 401 to a page load. Client-side JS handles the redirect, and every datum on the page comes from an authenticated API route. |
| `GET /admin/static/` | Admin gateway | CSS and JS assets. |

### 16.4 Opt-in subsystems

Two subsystems ship in 1.0.0 **off by default**. Both are mounted only when an operator sets their
gate, and on a deployment that sets neither, their five rows in section 16.2 do not exist: the mux
has no such patterns and `net/http.ServeMux` answers `404` in `text/plain`, not the JSON error
envelope.

| Subsystem | Routes | Gate | Detail |
|-----------|--------|------|--------|
| Subject-assertion signing oracle | `POST /mint` | `VAULT_MINT_ENABLED` (plus a required `VAULT_MINT_AUDIENCE` that must differ from `VAULT_ORIGIN`) | Section 6.5 |
| Service-scoped JSON document store | `PUT`, `GET`, `DELETE /service/documents/{subject}/{key}`, `GET /service/documents/{subject}` | `VAULT_SVCDOC_ENABLED`, with the shared visibility tier behind a second `VAULT_SVCDOC_SHARED_ENABLED` | Section 7.8 |

Both are in the stability contract on the same terms as every other route: their paths, error codes
and response fields are frozen for 1.x under sections 0.3 and 0.4. Being off by default is a
deployment property, not an exclusion from the contract, and section 0.6 does not list them.

Being opt-in is itself contractual in one direction. Section 0.4 forbids changing a default such
that an operator who set nothing gets different behaviour, so neither subsystem may become
on-by-default before 2.0.0.

---

## 17. Testing Strategy

Nine layers:

0. **Specification drift gate** (`tests/spec/`) -- parses the route registrations in
   `internal/server/server.go` and `internal/adminapi/router.go` with `go/ast` and compares them
   against the inventories in section 16 and in `api.md`, failing in both directions. It needs no
   database, no container and no build tag, and runs in well under a second: `go test ./tests/spec/`
   or `scripts/t.sh`. This is the layer that keeps this document honest; without it the endpoint
   inventory is a hand-maintained list that goes stale the first time someone is in a hurry.
1. **Unit tests** (`tests/unit/`, `internal/*/`) -- stdlib only, table-driven, covers all crypto operations
2. **Attack simulation** (`tests/attack/`) -- attack vectors against a real server + real PostgreSQL via testcontainers-go
3. **Compliance tests** (`tests/compliance/`) -- executable checks carrying requirement IDs. [`COMPLIANCE.md`](COMPLIANCE.md) is authoritative for which standards are claimed and at which revision; counts are not repeated here, because a hand-copied count is the first thing to go stale
4. **Integration tests** (`tests/integration/`) -- testcontainers-based PostgreSQL + Redis integration
5. **Fuzz tests** (`tests/fuzz/`) -- Go built-in `testing.F`: JWT parser/header/claims/time, registration input, login input, email validator, TOTP validator, ES256 signature, kid validation
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
| `github.com/jackc/pgx/v5` | v5.10.0 | PostgreSQL driver (pure Go) |
| `github.com/go-webauthn/webauthn` | v0.17.4 | WebAuthn/FIDO2 passkeys |
| `golang.org/x/crypto` | v0.53.0 | Argon2id password hashing |

Versions track `go.mod`, which is the authority; this table is a summary.

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

## 20. Issuer Metadata

**Endpoint:** `GET /.well-known/openid-configuration`

**vault42 is not an OpenID Connect provider** (section 0.8). The document served here states only
what is true of this server:

| Key | Value |
|-----|-------|
| `issuer` | Origin URL. The `iss` stamped into every token vault42 signs. |
| `jwks_uri` | `/.well-known/jwks.json`. Where the verification keys for those tokens live. |
| `access_token_signing_alg_values_supported` | `["RS256"]` |

Nothing else. The algorithm is also published per key in the JWKS, which stays correct if a key of
another algorithm is ever added; the summary key exists so a consumer can pin an expected algorithm
before it fetches the key set. It is deliberately **not** named
`id_token_signing_alg_values_supported`, because no ID token is ever issued.

**Why the rest was withdrawn.** Before 1.0.0 this document advertised an OIDC provider that does not
exist here, and publishing it at 1.0.0 would have frozen every consequence of that claim -- required
parameters, endpoint semantics and error codes -- under section 0.4. Each retracted key was false:

| Withdrawn key | Why it was untrue |
|---------------|-------------------|
| `token_endpoint: /auth/login` | `/auth/login` takes a JSON `{email, password}` body and ignores `grant_type` entirely. It is not an OAuth2 token endpoint. |
| `registration_endpoint: /auth/register` | In OIDC that key means RFC 7591 dynamic **client** registration. `/auth/register` is end-user signup. |
| `userinfo_endpoint: /user/profile` | Returns `display_name`, `email_verified` and friends, with no `sub` and no standard OIDC claim names. |
| `grant_types_supported: ["authorization_code", ...]` | There is no authorization-code token endpoint on this server. |
| `scopes_supported: ["openid", ...]` | No `id_token` is ever issued to a relying party. |
| `response_types_supported`, `subject_types_supported`, `code_challenge_methods_supported` | Meaningful only for the authorization-code flow that does not exist. |
| `dpop_signing_alg_values_supported` | Advertised unconditionally, including with `VAULT_DPOP_ENABLED` off, for a mechanism that binds nothing. Section 0.6.2. |

Keys are omitted rather than faked. Once `POST /client/token` reads `grant_type` and reports RFC 6749
error codes, `token_endpoint`, `grant_types_supported` and `token_endpoint_auth_methods_supported`
can be added back, which is additive under section 0.3. Removing them later would not have been.

Clients that only need to verify a vault42-issued token SHOULD fetch `/.well-known/jwks.json`
directly; this document exists to point at it.

**Source:** `internal/handler/wellknown.go`

---

## 21. Admin Gateway API

`cmd/admin-gateway` serves the 41 administrative routes in section 16 plus the HTML console. It runs
as a separate binary against the `vault_admin` database role, behind mTLS and six layers of
loopback-only enforcement, and is never mounted on the main binary. `admin-gateway.md` covers
deployment, the killswitch, certificate generation and the full RBAC matrix; this section covers the
API contract.

**Authentication** is a session cookie, not a JWT: `POST /admin/auth/login` takes username, password
and an optional TOTP code and returns a session whose SHA-256 hash is stored in
`auth.admin_sessions`; revoking an admin cascades to their sessions. Login is rate-limited 10/min/IP
in-process. `POST /admin/admins/me/totp/{setup,verify}` are reachable with a session that has not yet
passed 2FA, which is the point: an admin must be able to enrol.

**Authorization** is RBAC. Every route except login, logout, status and the caller's own TOTP setup
is wrapped in a permission check (`internal/rbac`). The permission for each route is in the
section 16 inventory. Permissions are service-wide: none of them is app-scoped or namespace-scoped.

### 21.1 Users

`GET /admin/users` is a lookup, not a listing: it requires `?q=` and resolves a UUID as an id and a
string containing `@` as an email. With no `q` it returns an empty collection. The response is the
standard list envelope, so a future real listing changes a value rather than a shape.

`POST /admin/users/import` batch-creates accounts, e.g. for a platform migration. Imported accounts
are **passwordless and `import_pending`**: legacy password hashes are never imported, and on the
user's first login with any password a one-time magic reset link is emailed. Completing it sets a
fresh Argon2id password and clears the flag. Admin-tier role names in `roles` are stripped. Existing
emails are skipped rather than overwritten. A `marketing_emails` value carried in from the source
system is stored with its provenance (`source=import`) and is **not** treated as affirmative
consent -- see `PRIVACY.md`.

`DELETE /admin/users/{id}` is the operator-initiated form of the erasure in section 7.6, with the
same escrow and the same cascade.

### 21.2 Sessions and keys

`GET /admin/sessions` lists active refresh families with the standard paged envelope.
`POST /admin/sessions/revoke-all` revokes every session service-wide. The key routes drive the
DB-backed keystore described in section 3.4.

### 21.3 Clients

Create, read, list, revoke and rotate service clients. A created or rotated secret is returned once
and never again; only its Argon2id hash is stored. The rotation route is
`POST /admin/clients/{id}/rotate` -- it is **not** `/rotate-secret`, which is the name of the CLI
verb (`rotate-client-secret`) and was documented as a path by mistake before 1.0.0.

### 21.4 Audit

`GET /admin/audit` filters on `user_id`, `event_type`, `since` and `until` (both RFC 3339), with
`limit` and `offset` on the same defaults and cap as every other admin list route.

The response projects each row explicitly (`auditEntryView`) rather than serialising the model, and
the projection is part of the contract:

- fields are `snake_case`, like the rest of the API;
- **`fingerprint_hash` is not exposed.** It is an HMAC of a device fingerprint, so it correlates
  events across accounts and across users. An operator investigating an event needs `device_id`,
  which identifies the same device without being a cross-account correlator;
- the request filter is not echoed back. It used to be, as a serialised internal repository struct;
- `total` is the number of entries in the returned window. `repository.AuditFilter` has no
  count-without-fetch counterpart, so a future true filtered count changes a value, not the shape;
- `risk_score` is present and is **explicitly excluded from the stability contract**. Section 0.6.1.

### 21.5 Roles

`GET|POST /admin/roles` and `DELETE /admin/roles/{name}` manage the application-role catalog
(`auth.app_roles`) that constrains what may appear in a user's `roles` claim. Baseline roles (`user`,
`viewer`, `operator`) are `reserved` and cannot be deleted; creating a role with an admin-tier or
reserved name is refused with `role_reserved`. This catalog is about application roles carried in
end-user tokens, and is distinct from the admin gateway's own RBAC roles.

### 21.6 Config

`GET /admin/config` reads the runtime key-value entries in `auth.admin_config`. Writes and deletes
are keyed in the path -- `PUT /admin/config/{key}`, `DELETE /admin/config/{key}` -- with the key
shape-validated. `PUT /admin/config` without a key is not a route and never was. Every change is
audited as `admin_config_change`.

This is a small runtime key-value store. Environment variables remain the primary configuration
mechanism and are not editable here.

### 21.7 Admin accounts

List, create and revoke admin gateway accounts. Creation enforces a 20-character minimum password.
Self-revocation is refused, so an operator cannot lock the last admin out by accident.

### 21.8 Email branding and templates

Nine routes backing section 10.3. Deleting a branding row or a template override drops that app back
to the global branding or the embedded default; there is no separate disable step.
`POST /admin/email-templates/preview` validates candidate content and renders it against sample data
without storing anything, and answers `200` with `{"valid": false, "error": ...}` for content that
fails validation rather than a `4xx` -- it is a linter, not a write.

### 21.9 Request strictness

The admin gateway decodes request bodies **without** `DisallowUnknownFields()`, so unknown keys are
ignored here and rejected on the main binary. Section 0.5 states the rule; callers MUST NOT rely on
either behaviour beyond what is written there.

### 21.10 `GET /admin/metrics` is not implemented

The route is mounted and gated on `metrics:read`, and there is nothing behind it. It answers
`501 not_implemented`.

It previously answered `200 OK` with `{"status":"ok","note":"Admin-specific metrics not yet
implemented"}` while `admin-gateway.md` described it as "get operational metrics". A 200-OK
placeholder is the worst of the available options: monitoring treats it as healthy and a client
cannot tell an empty feed from a working one. The endpoint is excluded from the stability contract
(section 0.6), so implementing it later is not a breaking change.

Prometheus metrics for the main binary are at `GET /metrics`, gated on `VAULT_METRICS_ENABLED`.

**Source:** `internal/adminapi/`, `cmd/admin-gateway/`

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
| OIDC auto-discovery (`.well-known/openid-configuration`) listed as optional | Two distinct things, both implemented. Outbound: full discovery against any configured OIDC issuer (section 2.11). Inbound: a minimal issuer-metadata document that claims only what is true of this server (section 20) | vault42 is an OIDC client, not a provider |
| Fingerprint separator collision prevention not specified | Length-prefixed fields (4-byte big-endian length + data) | Prevents crafted field values from producing identical hashes |
| Password confirmation for sensitive ops not in spec | `POST /auth/confirm` + `Confirmed` middleware with 5-minute window | Added for TOTP setup/disable, WebAuthn register/delete, backup code generation |
| MFA challenge flow not detailed in spec | 2FA challenge token (5-min JWT with `token_type: "2fa_challenge"`) | Implemented as a distinct token type with separate middleware |
| `rotate-jwks` listed as CLI command | Signing key update method exists (`TokenService.UpdateSigningKey`) | CLI command references this; not a standalone CLI subcommand in the implemented code |
| DPoP middleware listed in SpecV0 | Validator and wiring exist behind `VAULT_DPOP_ENABLED`; issuance does not, so the flag binds nothing | Dark launch, labelled experimental and excluded from the stability contract (section 0.6.2) |
| Argon2id parameter bounds checking not specified | Parser rejects iterations > 10, parallelism > 4, memory > 128 MiB | Prevents DoS via crafted hashes |

### Deferred to Future Versions

Verified against source at 1.0.0. Five rows of the pre-1.0.0 edition of this table were factually
wrong -- they denied features that ship -- so every row below cites what was checked.

| Feature | Status |
|---------|--------|
| **DPoP (Demonstration of Proof-of-Possession)** | **Inert, experimental, excluded from the stability contract.** The crypto (`internal/crypto/dpop.go`) and middleware (`internal/middleware/dpop.go`) are complete and correct, and the route wiring is real. Nothing issues a DPoP-bound token: `cnf.jkt` is declared in `internal/crypto/jwt.go` and never assigned, so the thumbprint check has nothing to compare against and the flag buys no sender-constraint in either position. Not advertised in discovery; the `DPoP` auth scheme is rejected unless `VAULT_DPOP_ENABLED` is set. Section 0.6.2. |
| **Facebook OAuth** | Fully implemented. `FacebookProvider` in `internal/oauth2/facebook.go`, PKCE S256 enforced, Vue login button added. |
| **Honeypot Bridge** | Fully implemented. `cmd/bridge/` is a standalone reverse proxy (stdlib only) that routes between real and honeypot Vault42 instances. Score-based detection (UA patterns, rate tracking, login failures, decoy page hits), admin API, Redis persistence, and fake login pages for scanner paths. Helm chart support via `bridge.enabled`. See [Bridge Deployment Guide](bridge.md). |
| **OIDC auto-discovery for providers** | **Implemented, and a headline feature.** `internal/oauth2/oidc.go` fetches and caches `{issuer}/.well-known/openid-configuration`, and `internal/config/config.go` registers arbitrary providers from `VAULT_OIDC_PROVIDERS` plus `VAULT_OIDC_<NAME>_{ISSUER,CLIENT_ID,SCOPES}`. Google and GitHub remain hardcoded because they predate it. Section 2.11. |
| **"Remember Me" as distinct device trust feature** | `remember_me` flag extends refresh token TTL (30 days vs 7 days), but the SpecV0 concept of "trusted device skips 2FA" is partially implemented via `MFAService.RequiresMFA` with `trustedDevice` parameter. Device trust window management is not enforced. |
| **Email encryption (paranoid mode)** | Not implemented |
| **Per-app white-label branding** | **Implemented.** `X-Vault-App` selects a stored branding row and per-template overrides for outbound auth email, managed through nine admin routes. Section 10.3. It is not a tenancy boundary: section 0.9. |
| **Server-rendered auth pages** | Not implemented, and not a goal. Branding applies to email only; the embedded Vue SPA (`VAULT_SERVE_FRONTEND`) is a static asset bundle, not a themed server-side render. Section 0.8. |
| **Multi-tenancy** | Not implemented. A tenant *concept* exists via `X-Vault-App` with exactly one job; section 0.9 states what it does and, at length, what it does not guarantee. Real tenancy changes the token shape, the schema and the RBAC model, so it is a major-version change. |
| **mTLS for service-to-service auth** | Not implemented on the main binary. The admin gateway requires mTLS. |
| **Certificate pinning** | Not implemented |
| **ACME auto-renewal (Let's Encrypt)** | Not implemented. BYO certificate only. Dev uses mkcert. |
| **Sidecar injection** | Not implemented |
| **SIEM streaming** | Not implemented. The audit log is queryable and exportable; nothing is pushed. |
| **IP geolocation** | Not implemented. `GEO_ALLOWLIST` / `GEO_BLOCKLIST` act on a country header the proxy supplies (`GEO_IP_HEADER`); vault42 performs no lookup of its own. |
| **Risk scoring (adaptive)** | Not implemented. `risk_score` is hardcoded per event type (0, 10, 20, 30, 70, 90) and is nonetheless **public** on `GET /admin/audit`, so section 0.6.1 excludes it from the stability contract: values are not comparable between event types and may change without a major bump. Clients MUST NOT threshold or rank on it. |
| **Progressive login delays** | Not implemented. Rate limiting is fixed-window and fails closed on the authentication endpoints, and account lockout is absolute. Backoff has no public API surface -- it changes latency and `Retry-After` values, both already in the contract -- so adding it later is compatible. |
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
