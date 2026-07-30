# Configuration Reference

> Vault42 -- Environment Variables & Configuration

## Overview

Vault42 is configured entirely through environment variables. There are no configuration files, command-line flags, or admin UIs for configuration.

Three mechanisms work together:

1. **Environment variables** -- all settings are read from env vars at startup.
2. **Profiles** -- preset defaults for production, dev, and embedded deployments. The profile is selected via `VAULT_PROFILE` and fills in any env vars you did not set.
3. **`_FILE` convention for secrets** -- sensitive values are never placed directly in env vars. Instead, a `_FILE`-suffixed variable points to a file containing the secret. The file is read into memory; with `VAULT_SECRET_FILE_CONSUME=true` it is then zeroed and removed from disk (opt-in, off by default).

The startup sequence is: read env vars, apply profile defaults for unset fields, load secrets from `_FILE` paths.

---

## Profiles

Four profiles provide sensible defaults so you only need to set the variables that differ from the baseline. An unrecognized profile value falls back to production.

### Production (`VAULT_PROFILE=production`, default)

The full-security baseline. Expects external PostgreSQL and Redis, TLS enabled, strict CORS, and all secrets provided via `_FILE` mounts.

### Dev (`VAULT_PROFILE=dev`)

Dev **extends production** -- it applies all production defaults first, then overrides a small set of values for local development convenience. TLS, rate limits, listen address, and cache backend are all inherited from production unless you explicitly override them.

### Embedded (`VAULT_PROFILE=embedded`)

Tuned for resource-constrained environments such as a Raspberry Pi 5. Uses in-memory cache, fewer database connections, and auto-migration. Target memory footprint: ~60-80 MB.

### Honeypot (`VAULT_PROFILE=honeypot`)

A deception deployment that mimics a real Vault42 instance to detect and alert on unauthorized access attempts. Extends production defaults with debug logging, auto-migration, and the embedded frontend enabled by default. Pairs with `VAULT_HONEYPOT_WEBHOOK` and `VAULT_HONEYPOT_TRAP_USERS` to send alerts when attackers interact with the honeypot.

### Profile Comparison

| Setting | Production | Dev | Embedded | Honeypot |
|---------|-----------|-----|----------|----------|
| `ListenAddr` | `:8443` | `:8443` (inherited) | `:8443` | `:8443` |
| `LogLevel` | `warn` | `debug` | `info` | `debug` |
| `TLSEnabled` | `true` | `true` (inherited) | `true` | `true` |
| `RateLimitEnabled` | `true` | `true` (inherited, overridable) | `true` | `true` |
| `AutoMigrate` | `false` | `true` | `true` | `true` |
| `CORSAllowAll` | `false` (forced) | `true` | `false` | `false` |
| `CacheBackend` | `redis` | `redis` (inherited) | `memory` | `redis` |
| `DBMaxConns` | `25` | `25` (inherited) | `5` | `25` |
| `ServeFrontend` | `false` | `false` (inherited) | `false` | `true` |
| `DBSSLMode` (effective) | `require` | `disable` (forced in `DatabaseURL()`) | `require` | `require` |
| `AccessTokenTTL` | `15m` | `15m` (inherited) | `15m` | `15m` |
| `RefreshTokenTTL` | `7d` (168h) | `24h` | `24h` | `7d` (168h) |
| `RememberMeTTL` | `30d` (720h) | `30d` (inherited) | `30d` | `30d` (720h) |
| `ShutdownTimeout` | `15s` | `5s` | `5s` | `15s` |
| `AuditFlushInterval` | *unset (0)* | *unset (0)* | `30s` | *unset (0)* |

Note: In the dev profile, if you explicitly set an env var (e.g., `LOG_LEVEL=info`), the explicit value takes precedence over the dev override. The dev profile only overrides values that were left unset. Exception: `VAULT_AUTO_MIGRATE` is unconditionally set to `true` in dev and cannot be overridden via env var.

---

## Environment Variables

### Core

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_PROFILE` | string | `production` | No | Deployment profile: `production`, `dev`, `embedded`, or `honeypot`. Controls defaults for all unset variables. |
| `LISTEN_ADDR` | string | `:8443` | No | Address and port the server binds to. Set by profile if unset. |
| `VAULT_ORIGIN` | string | *(none)* | Yes | Public-facing URL (e.g., `https://auth.example.com`). Used for CORS `Access-Control-Allow-Origin`, JWT issuer claim, cookie domain, and WebAuthn RP ID. |
| `LOG_LEVEL` | string | `warn` | No | Log verbosity. Profile defaults: `warn` (production), `debug` (dev), `info` (embedded). |
| `VAULT_APP_NAME` | string | `The Vault` | No | Application display name used in email templates, the WebAuthn RP name, and UI. |
| `VAULT_LOGO_URL` | string | *(none)* | No | URL to application logo for email templates. |
| `VAULT_PRIMARY_COLOR` | string | `#00FF42` | No | Primary branding color hex code for email templates. |
| `VAULT_AUTO_MIGRATE` | bool | `false` | No | Run database migrations automatically at startup. Profile defaults: `false` (production), `true` (dev, embedded). |
| `VAULT_SHUTDOWN_TIMEOUT` | duration | `15s` | No | Maximum wait time for in-flight requests during graceful shutdown. **Profile-only** -- not loaded from env vars, set only by profile defaults (15s production, 5s dev/embedded). |
| `VAULT_SERVE_FRONTEND` | bool | `false` | No | Serve the embedded Vue SPA from the Go binary. Default: `false` (secure by default). Honeypot profile enables this by default. |
| `VAULT_EMAIL_TEMPLATES_DIR` | string | *(none)* | No | Directory containing custom HTML email templates to override embedded defaults. |
| `VAULT_AUDIT_FLUSH_INTERVAL` | duration | `0` | No | Interval for flushing buffered audit log entries. `0` disables batching (immediate flush). **Profile-only** -- not loaded from env vars, set to `30s` in embedded profile. |
| `VAULT_AUDIT_BUFFER_SIZE` | int | `1000` | No | Maximum number of audit entries buffered before new entries are dropped. Only relevant when `VAULT_AUDIT_FLUSH_INTERVAL > 0`. |

### TLS

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_TLS_ENABLED` | bool | `true` | No | Enable HTTPS. Set by profile if unset. When `true`, `VAULT_TLS_CERT_FILE` and `VAULT_TLS_KEY_FILE` are required. **Note**: Due to Go zero-value semantics, setting this to `false` via env var has no effect -- all profiles default it to `true` and `setDefaultBool` cannot distinguish "unset" from "explicitly false". To disable TLS, modify the profile code. |
| `VAULT_TLS_CERT_FILE` | string | *(none)* | Conditional | Path to TLS certificate PEM file. Required when `VAULT_TLS_ENABLED=true`. |
| `VAULT_TLS_KEY_FILE` | string | *(none)* | Conditional | Path to TLS private key PEM file. Required when `VAULT_TLS_ENABLED=true`. |

Note: The secure cookie flag (`Secure`) is derived from `TLSEnabled`, not from the profile name. If TLS is enabled, cookies are marked `Secure`.

### Database

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `DB_HOST` | string | `localhost` | No | PostgreSQL hostname. |
| `DB_PORT` | string | `5432` | No | PostgreSQL port. |
| `DB_NAME` | string | `vault` | No | PostgreSQL database name. |
| `DB_SSLMODE` | string | `require` | No | PostgreSQL SSL mode (`require`, `verify-full`, `disable`). In the dev profile, `DatabaseURL()` forces this to `disable` regardless of the configured value. |
| `DB_MAX_CONNS` | int | `0` (profile sets) | No | Maximum database connections. Profile defaults: `25` (production/dev), `5` (embedded). |
| `DB_MIG_PASSWORD_FILE` | string | *(none)* | Yes | Path to file containing the `vault_mig` role password. Used for schema migrations at startup. See [Secret Loading](#secret-loading-_file-convention). |
| `DB_APP_PASSWORD_FILE` | string | *(none)* | Yes | Path to file containing the `vault_app` role password. Used for all runtime queries. See [Secret Loading](#secret-loading-_file-convention). |

The application uses two PostgreSQL roles with least-privilege separation:
- **`vault_mig`** -- DDL privileges for migrations only. Connection is closed after migrations complete.
- **`vault_app`** -- SELECT/INSERT/UPDATE on `auth` schema, INSERT/SELECT only on `audit` schema. No DELETE, no TRUNCATE, no DDL.

### JWT / Token

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_ACCESS_TOKEN_TTL` | duration | `0` (profile sets `15m`) | No | Lifetime of RS256 JWT access tokens. Profile default: `15m`. Valid range: typically 5m-15m. |
| `VAULT_REFRESH_TOKEN_TTL` | duration | `0` (profile sets) | No | Lifetime of refresh tokens. Profile defaults: `168h` / 7 days (production), `24h` (dev, embedded). |
| `VAULT_REMEMBER_ME_TTL` | duration | `0` (profile sets `720h`) | No | Extended refresh token lifetime when "remember me" is selected. Profile default: `720h` (30 days). |

Duration values use Go's `time.ParseDuration` format: `5m`, `1h`, `24h`, `168h`, `720h`, etc.

Access tokens are RS256-signed JWTs with fingerprint binding. Refresh tokens are stored hashed (SHA256) in PostgreSQL with single-use rotation and family-based replay detection.

### Security

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `MASTER_KEY_FILE` | string | *(none)* | Yes | Path to file containing the AES-256 master key (exactly 32 bytes). Used for encrypting TOTP secrets at rest. See [Secret Loading](#secret-loading-_file-convention). |
| `ADMIN_TOKEN_FILE` | string | *(none)* | Recommended | Path to file containing the Argon2id hash of the admin CLI token. Required for CLI commands (`add-client`, `rotate-jwks`, etc.). |
| `VAULT_PEPPER_FILE` | string | *(none)* | Recommended | Path to file containing the server-side pepper added to password hashes before Argon2id. Must be at least 32 bytes in non-dev profiles (startup fails otherwise). |
| `HMAC_SECRET_FILE` | string | *(none)* | Yes | Path to file containing the HMAC-SHA256 signing key. Must be at least 32 bytes in production/embedded profiles. Dev profile logs a warning for shorter keys. |
| `SIGNING_KEY_FILE` | string | *(none)* | Conditional | Path to RSA-2048 private key (PKCS#8 PEM) for JWT signing. Shared across all pods for horizontal scaling. Without this, each pod generates an ephemeral key (single-pod only). Required for multi-pod deployments. Generated by `scripts/generate-secrets.sh`. |
| `VAULT_PASSWORD_MIN_LENGTH` | int | `15` | No | Minimum password length per NIST SP 800-63B Rev 4. No composition rules enforced. |
| `VAULT_HIBP_CHECK` | bool | `true` | No | Enable Have I Been Pwned breach checking for passwords at registration and password change. |
| `VAULT_MFA_REQUIRED` | bool | `true` | No | Force all users to set up two-factor authentication. Set to `false` to make 2FA optional. |
| `VAULT_REGISTRATION_ENABLED` | bool | `true` | No | Enable public user registration via `POST /auth/register`. When `false`, the endpoint returns 403 `registration_disabled`. Use with `VAULT_SEED_FILE` for sealed deployments where all users are pre-provisioned. |
| `VAULT_MAX_SESSIONS_PER_USER` | int | `10` | No | Maximum concurrent refresh token families per user. Oldest sessions are revoked when the limit is exceeded. |
| `VAULT_RATE_LIMIT_ENABLED` | bool | `true` | No | Enable rate limiting on authentication endpoints. Defaults to `true`; in non-dev profiles startup refuses to run with it disabled unless `VAULT_ALLOW_RATE_LIMIT_DISABLED=true`. |
| `VAULT_ALLOW_RATE_LIMIT_DISABLED` | bool | `false` | No | Escape hatch to run a non-dev profile with rate limiting disabled (e.g. when an upstream gateway handles it). Without it, disabling rate limiting fails startup. |
| `VAULT_DPOP_ENABLED` | bool | `false` | No | Enable DPoP (Demonstrating Proof-of-Possession) validation on token endpoints per RFC 9449. When enabled, the DPoP middleware validates proof headers on `/auth/login`, `/auth/refresh`, the 2FA verify endpoints, and the `POST /kms/unwrap` key-release oracle (single-use anti-replay). |
| `KMS_ROOT_KEY_FILE` | string | *(none)* | No | Path to a file containing the KMS root secret (at least 32 bytes). Per-kid KEKs are derived from it via HKDF-SHA256, kept cryptographically separate from the master key. When unset, the `POST /kms/unwrap` envelope-unwrap oracle is not mounted. See [Secret Loading](#secret-loading-_file-convention). |
| `VAULT_FORCE_SECURE_COOKIES` | bool | `false` | No | Force the `Secure` flag on cookies even when TLS is not enabled locally. Useful when running behind a TLS-terminating proxy (e.g., Cloudflare Tunnel, nginx with TLS offloading). |
| `TRUSTED_PROXIES` | string | *(none)* | No | Comma-separated list of CIDR ranges or IPs trusted to set `X-Forwarded-For` (e.g., `10.0.0.0/8,172.16.0.0/12`). |
| `REAL_IP_HEADER` | string | *(none)* | No | HTTP header containing the real client IP from a trusted proxy. Only read when the direct connection is from a trusted proxy. Examples: `CF-Connecting-IP` (Cloudflare), `X-Real-IP` (nginx). Empty = use XFF parsing only. |
| `VAULT_TLS_FINGERPRINT_HEADER` | string | *(none)* | No | HTTP header containing the client's TLS fingerprint (e.g. JA4) set by the TLS-terminating proxy. Since Vault42 runs behind a reverse proxy, it cannot compute TLS fingerprints directly; the proxy must extract the fingerprint during the TLS handshake and pass it as a header. The value is included in the device fingerprint hash. Empty = TLS fingerprint field remains empty (backward compatible). Example: `X-TLS-Fingerprint`. |

### IP Access Control & Geo-Fencing

Optional IP-based access control and geographic restrictions. All lists are empty by default (no restrictions). Requires `TRUSTED_PROXIES` to be set for accurate client IP resolution.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `IP_ALLOWLIST` | string | *(none)* | No | Comma-separated CIDR/IP list. When set, only matching IPs are allowed. |
| `IP_BLOCKLIST` | string | *(none)* | No | Comma-separated CIDR/IP list. Matching IPs are denied (403). Evaluated after allowlist. |
| `GEO_IP_HEADER` | string | *(none)* | No | HTTP header containing the client's ISO 3166-1 alpha-2 country code. Examples: `CF-IPCountry` (Cloudflare), `X-Geo-Country` (custom). Empty = geo-fencing disabled. |
| `GEO_ALLOWLIST` | string | *(none)* | No | Comma-separated country codes. When set, only matching countries are allowed. Requires `GEO_IP_HEADER`. |
| `GEO_BLOCKLIST` | string | *(none)* | No | Comma-separated country codes. Matching countries are denied (403). Requires `GEO_IP_HEADER`. Use `T1` for Tor exit nodes (Cloudflare). |

The IP blocklist supports runtime updates via `AddToIPBlocklist()` / `RemoveFromIPBlocklist()`: atomic copy-on-write, zero read contention.

**Evaluation order:** IP allowlist → IP blocklist → Geo allowlist → Geo blocklist. Health endpoints (`/healthz`, `/readyz`) bypass all checks.

### CORS

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `CORS_ORIGINS` | string | *(none)* | Conditional | Comma-separated list of allowed CORS origins. Required in production (since `CORS_ALLOW_ALL` is forced off). |
| `CORS_ALLOW_ALL` | bool | `false` | No | Permit all CORS origins. **Forced off in production**. In dev profile, defaults to `true` unless the `CORS_ALLOW_ALL` env var is set to any non-empty value (presence check, not boolean parsing). |

### Cache

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `CACHE_BACKEND` | string | *(profile sets)* | No | Cache implementation: `redis`, `memory`, or `postgres`. Profile defaults: `redis` (production/dev), `memory` (embedded). |
| `REDIS_ADDR` | string | *(none)* | Conditional | Redis server address (e.g., `redis:6379`). Required when `CACHE_BACKEND=redis`. |
| `REDIS_PASS_FILE` | string | *(none)* | No | Path to file containing the Redis password. See [Secret Loading](#secret-loading-_file-convention). |

Cache degradation is graceful -- authentication never fails because the cache is down. The system falls back to database lookups.

### Email

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_EMAIL_PROVIDER` | string | `smtp` | No | Email sending backend: `smtp` or `sendgrid`. Both adapters are implemented. SendGrid uses stdlib `net/http` (no SDK dependency). |
| `SMTP_HOST` | string | *(none)* | Conditional | SMTP server hostname. Required when `VAULT_EMAIL_PROVIDER=smtp`. |
| `SMTP_PORT` | string | `587` | No | SMTP server port. |
| `SMTP_USER_FILE` | string | *(none)* | No | Path to file containing the SMTP username. See [Secret Loading](#secret-loading-_file-convention). |
| `SMTP_PASS_FILE` | string | *(none)* | Conditional | Path to file containing the SMTP password. See [Secret Loading](#secret-loading-_file-convention). |
| `VAULT_EMAIL_FROM` | string | *(none)* | Yes | Sender address for outgoing emails (e.g., `noreply@example.com`). |
| `SENDGRID_API_KEY_FILE` | string | *(none)* | Conditional | Path to file containing the SendGrid API key. Required when `VAULT_EMAIL_PROVIDER=sendgrid`. See [Secret Loading](#secret-loading-_file-convention). |

### Honeypot

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_HONEYPOT_WEBHOOK` | string | *(none)* | No | URL to POST honeypot alerts to. Only used when `VAULT_PROFILE=honeypot`. |
| `VAULT_HONEYPOT_TRAP_USERS` | string | *(none)* | No | Comma-separated list of fake usernames/emails that trigger honeypot alerts. |

### Bridge (Honeypot Bridge Proxy)

The bridge is a separate binary (`cmd/bridge/`) that sits in front of two Vault42 instances. See [Bridge Deployment Guide](bridge.md) for full documentation.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `BRIDGE_LISTEN_ADDR` | string | `:8080` | No | Listen address for the bridge proxy. |
| `BRIDGE_REAL_UPSTREAM` | string | *(none)* | Yes | URL of the real Vault42 service. |
| `BRIDGE_HONEYPOT_UPSTREAM` | string | *(none)* | Yes | URL of the honeypot Vault42 service. |
| `BRIDGE_RATE_THRESHOLD` | int | `60` | No | Requests per window before scoring begins. |
| `BRIDGE_RATE_WINDOW` | duration | `1m` | No | Sliding window for rate counting. |
| `BRIDGE_LOGIN_FAIL_THRESHOLD` | int | `5` | No | Failed logins before scoring begins. |
| `BRIDGE_LOGIN_FAIL_WINDOW` | duration | `15m` | No | Sliding window for login failure counting. |
| `BRIDGE_FLAG_TTL` | duration | `24h` | No | How long a flagged IP stays routed to honeypot. |
| `BRIDGE_FLAG_THRESHOLD` | int | `100` | No | Cumulative score threshold to trigger flagging. |
| `BRIDGE_WEBHOOK_URL` | string | *(none)* | No | Optional webhook URL for flag event notifications. |
| `BRIDGE_ADMIN_TOKEN_FILE` | string | *(none)* | No | Path to file containing the admin API bearer token (`_FILE` convention). |
| `BRIDGE_REDIS_ADDR` | string | *(none)* | No | Optional Redis address for persistent flag storage. |
| `BRIDGE_TRUSTED_PROXIES` | string | *(none)* | No | Comma-separated CIDR ranges for proxy IP detection. |
| `BRIDGE_REAL_IP_HEADER` | string | *(none)* | No | Header from trusted proxy containing real client IP (e.g., `CF-Connecting-IP`). |
| `BRIDGE_LOG_LEVEL` | string | `info` | No | Log level (`info`, `debug`). |

### Metrics & Observability

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_METRICS_ENABLED` | bool | `false` | No | Enable the Prometheus-compatible `/metrics` endpoint. Exposes operational counters (argon2 semaphore, login, token). Protect with Kubernetes NetworkPolicy in production. |

### Blob Storage

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_BLOB_MIN_SIZE` | int | `0` (disabled) | No | Minimum single blob size in bytes. Blobs smaller than this are rejected. `0` disables the minimum check (empty blobs are still rejected). |
| `VAULT_BLOB_MAX_SIZE` | int | `10485760` (10MB) | No | Maximum single blob size in bytes. Blobs larger than this are rejected. |
| `VAULT_BLOB_MAX_PER_USER` | int | `50` | No | Maximum number of blobs per user. |
| `VAULT_BLOB_QUOTA_BYTES` | int | `10485760` (10MB) | No | Total storage quota per user in bytes. Set to `0` to disable the blob storage feature entirely. |

### Account Erasure & Recovery Escrow

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_RECOVERY_PUBLIC_KEY_FILE` | string | *(none)* | No | Path to an RSA **public** key (PEM) that account erasure encrypts recovery records to. When set, every erasure first appends one record to `auth.account_recovery` holding the erased user's email, account creation date, roles and display name, encrypted to this key, and the erasure is refused if that write fails. The service holds only the public half, so it can write a record but never read one back; decryption needs the private key, which is kept offline and used by `cmd/recover`. When unset, no escrow record is written and erasure is final at the moment the cascade completes -- startup logs a warning so the choice is deliberate. Enabling it means retaining personal data past an erasure request: set `VAULT_RECOVERY_RETENTION_DAYS` too, and disclose it in the end-user privacy notice (see `docs/PRIVACY.md` §3.1, §4, §5.3). |
| `VAULT_RECOVERY_RETENTION_DAYS` | int (days) | `0` (disabled) | No | Retention horizon for account-recovery escrow records. A background sweeper runs at startup and every 6h, deleting records older than this. The escrow is append-only and exempt from the erasure cascade, so GDPR Art. 5(1)(e) is what caps its lifetime -- an Operator that configures a recovery key should set a horizon covering the window in which a mistaken or malicious deletion would still be noticed and reversed. Left at `0`, nothing is ever purged: the escrow holds the only recoverable copy of an erased account, so destroying it is an explicit operator choice. `vault cleanup-recovery --retention-days N` performs the same purge on demand, and is the only other supported removal path (both application roles have DELETE revoked on the table). |

### Seeding

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_SEED_FILE` | string | *(none)* | No | Path to a JSON file for declarative client and user seeding at startup. When set, the file is loaded and processed idempotently after `InitAdminToken` and before the CLI check. Existing entries (matched by client name or user email) are skipped. Client secrets are generated and printed to stdout. See `seed.example.json` for the file format. |

### Key Rotation

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_KEY_ROTATION_DB` | bool | `false` | No | Enable database-backed signing key storage and rotation. When `false` (default), the existing file-based `SIGNING_KEY_FILE` behavior is used. |
| `VAULT_KEY_RETENTION_PERIOD` | duration | `1h` | No | How long retired signing keys remain in JWKS after rotation. Tokens signed with retired keys are still validated during this window. |
| `VAULT_AUDIT_RETENTION_DAYS` | int (days) | `0` (disabled) | No | Retention horizon for audit entries. A background sweeper runs at startup and every 6h, deleting entries older than this. Audit rows hold personal data (user ID, IP, user agent, fingerprint hash), so GDPR Art. 5(1)(e) caps how long they may be kept — an Operator processing personal data should set this. Left at `0`, nothing is ever purged: silently deleting security logs is not a safe default. `vault cleanup-audit --retention-days N` performs the same purge on demand. |
| `VAULT_KEY_REFRESH_INTERVAL` | duration | `60s` | No | How often pods refresh signing keys from the database. Lower values provide faster rotation propagation at the cost of more DB queries. |

When `VAULT_KEY_ROTATION_DB=true`, signing keys are stored encrypted (AES-256-GCM with master key) in PostgreSQL. On first boot, if `SIGNING_KEY_FILE` is present, the key is imported into the database; otherwise, a new RSA-2048 key is generated. All pods share the same keys via periodic database polling. Runtime key management (rotate, list, revoke) is performed via the admin gateway (`cmd/admin-gateway/`), which provides mTLS + RBAC + session authentication. CLI admin commands remain available via pod exec.

### OAuth2

All OAuth2 providers are optional. Configure only the providers you want to support. PKCE S256 is enforced on all flows with strict redirect URI matching (no wildcards).

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_OAUTH_GOOGLE_CLIENT_ID` | string | *(none)* | No | Google OAuth2 client ID. |
| `VAULT_OAUTH_GOOGLE_CLIENT_SECRET_FILE` | string | *(none)* | Conditional | Path to file containing the Google OAuth2 client secret. Required if Google client ID is set. |
| `VAULT_OAUTH_GITHUB_CLIENT_ID` | string | *(none)* | No | GitHub OAuth2 client ID. |
| `VAULT_OAUTH_GITHUB_CLIENT_SECRET_FILE` | string | *(none)* | Conditional | Path to file containing the GitHub OAuth2 client secret. Required if GitHub client ID is set. |
| `VAULT_OAUTH_FACEBOOK_CLIENT_ID` | string | *(none)* | No | Facebook OAuth2 client ID. |
| `VAULT_OAUTH_FACEBOOK_CLIENT_SECRET_FILE` | string | *(none)* | Conditional | Path to file containing the Facebook OAuth2 client secret. Required if Facebook client ID is set. |

#### Generic OpenID Connect providers

Beyond the built-in social providers above, any standard OpenID Connect issuer
(Okta, Auth0, Keycloak, Microsoft Entra, …) can be registered. ID tokens are
verified against the issuer's JWKS (RS256/384/512 only; `alg=none`, HMAC, and
embedded-key headers are rejected), bound to the authorize-time nonce, and the
`iss`/`aud`/`exp` claims are checked. A provider missing an issuer or client ID
is skipped at startup.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_OIDC_PROVIDERS` | string | *(none)* | No | Comma-separated provider names to enable (e.g. `okta,keycloak`). Each name maps to its own callback at `/auth/oauth2/callback/<name>`. |
| `VAULT_OIDC_<NAME>_ISSUER` | string | *(none)* | Conditional | Issuer base URL; discovery uses `{issuer}/.well-known/openid-configuration`. |
| `VAULT_OIDC_<NAME>_CLIENT_ID` | string | *(none)* | Conditional | OIDC client ID for `<NAME>`. |
| `VAULT_OIDC_<NAME>_CLIENT_SECRET_FILE` | string | *(none)* | Conditional | Path to file containing the client secret (or inline via `VAULT_OIDC_<NAME>_CLIENT_SECRET`). |
| `VAULT_OIDC_<NAME>_SCOPES` | string | `openid email profile` | No | Space-separated scopes to request. |

### WebAuthn

WebAuthn/FIDO2 passkey configuration is derived from other settings rather than having its own env vars:

- **RP ID** (Relying Party Identifier) -- extracted as the hostname from `VAULT_ORIGIN`.
- **RP Origin** -- the full `VAULT_ORIGIN` value.
- **RP Display Name** -- the `VAULT_APP_NAME` value.

If `VAULT_ORIGIN` is unset or unparseable, RP ID falls back to `localhost`.

---

## Secret Loading (`_FILE` Convention)

All sensitive configuration values use the `_FILE` suffix convention. The env var contains a **file path**, not the secret itself. At startup, Vault42:

1. Reads the env var (e.g., `MASTER_KEY_FILE=/run/secrets/master-key`).
2. Reads the file at that path.
3. Trims leading/trailing whitespace from the contents.
4. If `VAULT_SECRET_FILE_CONSUME=true`, zeros **and removes** the file (defense in depth). By default the file is left intact: the canonical deployment mounts secrets read-only where zeroing is a no-op, and on a writable real keyfile an unconditional wipe would destroy the operator's secret on first read.
5. Stores the value in memory only.

This design ensures secrets never appear in environment variable listings (`/proc/*/environ`, `docker inspect`, Kubernetes `kubectl describe pod`, etc.).

`VAULT_SECRET_FILE_CONSUME` (bool, default `false`): when `true`, every `_FILE` secret is zeroed and deleted from disk after it is read. Leave it unset when the same keyfile must survive a restart.

### Variables with `_FILE` Variants

| Secret Variable | Env Var (file path) | Description |
|----------------|---------------------|-------------|
| Master Key | `MASTER_KEY_FILE` | AES-256 key (32 bytes) for TOTP secret encryption |
| Admin Token | `ADMIN_TOKEN_FILE` | Argon2id hash of the admin CLI token |
| Pepper | `VAULT_PEPPER_FILE` | Server-side secret added to password hashes |
| HMAC Secret | `HMAC_SECRET_FILE` | HMAC-SHA256 signing key (min 32 bytes in production) |
| Signing Key | `SIGNING_KEY_FILE` | RSA-2048 private key (PKCS#8 PEM) for JWT signing |
| Recovery Public Key | `VAULT_RECOVERY_PUBLIC_KEY_FILE` | RSA **public** key (PEM) that account-erasure recovery records are encrypted to |
| DB Migration Password | `DB_MIG_PASSWORD_FILE` | Password for the `vault_mig` PostgreSQL role |
| DB App Password | `DB_APP_PASSWORD_FILE` | Password for the `vault_app` PostgreSQL role |
| Redis Password | `REDIS_PASS_FILE` | Redis authentication password |
| SMTP User | `SMTP_USER_FILE` | SMTP authentication username |
| SMTP Password | `SMTP_PASS_FILE` | SMTP authentication password |
| Google OAuth Secret | `VAULT_OAUTH_GOOGLE_CLIENT_SECRET_FILE` | Google OAuth2 client secret |
| GitHub OAuth Secret | `VAULT_OAUTH_GITHUB_CLIENT_SECRET_FILE` | GitHub OAuth2 client secret |
| SendGrid API Key | `SENDGRID_API_KEY_FILE` | SendGrid API key for email sending |
| Facebook OAuth Secret | `VAULT_OAUTH_FACEBOOK_CLIENT_SECRET_FILE` | Facebook OAuth2 client secret |

**Important**: There is no way to set these values directly via env vars (e.g., there is no `MASTER_KEY` env var -- only `MASTER_KEY_FILE`). This is intentional.

---

## Example Configurations

### Minimal Development

The dev profile inherits production defaults and overrides only what is needed for local work. In a Kubernetes dev environment, `scripts/deploy-dev.sh` handles all of this automatically.

```bash
export VAULT_PROFILE=dev
export VAULT_ORIGIN=https://vault.localhost
export VAULT_TLS_ENABLED=true
export VAULT_TLS_CERT_FILE=/etc/vault42-tls/tls.crt
export VAULT_TLS_KEY_FILE=/etc/vault42-tls/tls.key

# Database (dev profile forces sslmode=disable)
export DB_HOST=vault42-postgres
export DB_PORT=5432
export DB_NAME=vault42

# Secrets (mounted from Kubernetes Secret)
export MASTER_KEY_FILE=/run/secrets/master-key
export DB_MIG_PASSWORD_FILE=/run/secrets/db-mig-password
export DB_APP_PASSWORD_FILE=/run/secrets/db-app-password
export HMAC_SECRET_FILE=/run/secrets/hmac-secret
export ADMIN_TOKEN_FILE=/run/secrets/admin-token

# Cache
export CACHE_BACKEND=redis
export REDIS_ADDR=vault42-redis:6379
export REDIS_PASS_FILE=/run/secrets/redis-password

# Email (Mailpit for local testing)
export SMTP_HOST=vault42-mailpit
export SMTP_PORT=1025
export VAULT_EMAIL_FROM=vault42@localhost
```

### Production

Production requires explicit CORS origins, TLS (typically terminated at ingress), Redis cache, and all secrets mounted from a secrets manager.

```bash
export VAULT_PROFILE=production
export LISTEN_ADDR=:8080
export VAULT_ORIGIN=https://auth.example.com
export LOG_LEVEL=warn

# TLS -- all profiles default to enabled.
# To disable (e.g., TLS terminated at ingress), modify the profile code.
# export VAULT_TLS_ENABLED=false  # has no effect due to setDefaultBool limitation

# Database
export DB_HOST=postgres.internal
export DB_PORT=5432
export DB_NAME=vault42
export DB_SSLMODE=verify-full
export DB_MAX_CONNS=25

# Secrets (from mounted Kubernetes Secret or secrets manager)
export MASTER_KEY_FILE=/run/secrets/master-key
export DB_MIG_PASSWORD_FILE=/run/secrets/db-mig-password
export DB_APP_PASSWORD_FILE=/run/secrets/db-app-password
export HMAC_SECRET_FILE=/run/secrets/hmac-secret
export ADMIN_TOKEN_FILE=/run/secrets/admin-token
export VAULT_PEPPER_FILE=/run/secrets/pepper

# Cache
export CACHE_BACKEND=redis
export REDIS_ADDR=redis.internal:6379
export REDIS_PASS_FILE=/run/secrets/redis-password

# CORS (explicit origins, CORS_ALLOW_ALL is forced off)
export CORS_ORIGINS=https://app.example.com,https://admin.example.com

# Token TTLs (using defaults: 15m access, 7d refresh, 30d remember-me)

# Email
export VAULT_EMAIL_PROVIDER=smtp
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_USER_FILE=/run/secrets/smtp-user
export SMTP_PASS_FILE=/run/secrets/smtp-pass
export VAULT_EMAIL_FROM=noreply@example.com

# Security
export VAULT_PASSWORD_MIN_LENGTH=15
export VAULT_HIBP_CHECK=true
export VAULT_RATE_LIMIT_ENABLED=true
export VAULT_MAX_SESSIONS_PER_USER=10
export TRUSTED_PROXIES=10.0.0.0/8

# OAuth2 (optional -- configure only enabled providers)
export VAULT_OAUTH_GOOGLE_CLIENT_ID=123456.apps.googleusercontent.com
export VAULT_OAUTH_GOOGLE_CLIENT_SECRET_FILE=/run/secrets/google-oauth-secret
```

### Embedded (Raspberry Pi 5)

Minimal resource footprint with in-memory cache and fewer database connections. Auto-migration enabled for single-node deployments.

```bash
export VAULT_PROFILE=embedded
export VAULT_ORIGIN=https://vault42.local
export VAULT_TLS_ENABLED=true
export VAULT_TLS_CERT_FILE=/etc/vault42/tls.crt
export VAULT_TLS_KEY_FILE=/etc/vault42/tls.key

# Database (5 connections, sslmode=require)
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=vault42

# Secrets
export MASTER_KEY_FILE=/etc/vault42/secrets/master-key
export DB_MIG_PASSWORD_FILE=/etc/vault42/secrets/db-mig-password
export DB_APP_PASSWORD_FILE=/etc/vault42/secrets/db-app-password
export HMAC_SECRET_FILE=/etc/vault42/secrets/hmac-secret
export ADMIN_TOKEN_FILE=/etc/vault42/secrets/admin-token

# Cache (in-memory, no Redis needed)
# CACHE_BACKEND defaults to "memory" in embedded profile

# Email
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_PASS_FILE=/etc/vault42/secrets/smtp-pass
export VAULT_EMAIL_FROM=vault42@example.com
```

### Honeypot

A deception deployment that logs all interactions and alerts on suspicious activity. Designed to be internet-facing alongside (or instead of) the real Vault42 instance.

```bash
export VAULT_PROFILE=honeypot
export VAULT_ORIGIN=https://auth.decoy.example.com
export VAULT_TLS_ENABLED=true
export VAULT_TLS_CERT_FILE=/etc/vault42-tls/tls.crt
export VAULT_TLS_KEY_FILE=/etc/vault42-tls/tls.key

# Database
export DB_HOST=honeypot-postgres
export DB_PORT=5432
export DB_NAME=vault42

# Secrets
export MASTER_KEY_FILE=/run/secrets/master-key
export DB_MIG_PASSWORD_FILE=/run/secrets/db-mig-password
export DB_APP_PASSWORD_FILE=/run/secrets/db-app-password
export HMAC_SECRET_FILE=/run/secrets/hmac-secret
export ADMIN_TOKEN_FILE=/run/secrets/admin-token

# Cache
export CACHE_BACKEND=redis
export REDIS_ADDR=honeypot-redis:6379
export REDIS_PASS_FILE=/run/secrets/redis-password

# Honeypot-specific
export VAULT_HONEYPOT_WEBHOOK=https://alerts.example.com/honeypot
export VAULT_HONEYPOT_TRAP_USERS=admin,root,administrator,sa,test,user

# Email (Mailpit or discard, never send real emails from a honeypot)
export SMTP_HOST=honeypot-mailpit
export SMTP_PORT=1025
export VAULT_EMAIL_FROM=vault42@decoy.example.com
```

---

## Kubernetes / Helm Configuration

When deployed via the Helm chart (`charts/vault42/`), environment variables are set through two mechanisms:

1. **ConfigMap** (non-sensitive values) -- generated from `values.yaml` fields like `profile`, `listenAddr`, `origin`, etc. These map directly to the env vars documented above.
2. **Secret volume mounts** (sensitive values) -- a Kubernetes Secret is mounted at `secrets.mountPath` (default: `/run/secrets`), and `_FILE` env vars point to the individual files within it.

Key Helm values and their corresponding env vars:

| Helm Value | Env Var |
|-----------|---------|
| `profile` | `VAULT_PROFILE` |
| `listenAddr` | `LISTEN_ADDR` |
| `origin` | `VAULT_ORIGIN` |
| `appName` | `VAULT_APP_NAME` |
| `autoMigrate` | `VAULT_AUTO_MIGRATE` |
| `rateLimitEnabled` | `VAULT_RATE_LIMIT_ENABLED` |
| `tls.enabled` | `VAULT_TLS_ENABLED` |
| `tls.certFile` | `VAULT_TLS_CERT_FILE` |
| `tls.keyFile` | `VAULT_TLS_KEY_FILE` |
| `passwordMinLength` | `VAULT_PASSWORD_MIN_LENGTH` |
| `hibpCheck` | `VAULT_HIBP_CHECK` |
| `emailFrom` | `VAULT_EMAIL_FROM` |
| `database.host` | `DB_HOST` |
| `database.port` | `DB_PORT` |
| `database.name` | `DB_NAME` |
| `database.sslmode` | `DB_SSLMODE` |
| `database.maxConns` | `DB_MAX_CONNS` |
| `cache.backend` | `CACHE_BACKEND` |
| `redis.addr` | `REDIS_ADDR` |
| `smtp.host` | `SMTP_HOST` |
| `smtp.port` | `SMTP_PORT` |
| `tlsFingerprintHeader` | `VAULT_TLS_FINGERPRINT_HEADER` |
| `seed.enabled` | `VAULT_SEED_FILE` (set to `/etc/vault42/seed.json` when enabled) |

Secrets are mapped via `secrets.keys.*`:

| Helm Secret Key | Env Var |
|----------------|---------|
| `secrets.keys.masterKey` | `MASTER_KEY_FILE` |
| `secrets.keys.dbMigPassword` | `DB_MIG_PASSWORD_FILE` |
| `secrets.keys.dbAppPassword` | `DB_APP_PASSWORD_FILE` |
| `secrets.keys.hmacSecret` | `HMAC_SECRET_FILE` |
| `secrets.keys.adminToken` | `ADMIN_TOKEN_FILE` |
| `secrets.keys.redisPassword` | `REDIS_PASS_FILE` |

See `charts/vault42/values.yaml` for production defaults and `charts/vault42/values-dev.yaml` for the dev overlay.

**Minimum resource requirements (production):** Memory limit must be at least 512 MiB. Each Argon2id operation allocates 46 MiB, and the semaphore allows up to 4 concurrent operations (184 MiB peak). Pods with less than 512 MiB risk OOM kills under authentication load.

---

## Boolean Parsing

Boolean env vars accept: `true`, `1`, or `yes` (case-sensitive) as truthy. All other values (including empty) are treated as `false`.

Exception: `VAULT_HIBP_CHECK` defaults to `true` when unset and must be explicitly set to a non-truthy value to disable it.

## Duration Parsing

Duration env vars use Go's standard `time.ParseDuration` format:

| Format | Meaning |
|--------|---------|
| `5m` | 5 minutes |
| `1h` | 1 hour |
| `24h` | 24 hours |
| `168h` | 7 days |
| `720h` | 30 days |

Invalid duration strings are silently ignored and the default (or profile default) is used instead.
