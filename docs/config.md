# Configuration Reference

> Vault42 -- Environment Variables & Configuration

## Overview

Vault42 is configured entirely through environment variables. There are no configuration files, command-line flags, or admin UIs for configuration.

Three mechanisms work together:

1. **Environment variables** -- all settings are read from env vars at startup.
2. **Profiles** -- preset defaults for production, dev, and embedded deployments. The profile is selected via `VAULT_PROFILE` and fills in any env vars you did not set.
3. **`_FILE` convention for secrets** -- sensitive values are never placed directly in env vars. Instead, a `_FILE`-suffixed variable points to a file containing the secret. The vault binary reads the file into memory; with `VAULT_SECRET_FILE_CONSUME=true` it is then zeroed and removed from disk (opt-in, off by default). The bridge does not honour that flag: see `BRIDGE_ADMIN_TOKEN_FILE`.

The startup sequence is: read env vars, apply profile defaults for unset fields, load secrets from `_FILE` paths.

---

## Profiles

Four profiles provide sensible defaults so you only need to set the variables that differ from the baseline. An unset profile is production; a profile name that is set and unrecognized refuses to start. Case and surrounding whitespace are normalized, so `VAULT_PROFILE=Honeypot` selects the honeypot profile rather than becoming production.

### Production (`VAULT_PROFILE=production`, default)

The full-security baseline. Expects external PostgreSQL and Redis, TLS enabled, strict CORS, and all secrets provided via `_FILE` mounts.

### Dev (`VAULT_PROFILE=dev`)

Dev **extends production** -- it applies all production defaults first, then overrides a small set of values for local development convenience. TLS, rate limits, listen address, and cache backend are all inherited from production unless you explicitly override them.

### Embedded (`VAULT_PROFILE=embedded`)

Tuned for resource-constrained environments such as a Raspberry Pi 5. Uses in-memory cache, fewer database connections, and auto-migration. Target memory footprint: ~60-80 MB.

### Honeypot (`VAULT_PROFILE=honeypot`)

A deception deployment that mimics a real Vault42 instance to detect and alert on unauthorized access attempts. Extends production defaults with auto-migration and the embedded frontend enabled by default. Pairs with `VAULT_HONEYPOT_WEBHOOK` and `VAULT_HONEYPOT_TRAP_USERS` to send alerts when attackers interact with the honeypot.

### Profile Comparison

| Setting | Production | Dev | Embedded | Honeypot |
|---------|-----------|-----|----------|----------|
| `ListenAddr` | `:8443` | `:8443` (inherited) | `:8443` | `:8443` |
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

Note: In the dev profile, if you explicitly set an env var (e.g., `VAULT_REFRESH_TOKEN_TTL=48h`), the explicit value takes precedence over the dev override. The dev profile only overrides values that were left unset. Exception: `VAULT_AUTO_MIGRATE` is unconditionally set to `true` in dev and cannot be overridden via env var.

---

## Fail-Closed Overrides (read this before production)

`Config.Validate()` (`internal/config/config.go`) refuses to start a non-dev profile
that has a security guarantee switched off. Five environment variables move a guard, and each
one is an audited, deliberate weakening. They are listed here together because an operator or
auditor reviewing a deployment needs to find them in one place, not by grepping the source.

| Variable | Default | What setting it does |
|---|---|---|
| `VAULT_ALLOW_PLAINTEXT` | `false` | **Permits a non-dev profile to serve plain HTTP.** Without it, `VAULT_TLS_ENABLED=false` with `VAULT_FORCE_SECURE_COOKIES` also off is a startup failure. Setting it serves credentials and tokens in cleartext to anything between the client and the process, and on its own leaves the `Secure` cookie flag off, because the flag tracks `VAULT_TLS_ENABLED` and `VAULT_FORCE_SECURE_COOKIES` rather than this variable. The only defensible use is a TLS-terminating proxy on the same host or pod network -- and in that case set `VAULT_FORCE_SECURE_COOKIES=true` instead, which keeps the guard intact. See [TLS and Cookies](#tls-and-cookies) for the full combination table. |
| `VAULT_ALLOW_PLAINTEXT_DB` | `false` | **Permits a non-dev profile to use an unencrypted database link.** `DB_SSLMODE=disable`, `allow` or `prefer` do not guarantee TLS. The startup packet carries the role password and every later query carries every row, including TOTP secrets and password hashes. Without this override those three modes refuse to start outside `dev`. Set it only when Postgres is on the same pod or a private loopback, which is what the bundled chart postgres does. `prefer` is the one to watch: it asks for TLS and falls back to plaintext without an error. |
| `VAULT_ALLOW_RATE_LIMIT_DISABLED` | `false` | **Permits a non-dev profile to run with `VAULT_RATE_LIMIT_ENABLED=false`.** Rate limiting is the brute-force defence on login, registration, password reset, TOTP verify and the KMS unwrap oracle. Setting this removes it. Justified only when an upstream gateway enforces equivalent per-IP limits on those exact paths. |
| `VAULT_EMBEDDED_TRUSTED_UPSTREAM` | `false` | **Auto-trusts every RFC1918 range, IPv6 ULA and loopback as a proxy, and honours `X-Forwarded-For` from them** (`config.Load`, `internal/config/config.go`). On a flat network any pod can then forge a client IP, collapsing per-IP rate limiting and audit attribution. Startup refuses it outside the `embedded` profile. Prefer explicit `TRUSTED_PROXIES` + `REAL_IP_HEADER` everywhere else. |
| `VAULT_STRICT_SESSION_LIMIT` | `false` | The inverse: **the concurrent-session cap fails open by default.** If the active-family count query errors, `VAULT_MAX_SESSIONS_PER_USER` is not enforced for that login (`AuthService.checkSessionLimit`). Setting this to `true` makes the check fail closed -- the login is refused and a risk-80 audit event is written. Enable it if the session cap is a control you rely on. |

`VAULT_SECRET_FILE_CONSUME` is not in this table because it hardens rather than relaxes, but it
has a matching failure mode: it destroys the on-disk secret after the first read. See
[Secret Loading](#secret-loading-_file-convention).

---

## Environment Variables

### Core

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_PROFILE` | string | `production` | No | Deployment profile: `production`, `dev`, `embedded`, or `honeypot`. Controls defaults for all unset variables. |
| `LISTEN_ADDR` | string | `:8443` | No | Address and port the server binds to. Set by profile if unset. |
| `VAULT_ORIGIN` | string | *(none)* | Yes | Public-facing URL (e.g., `https://auth.example.com`). Used for CORS `Access-Control-Allow-Origin`, JWT issuer claim, cookie domain, and WebAuthn RP ID. |
| `VAULT_APP_NAME` | string | `The Vault` | No | Application display name used in email templates, the WebAuthn RP name, and UI. |
| `VAULT_LOGO_URL` | string | *(none)* | No | URL to application logo for email templates. |
| `VAULT_PRIMARY_COLOR` | string | `#00FF42` | No | Primary branding color hex code for email templates. |
| `VAULT_AUTO_MIGRATE` | bool | `false` | No | Run database migrations automatically at startup. Profile defaults: `false` (production), `true` (dev, embedded). |
| `VAULT_SHUTDOWN_TIMEOUT` | duration | `0` (profile sets) | No | Maximum wait time for in-flight requests during graceful shutdown. Read from the environment in every profile; an explicit value beats the profile default. Profile defaults: `15s` (production, honeypot), `5s` (dev, embedded). |
| `VAULT_SERVE_FRONTEND` | bool | `false` | No | Serve the embedded Vue SPA from the Go binary. Default: `false` (secure by default). Honeypot profile enables this by default. |
| `VAULT_EMAIL_TEMPLATES_DIR` | string | *(none)* | No | Directory containing custom HTML email templates to override embedded defaults. |
| `VAULT_AUDIT_FLUSH_INTERVAL` | duration | `0` | No | Interval for flushing buffered audit log entries. `0` disables batching (immediate flush). Read from the environment in every profile. The embedded profile sets `30s` when this is left unset, so a Pi-class box is not doing a write per event. |
| `VAULT_AUDIT_BUFFER_SIZE` | int | `1000` | No | Maximum number of audit entries buffered before new entries are dropped. Only relevant when `VAULT_AUDIT_FLUSH_INTERVAL > 0`. |

### TLS and Cookies

Four variables decide two separate things: whether this process speaks TLS, and
whether session cookies carry the `Secure` flag. They are separate because the
supported production topology terminates TLS at an ingress or a tunnel, where the
process is reached over plain HTTP but the browser hop is HTTPS and the flag must
still be set.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_TLS_ENABLED` | bool | `true` | No | Serve HTTPS from this process. Read from the environment in every profile: profile defaults are applied through `os.LookupEnv`, so an explicit value beats the profile's `true`. Setting it to `false` is a supported deployment, and the Helm chart uses it (`charts/vault/templates/honeypot-vault.yaml`). Which combinations then start, and what happens to cookies, is the table below. |
| `VAULT_TLS_CERT_FILE` | string | *(none)* | Conditional | Path to the TLS certificate PEM file. |
| `VAULT_TLS_KEY_FILE` | string | *(none)* | Conditional | Path to the TLS private key PEM file. |
| `VAULT_FORCE_SECURE_COOKIES` | bool | `false` | No | Mark cookies `Secure` regardless of `VAULT_TLS_ENABLED`. The setting for proxy termination, and the one that keeps the guard intact. Also documented under [Security](#security). |
| `VAULT_ALLOW_PLAINTEXT` | bool | `false` | No | **Fail-closed override.** Lifts the startup refusal on serving plain HTTP without `Secure` cookies. Also documented under [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production). |

**Certificate and key.** Both are needed to serve HTTPS. With TLS on and either
one missing, a non-dev profile refuses to start unless
`VAULT_FORCE_SECURE_COOKIES=true` opts into proxy termination. With that opt-in
and no certificate, the process listens in plain HTTP and still marks cookies
`Secure`, which is the intended proxy deployment. With that opt-in and a
certificate but no key, the process selects the TLS listener instead and
`ListenAndServeTLS` fails on the missing key, so a half-configured pair surfaces
as a crash rather than as silent plaintext.

**Cookies.** The `Secure` flag is `VAULT_TLS_ENABLED` **or**
`VAULT_FORCE_SECURE_COOKIES`. It is computed once in `internal/server` and handed
to every handler that writes a cookie, so it does not follow the profile name.
`VAULT_ALLOW_PLAINTEXT` is not part of that expression: it removes a startup
refusal and neither sets nor clears the flag. Behind a TLS-terminating proxy,
`VAULT_FORCE_SECURE_COOKIES=true` is what keeps session cookies protected on the
last hop; using `VAULT_ALLOW_PLAINTEXT` on its own is what leaves them exposed.

**Startup.** `Config.Validate` refuses exactly two combinations, and only in
non-dev profiles:

- TLS off, `VAULT_FORCE_SECURE_COOKIES` off, `VAULT_ALLOW_PLAINTEXT` off. The
  server would serve credentials and tokens in cleartext with cookies that any
  intermediary can read.
- TLS on, certificate or key missing, `VAULT_FORCE_SECURE_COOKIES` off. Without
  the opt-in this silently degrades to a plaintext listener while the operator
  believes TLS is on.

The `dev` profile is exempt from both: `Config.Validate` returns before either
check, so dev serves plaintext with cookies that are not `Secure` and needs no
override variable to do it.

**Parsing.** All four follow the single rule described under
[Boolean Parsing](#boolean-parsing): every recognized spelling means what it
says, an empty value means "unset", and an unrecognized one refuses to start.
So `VAULT_TLS_ENABLED=no` turns TLS off, and `VAULT_ALLOW_PLAINTEXT=TRUE` lifts
the refusal. These two used to be read by different parsers, and each answered
"use the default" outside its own set: `VAULT_TLS_ENABLED=no` served HTTPS
anyway, and `VAULT_ALLOW_PLAINTEXT=TRUE` did not lift anything.

The table below is executed against `config.Load`, `Config.Validate` and
`internal/server` by `tests/spec/tls_cookie_docs_test.go`, under each of the
`production`, `embedded` and `honeypot` profiles. A row that stops being true
fails the build.

<!-- BEGIN TLS COOKIE MATRIX -->

| `VAULT_TLS_ENABLED` | cert + key | `VAULT_FORCE_SECURE_COOKIES` | `VAULT_ALLOW_PLAINTEXT` | Effective TLS | Startup | `Secure` cookie | Listener |
|---|---|---|---|---|---|---|---|
| unset | set | unset | unset | true | starts | set | HTTPS |
| `true` | set | unset | unset | true | starts | set | HTTPS |
| `true` | unset | unset | unset | true | refused | n/a | n/a |
| `true` | unset | `true` | unset | true | starts | set | plaintext |
| `true` | cert only | unset | unset | true | refused | n/a | n/a |
| `true` | cert only | `true` | unset | true | starts | set | HTTPS |
| `false` | unset | unset | unset | false | refused | n/a | n/a |
| `false` | unset | `true` | unset | false | starts | set | plaintext |
| `false` | unset | unset | `true` | false | starts | unset | plaintext |
| `false` | unset | `true` | `true` | false | starts | set | plaintext |
| `no` | set | unset | unset | false | refused | n/a | n/a |
| `0` | unset | `true` | unset | false | starts | set | plaintext |
| `false` | unset | unset | `TRUE` | false | starts | unset | plaintext |

<!-- END TLS COOKIE MATRIX -->

The `cert only` rows are the exception to reading the Listener column literally:
`HTTPS` there means the process picks the TLS listener, which then fails on the
missing key file. Every other row's listener serves.

Two rows deserve to be read twice. `VAULT_TLS_ENABLED=false` with
`VAULT_FORCE_SECURE_COOKIES=true` is the proxy deployment done right: the process
speaks HTTP to the proxy, and the cookies it issues are still `Secure`.
`VAULT_TLS_ENABLED=false` with `VAULT_ALLOW_PLAINTEXT=true` and nothing else is
the same deployment with the flag dropped, which is a real exposure on the last
hop and the reason the first row of that pair is the documented answer.

### Database

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `DB_HOST` | string | `localhost` | No | PostgreSQL hostname. |
| `DB_PORT` | string | `5432` | No | PostgreSQL port. |
| `DB_NAME` | string | `vault` | No | PostgreSQL database name. |
| `DB_SSLMODE` | string | `require` | No | PostgreSQL SSL mode. One of `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`; anything else refuses to start. `disable`, `allow` and `prefer` do not guarantee an encrypted connection, and the startup banner says so in a non-dev profile. In the dev profile, `DatabaseURL()` forces this to `disable` regardless of the configured value. |
| `DB_MAX_CONNS` | int | `0` (profile sets) | No | Maximum database connections. Profile defaults: `25` (production/dev), `5` (embedded). |
| `DB_STATEMENT_TIMEOUT` | duration | `10s` | No | Server-side ceiling on a single statement. Zero disables it. Without it a pathological query pins the whole pool and the process stops serving with no error anywhere. |
| `DB_LOCK_TIMEOUT` | duration | `3s` | No | Server-side ceiling on waiting for a lock. Zero disables it. |
| `VAULT_ALLOW_PLAINTEXT_DB` | bool | `false` | No | **Fail-closed override.** Permits a non-dev profile to start with `DB_SSLMODE` set to `disable`, `allow` or `prefer`. Without it those modes refuse to start, because the role password and every row would travel in cleartext. Also documented under [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production). |
| `DB_MIG_PASSWORD_FILE` | string | *(none)* | Yes | Path to file containing the `vault_mig` role password. Used for schema migrations at startup. See [Secret Loading](#secret-loading-_file-convention). |
| `DB_APP_PASSWORD_FILE` | string | *(none)* | Yes | Path to file containing the `vault_app` role password. Used for all runtime queries. See [Secret Loading](#secret-loading-_file-convention). |

The application uses two PostgreSQL roles with least-privilege separation:

- **`vault_mig`** -- DDL privileges for migrations only. Connection is closed after migrations complete.
- **`vault_app`** -- SELECT/INSERT/UPDATE on `auth` schema, INSERT/SELECT only on `audit` schema (append-only: no UPDATE, no DELETE). No TRUNCATE, no DDL. DELETE is held on the per-user and per-session tables for token lifecycle and the erasure cascade, and on `auth.signing_keys` for the key reap, where a trigger narrows it to retired keys past expiry. Two writes are narrowed further than their grant: it may not put a vault42 capability scope on a client row (migration 023), and it may not un-confirm an email address, re-arm `import_pending`, ban or disable an account (migration 024). See [admin-gateway.md](admin-gateway.md#database-role-separation).

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
| `ADMIN_TOKEN_FILE` | string | *(none)* | Recommended | Path to a file holding the admin CLI token, either as its Argon2id hash (preferred) or as the plaintext token. On first boot the value seeds `admin_config.admin_token_hash`, the credential every CLI command (`add-client`, `rotate-jwks`, ...) is checked against. Without it, a token is generated on first boot and delivered through `VAULT_FIRST_BOOT_CREDENTIAL_FILE` (or to a terminal), never to the process log. See [Admin Token Provisioning](#admin-token-provisioning). |
| `VAULT_PEPPER_FILE` | string | *(none)* | Recommended | Path to file containing the server-side pepper added to password hashes before Argon2id. Must be at least 32 bytes in non-dev profiles (startup fails otherwise). |
| `HMAC_SECRET_FILE` | string | *(none)* | Yes | Path to file containing the HMAC-SHA256 signing key. Must be at least 32 bytes in production/embedded profiles. Dev profile logs a warning for shorter keys. |
| `SIGNING_KEY_FILE` | string | *(none)* | Conditional | Path to RSA-2048 private key (PKCS#8 PEM, `BEGIN PRIVATE KEY`) for JWT signing. `LoadSigningKeyPEM` (`internal/crypto/jwt.go`) accepts PKCS#8 only; PKCS#1 (`BEGIN RSA PRIVATE KEY`) is a startup parse failure. The kid the process advertises is `KIDFromPublicKey` (first 16 hex characters of SHA-256 over the PKIX DER of the public key, formatted `xxxxxxxx-xxxxxxxx`), not a UUID you write down. Shared across all pods for horizontal scaling. Without this, each pod generates an ephemeral key (single-pod only). Required for multi-pod deployments. Generate with `scripts/generate-secrets.sh` (`openssl genpkey`). `vault rotate-jwks` writes PKCS#1 and prints a discarded UUID: pointing this variable at that output does not rotate the signing key. |
| `VAULT_PASSWORD_MIN_LENGTH` | int | `15` | No | Minimum password length per NIST SP 800-63B Rev 4. No composition rules enforced. |
| `VAULT_HIBP_CHECK` | bool | `true` | No | Enable Have I Been Pwned breach checking for passwords at registration and password change. |
| `VAULT_MFA_REQUIRED` | bool | `true` | No | Force all users to set up two-factor authentication. Set to `false` to make 2FA optional. |
| `VAULT_REGISTRATION_ENABLED` | bool | `true` | No | Enable public user registration via `POST /auth/register`. When `false`, the endpoint returns 403 `registration_disabled`. Use with `VAULT_SEED_FILE` for sealed deployments where all users are pre-provisioned. |
| `VAULT_MAX_SESSIONS_PER_USER` | int | `10` | No | Maximum concurrent refresh token families per user. A new family that would exceed the cap is refused with `429 too_many_sessions`. Existing sessions are not evicted: the bound is a ceiling on new logins, not a least-recently-used replacement policy. |
| `VAULT_MAX_SESSION_LIFETIME` | duration | `720h` | No | Absolute ceiling on the age of a refresh-token family, measured from its creation and independent of how often it is refreshed. Without it, rotation grants a fresh full TTL every time and a client that keeps refreshing holds a session forever. The default matches `VAULT_REMEMBER_ME_TTL`, so a session can live as long as the longest single token and no longer. NIST SP 800-63B-4 §2.2.3 requires that a definite overall reauthentication timeout SHALL be established, and says it SHOULD be no more than 24 hours at AAL2. This setting is what establishes the SHALL; the 720h default is a deliberate deviation from the SHOULD, because a general-purpose authentication server is not deployed only at AAL2 and a 24-hour default would force a daily re-login on every deployment that is not. Set `24h` if you need that conformance, which will log out remember-me users on schedule. §2.2.3's other figure, the 1-hour inactivity timeout, is `VAULT_INACTIVITY_TIMEOUT` below and is met at the default. `0` disables the bound. |
| `VAULT_INACTIVITY_TIMEOUT` | duration | `1h` | No | How long a refresh-token family may go **unused** before it is terminated and the user must log in again. This is the other half of `VAULT_MAX_SESSION_LIFETIME`: that bound ends a session that is in constant use, this one ends a session that has stopped being used. The default is the figure NIST SP 800-63B-4 §2.2.3 says the AAL2 inactivity timeout SHOULD not exceed. **Measured from the family's last rotation, not from its last request.** A client in normal use rotates about once per `VAULT_ACCESS_TOKEN_TTL`, so a session in use never approaches the window; a value at or below the access token TTL would terminate sessions that never went idle, and startup logs a warning if you set one. The error is one-directional — the check can conclude a session is idler than it really is, never fresher — so it never runs long. Termination revokes the whole family and is audited with `reason=session_inactivity_exceeded`; the client sees an ordinary expired-token response. Issuance also clamps the refresh token's own expiry to this window, so a timed-out session stops counting against `VAULT_MAX_SESSIONS_PER_USER` instead of holding a slot for the rest of `VAULT_REFRESH_TOKEN_TTL`. **Upgrade note:** turning this on logs out any session, including a "remember me" one, that has been idle longer than the window; set a longer duration or `0` to disable the bound if that is not wanted. |
| `VAULT_STRICT_SESSION_LIMIT` | bool | `false` | No | Make the concurrent-session check fail closed. By default, if the active-family count query errors the login is allowed through and the cap is not enforced for that request. When `true`, the login is refused with `too_many_sessions` and a risk-80 audit event is recorded. See [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production). |
| `VAULT_RATE_LIMIT_ENABLED` | bool | `true` | No | Enable rate limiting on authentication endpoints. Defaults to `true`; in non-dev profiles startup refuses to run with it disabled unless `VAULT_ALLOW_RATE_LIMIT_DISABLED=true`. |
| `VAULT_ALLOW_RATE_LIMIT_DISABLED` | bool | `false` | No | **Fail-closed override.** Permits a non-dev profile to run with rate limiting disabled (e.g. when an upstream gateway handles it). Without it, disabling rate limiting fails startup. See [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production). |
| `VAULT_ALLOW_PLAINTEXT` | bool | `false` | No | **Fail-closed override.** Permits a non-dev profile to serve plain HTTP. Without it, `VAULT_TLS_ENABLED=false` with `VAULT_FORCE_SECURE_COOKIES` also off refuses to start (`Config.Validate`). Setting it serves credentials and tokens in cleartext, and on its own leaves the `Secure` cookie flag off. Behind a TLS-terminating proxy, set `VAULT_FORCE_SECURE_COOKIES=true` instead. See [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production) and [TLS and Cookies](#tls-and-cookies). |
| `VAULT_EMBEDDED_TRUSTED_UPSTREAM` | bool | `false` | No | **Fail-closed override.** Embedded profile only (startup fails elsewhere). When `TRUSTED_PROXIES` is empty, auto-populates it with `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `127.0.0.0/8` and `::1/128`; when `REAL_IP_HEADER` is empty, defaults it to `X-Forwarded-For`. Intended for a sibling reverse proxy on the same private network. Explicit `TRUSTED_PROXIES` / `REAL_IP_HEADER` always win. See [Fail-Closed Overrides](#fail-closed-overrides-read-this-before-production). |
| `VAULT_DPOP_ENABLED` | bool | `false` | No | Sender-constrains access tokens issued with a DPoP proof (RFC 9449). When true, the DPoP middleware is mounted on `POST /auth/login`, `POST /auth/refresh`, the 2FA verify endpoints and every authenticated route (inside the auth middleware, so it can read `cnf.jkt`). A login, refresh or 2FA-challenge request that presents a valid `DPoP` proof has that proof's JWK thumbprint written into the issued access or challenge token as `cnf.jkt` (RFC 9449 §6.1). A later request presenting that token must use the `DPoP` authorization scheme and a matching proof; a missing or mismatched proof is `401`. A token issued without a proof stays an ordinary bearer token, so enabling the flag does not break existing clients. Two limits are real and are not closed by this flag: refresh tokens are opaque and are not sender-bound, and the server neither issues nor requires a `DPoP-Nonce`. One issuance path is not wrapped: `GET /auth/oauth2/callback/{provider}` (the provider redirects the browser with a GET, which cannot carry a proof, so federated login never stamps `cnf.jkt`; `POST /auth/oauth2/exchange` returns that already-issued token). A later 2FA verify *is* wrapped, so an MFA-completing federated login can still bind there. `POST /client/token` **is** wrapped, so a client-credential token minted with a proof carries `cnf.jkt` like any other; that route was the last unwrapped issuance path and was closed during the 1.0.0 hardening. The default is off so a deployment that has not rolled out DPoP clients keeps working; turn it on when those clients can send proofs. |
| `KMS_ROOT_KEY_FILE` | string | *(none)* | No | Path to a file containing the KMS root secret (at least 32 bytes). Per-kid KEKs are derived from it via HKDF-SHA256, kept cryptographically separate from the master key. When unset, the `POST /kms/unwrap` envelope-unwrap oracle is not mounted. See [Secret Loading](#secret-loading-_file-convention). |
| `VAULT_FORCE_SECURE_COOKIES` | bool | `false` | No | Force the `Secure` flag on cookies even when TLS is not enabled locally. The setting to reach for behind a TLS-terminating proxy (e.g., Cloudflare Tunnel, nginx with TLS offloading), because it keeps the last hop protected without disabling the startup guard. It also satisfies the certificate requirement when `VAULT_TLS_ENABLED` is left on, in which case the listener is plain HTTP. See [TLS and Cookies](#tls-and-cookies). |
| `TRUSTED_PROXIES` | string | *(none)* | No | Comma-separated list of CIDR ranges or IPs trusted to set `X-Forwarded-For` (e.g., `10.0.0.0/8,172.16.0.0/12`). Also gates the `X-Vault-App` white-label tenant header: the slug is only honoured when the direct peer is on this list, so an outside caller cannot dress an auth email in another tenant's branding. Empty = white-label tenant selection is off and all auth emails use the global branding. See [API Reference -- White-Label Tenant Selection](api.md#white-label-tenant-selection). |
| `REAL_IP_HEADER` | string | *(none)* | No | HTTP header containing the real client IP from a trusted proxy. Only read when the direct connection is from a trusted proxy. Examples: `CF-Connecting-IP` (Cloudflare), `X-Real-IP` (nginx). Empty = use XFF parsing only. A comma-joined value (the embedded profile sets this to `X-Forwarded-For`) is split and the rightmost address wins; a value that is not an IP is discarded and resolution falls back to XFF parsing, then `RemoteAddr`. |
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
| `VAULT_SMTP_ALLOW_PLAINTEXT` | bool | `false` | No | Permits delivery to an SMTP server that does not advertise STARTTLS. Every message carries a bearer secret, so a relay that cannot be upgraded is a failed send by default. Outside `dev` the opt-out is accepted only for a loopback `SMTP_HOST` (`localhost` or a loopback address); a remote host with this set refuses to start, because that would mail one-time codes across a network in cleartext. |
| `VAULT_EMAIL_FROM` | string | *(none)* | Yes | Sender address for outgoing emails (e.g., `noreply@example.com`). |
| `VAULT_EMAIL_FROM_NAME` | string | *(none)* | No | Global display name for the `From` line (e.g. `Acme Security`). Empty = the address alone. Per-app white-label branding can override it. |
| `VAULT_EMAIL_FROM_ALLOWED_DOMAINS` | string | *(none)* | No | Comma-separated domain allowlist for per-app `From` **address** overrides. A per-app `from_address` whose domain is not listed falls back to `VAULT_EMAIL_FROM`. Empty (the default) disables address overrides entirely; display-name overrides still apply. This is the control that stops a tenant from sending auth mail as another tenant's domain, so leave it empty unless white-label sending is deliberately wanted. |
| `VAULT_MAX_EMAIL_TEMPLATE_SIZE` | int (bytes) | `65536` | No | Upper bound on a custom email template body accepted by the admin API (`PUT /admin/email-templates/{app}/{name}`). Templates over the limit are rejected. |
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
| `BRIDGE_ADMIN_TOKEN_FILE` | string | *(none)* | No | Path to file containing the admin API bearer token. This is not the vault `_FILE` consume convention. `cmd/bridge/config.go` always overwrites the file with zeros after the first read and ignores `VAULT_SECRET_FILE_CONSUME`. The file is not deleted. On a writable mount the token is gone after the first start, so keep a copy elsewhere before pointing the bridge at it. A read-only mount (the usual Secret volume) leaves the file intact because the overwrite fails. |
| `BRIDGE_REDIS_ADDR` | string | *(none)* | No | Optional Redis address for persistent flag storage. |
| `BRIDGE_TRUSTED_PROXIES` | string | *(none)* | No | Comma-separated CIDR ranges for proxy IP detection. |
| `BRIDGE_REAL_IP_HEADER` | string | *(none)* | No | Header from trusted proxy containing real client IP (e.g., `CF-Connecting-IP`). |
| `BRIDGE_LOG_LEVEL` | string | `info` | No | Log level (`info`, `debug`). |
| `BRIDGE_MAX_BODY_BYTES` | int | `16777216` (16 MiB) | No | Cap on a proxied request body. The default sits above the vault's 10 MiB blob ceiling so this cap is not what rejects a legitimate upload; the vault re-applies its own, smaller, limit per route. Without it the bridge would stream whatever the client sent for as long as the read timeout allowed. |
| `BRIDGE_MAX_INFLIGHT` | int | `512` | No | Cap on concurrently proxied requests. One goroutine and one upstream socket per request with nothing counting them is how a slow upstream turns a request flood into an unbounded connection table. Zero disables the cap. |
| `BRIDGE_STRIP_HEADERS` | string | *(none)* | No | Extra request headers deleted before the request reaches an upstream, comma-separated. The bridge already strips the names the vault ships with (tenant slug, TLS fingerprint, real-IP, geo). Use this when you renamed one of those via `VAULT_TLS_FINGERPRINT_HEADER`, `REAL_IP_HEADER` or `GEO_IP_HEADER`, so a client cannot supply the value the upstream control is checking. |

### Admin Gateway

The admin gateway is a separate binary (`cmd/admin-gateway/`) serving the mTLS, loopback-only
admin plane. See [Admin Gateway](admin-gateway.md#configuration) for the deployment model; the
full variable set is reproduced here so this page remains the complete env-var reference.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `ADMIN_GW_LISTEN_ADDR` | string | `127.0.0.1:9443` | No | Bind address. Startup fails unless it is loopback (`127.0.0.1:`, `[::1]:` or `localhost:`), except in dev mode. |
| `ADMIN_GW_TLS_CERT_FILE` | string | *(none)* | Yes | Server TLS certificate path. |
| `ADMIN_GW_TLS_KEY_FILE` | string | *(none)* | Yes | Server TLS private key path. |
| `ADMIN_GW_CLIENT_CA_FILE` | string | *(none)* | Yes | Client CA certificate for mTLS verification. The TLS stack requires a certificate signed by this CA. Which identities that CA may have issued are pinned separately, below. |
| `ADMIN_GW_CLIENT_CN_ALLOWLIST` | string | *(empty)* | No | Comma-separated identities allowed to complete the mTLS handshake. Each entry is matched exactly against the leaf certificate's subject common name and its DNS, email and URI SANs. Empty pins nothing: any certificate this CA has ever signed is accepted, and the gateway logs a security warning naming [AR-9](security.md#ar-9-admin-client-certificate-identity-pinning-is-optional). Set this once more than one certificate has been issued from the CA, so a decommissioned operator or a cert minted for another component cannot reach `POST /admin/login`. |
| `ADMIN_GW_CLIENT_CRL_FILE` | string | *(empty)* | No | Path to a PEM or DER certificate revocation list signed by the client CA. Every handshake is checked against it, and the list is re-read each time so a newly published revocation takes effect without a restart. An unreadable, unparseable, foreign-signed or expired list refuses the handshake. A path that cannot be read or parsed at boot is fatal: the process exits rather than coming up with revocation checking appearing configured and then rejecting every operator. Empty checks nothing. |
| `ADMIN_GW_SESSION_TTL` | duration | `1h` | No | Admin session lifetime. |
| `ADMIN_GW_MAX_FAILED_LOGINS` | int | `5` | No | Failed admin login attempts before account lockout. |
| `ADMIN_GW_LOCKOUT_DURATION` | duration | `30m` | No | Admin account lockout duration. |
| `ADMIN_GW_AUTO_MIGRATE` | bool | `false` | No | Run database migrations at gateway startup. |
| `ADMIN_GW_SHUTDOWN_TIMEOUT` | duration | `15s` | No | Graceful shutdown wait time. |
| `ADMIN_GW_DEV_MODE` | bool | `false` | No | Relaxes loopback enforcement for development behind an ingress controller: disables the `LocalOnly` and `RejectProxyHeaders` middleware, and turns the killswitch off by default. Never set this in production -- it removes two of the six enforcement layers. |
| `ADMIN_GW_KILLSWITCH` | bool | `true` (`false` in dev mode) | No | When enabled, a non-loopback request is audited and then panics the process rather than returning 403, so the breach attempt surfaces as CrashLoopBackOff. |
| `DB_ADMIN_PASSWORD_FILE` | string | *(none)* | Yes | Path to file containing the `vault_admin` PostgreSQL role password. See [Secret Loading](#secret-loading-_file-convention). |

The gateway also reads `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_SSLMODE`, `DB_MAX_CONNS` (default
`5` here, not `25`), `DB_STATEMENT_TIMEOUT`, `DB_LOCK_TIMEOUT`, `MASTER_KEY_FILE`,
`HMAC_SECRET_FILE`, `VAULT_PEPPER_FILE`, `VAULT_RECOVERY_PUBLIC_KEY_FILE`, `VAULT_SEED_FILE`,
`VAULT_MAX_EMAIL_TEMPLATE_SIZE` and `VAULT_FIRST_BOOT_CREDENTIAL_FILE` with the same meanings
as above. `VAULT_PEPPER_FILE` must be the same value the user-facing service uses, or
admin-created user passwords will not verify. `ADMIN_GW_DEV_MODE` is an exact-match test
(`true` only, not the boolean parser used by the vault binary). `ADMIN_GW_KILLSWITCH` accepts
only `true`/`1`/`yes` and `false`/`0`/`no`, case-sensitive; any other spelling refuses to start.

### Offline Recovery Tool

`cmd/recover/` decrypts account-erasure escrow records with the offline private half of
`VAULT_RECOVERY_PUBLIC_KEY_FILE`. It is run by hand, never by the server.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `DATABASE_URL` | string | *(none)* | Conditional | PostgreSQL DSN for the recovery run. One of the two is required. Prefer this over `--dsn`: a DSN in argv is world-readable through `/proc/<pid>/cmdline` for the life of the run and lands in shell history, while `/proc/<pid>/environ` is readable only by the process owner. `recover` warns on stderr when it sees a password arrive in argv. It is no longer the default for `--dsn` either, because `flag.PrintDefaults` printed that default in the usage text, so `recover -h` disclosed the password to the terminal. |

### Metrics & Observability

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_METRICS_ENABLED` | bool | `false` | No | Enable the Prometheus-compatible `/metrics` endpoint on a dedicated listener, not on the public one. Exposes operational counters (argon2 semaphore, login, token). |
| `VAULT_METRICS_ADDR` | string | `127.0.0.1:9090` | No | Bind address for that dedicated listener. The default is loopback so a scrape from another pod cannot reach it. The Helm chart sets this to `:<metrics.port>` so Prometheus can scrape, and expects `metrics.networkPolicy` to be the fence the loopback default was. Leave the default unless something outside the pod must scrape. |
<!-- loglevel-gate:begin -->
| `LOG_LEVEL` | string | *(ignored)* | No | **Read and ignored.** vault42 has no log-verbosity control. If this is set, startup logs one line saying so and every log line is still emitted. It is not refused, because co-located software often inherits `LOG_LEVEL` and a hard error would turn that into a boot loop. Setting it does not cut log exposure. |
<!-- loglevel-gate:end -->

### Blob Storage

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_BLOB_MIN_SIZE` | int | `0` (disabled) | No | Minimum single blob size in bytes. Blobs smaller than this are rejected. `0` disables the minimum check (empty blobs are still rejected). |
| `VAULT_BLOB_MAX_SIZE` | int | `10485760` (10MB) | No | Maximum single blob size in bytes. Blobs larger than this are rejected. |
| `VAULT_BLOB_MAX_PER_USER` | int | `50` | No | Maximum number of blobs per user. |
| `VAULT_BLOB_QUOTA_BYTES` | int | `10485760` (10MB) | No | Total storage quota per user in bytes. Set to `0` to disable the blob storage feature entirely. |

### Signing Oracle (`POST /mint`)

Off by default. When disabled the route is not registered at all, so a vanilla deployment has no mint.

`/mint` signs a token for a subject that the calling service authenticated somewhere else. Anyone
holding the mint credential can therefore speak as any subject to every service that trusts the JWKS,
and a verifier cannot tell a minted token from a real one by its signature. Treat enabling it as a
trust-model decision, not a feature flag.

The request and response contract is in [`api.md`](api.md#post-mint); the threat model and the
controls that bound it are in [`spec.md` section 6.5](spec.md#65-subject-assertion-signing-oracle).

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_MINT_ENABLED` | bool | `false` | No | Mounts `POST /mint`. Leave unset unless a service genuinely needs delegated signing. |
| `VAULT_MINT_AUDIENCE` | string | *(none)* | When enabled | The `aud` claim stamped on minted tokens. **MUST differ from `VAULT_ORIGIN`.** The server refuses to start otherwise, in every profile including dev: a minted token carrying vault42's own audience authenticates against vault42 itself, which turns the oracle into account takeover for every user. |
| `VAULT_MINT_TOKEN_TTL` | duration | `5m` | No | Lifetime of a minted token when the caller names none. |
| `VAULT_MINT_MAX_TTL` | duration | `5m` | No | Ceiling on a caller-requested lifetime, itself capped at 15m in code. A request above the ceiling is **refused, not clamped**, so a misconfigured caller is visible rather than silently downgraded. Minted tokens cannot be revoked, so the lifetime is the only bound on a leaked one. |
| `VAULT_MINT_ROLES` | list | *(empty)* | No | Comma-separated allow-list of roles a minted token may carry. Empty means no role may be minted. The admin-reserved names are refused at startup regardless of what is listed here. |
| `VAULT_MINT_SCOPES` | list | *(empty)* | No | Comma-separated allow-list of scopes a minted token may carry. Empty means no scope may be minted. Capability scopes such as `kms:unwrap` and `mint:token` are refused regardless. |

### Service-Scoped JSON Documents

Off by default. Lets a registered service store arbitrary JSON against a subject, encrypted at rest.
Documents are private to the writing service unless the shared tier is enabled and the write asks for
it. Erasure removes a subject's documents across every owning service, and the GDPR data export
returns them decrypted, including private ones.

The request and response contract is in [`api.md`](api.md#service-documents); the storage model,
validation bounds and access control are in
[`spec.md` section 7.8](spec.md#78-service-scoped-json-documents). Neither the 32-level nesting
bound nor the 1024-key bound is operator-tunable, and they are not in the table below.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_SVCDOC_ENABLED` | bool | `false` | No | Mounts the `/service/documents/*` routes. This is new surface reachable by every existing client-credentials holder, so enabling it is an explicit operator decision rather than a consequence of upgrading. |
| `VAULT_SVCDOC_SHARED_ENABLED` | bool | `false` | No | Allows a service to publish a document readable by all other services. Without it every document stays private to its writer. |
| `VAULT_SVCDOC_MAX_SIZE` | int | `65536` (64KB) | No | Maximum size of a single document in bytes. |
| `VAULT_SVCDOC_MAX_PER_SUBJECT` | int | `32` | No | Maximum documents one service may hold for one subject. |
| `VAULT_SVCDOC_QUOTA_BYTES` | int | `1048576` (1MB) | No | Total stored bytes per subject, summed across every owning service. |

### Account Erasure & Recovery Escrow

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_RECOVERY_PUBLIC_KEY_FILE` | string | *(none)* | No | Path to an RSA **public** key (PEM) that account erasure encrypts recovery records to. When set, every erasure first appends one record to `auth.account_recovery` holding the erased user's id, email, account creation date, roles and display name, encrypted to this key and cryptographically bound to the row it is written to, and the erasure is refused if that write fails. The service holds only the public half, so it can write a record but never read one back; decryption needs the private key, which is kept offline and used by `cmd/recover`. When unset, no escrow record is written and erasure is final at the moment the cascade completes -- startup logs a warning so the choice is deliberate. Enabling it means retaining personal data past an erasure request: set `VAULT_RECOVERY_RETENTION_DAYS` too, and disclose it in the end-user privacy notice (see `docs/PRIVACY.md` §3.1, §4, §5.3). |
| `VAULT_RECOVERY_RETENTION_DAYS` | int (days) | `0` (disabled) | No | Retention horizon for account-recovery escrow records. A background sweeper runs at startup and every 6h, deleting records older than this. The escrow is append-only and exempt from the erasure cascade, so GDPR Art. 5(1)(e) is what caps its lifetime -- an Operator that configures a recovery key should set a horizon covering the window in which a mistaken or malicious deletion would still be noticed and reversed. Left at `0`, nothing is ever purged: the escrow holds the only recoverable copy of an erased account, so destroying it is an explicit operator choice. `vault cleanup-recovery --retention-days N` performs the same purge on demand, and is the only other supported removal path (both application roles have DELETE revoked on the table). |

### Seeding

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_SEED_FILE` | string | *(none)* | No | Path to a JSON file for declarative client and user seeding at startup. When set, the file is loaded and processed idempotently on the server path only, after the CLI check, so an admin subcommand such as `vault list-clients` does not create the declared clients and users as a side effect. To seed on demand, use the `vault seed` subcommand. Existing entries (matched by client name or user email) are skipped. Client secrets are generated and delivered through `VAULT_FIRST_BOOT_CREDENTIAL_FILE` (or to a terminal), never to the process log. See `seed.example.json` for the file format. |
| `VAULT_FIRST_BOOT_CREDENTIAL_FILE` | string | *(none)* | Conditional | Path a first-boot credential is appended to (`KEY=VALUE`, mode `0600`). Three things are minted exactly once with no second chance to show them: the admin CLI token (when `ADMIN_TOKEN_FILE` is unset), each seeded client secret, and the admin gateway's first `super_admin` password. They used to go to stdout, which under Kubernetes is the pod log. They now go here, or to stdout only when stdout is a terminal. With neither available the minting step refuses rather than storing the hash of a credential nobody holds. An existing path must already be a regular file no wider than `0600` (a symlink fails that test). A Kubernetes pod is not a terminal, so a seeded or first-boot install without this path fails at seed time. The Helm chart sets it to `firstBootCredential.path`. |

### Key Rotation

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_KEY_ROTATION_DB` | bool | `false` | No | Enable database-backed signing key storage and rotation. When `false` (default), the existing file-based `SIGNING_KEY_FILE` behavior is used. |
| `VAULT_KEY_ROTATION_INTERVAL` | duration | `720h` (30 days) | No | How old the active signing key may get before the scheduler rotates it. Only consulted when `VAULT_KEY_ROTATION_DB=true`. Zero or less disables the scheduler, which is how an operator who rotates through `POST /admin/keys/rotate` turns automatic rotation off. `vault rotate-jwks` writes a PKCS#1 key file and a discarded UUID; it does not drive this path and cannot be mounted as `SIGNING_KEY_FILE`. Distinct from `VAULT_KEY_REFRESH_INTERVAL` (how often a pod re-reads the store) and `VAULT_KEY_RETENTION_PERIOD` (how long a retired key lingers afterwards). |
| `VAULT_KEY_RETENTION_PERIOD` | duration | `1h` | No | How long retired signing keys remain in JWKS after rotation. Tokens signed with retired keys are still validated during this window. |
| `VAULT_AUDIT_RETENTION_DAYS` | int (days) | `0` (disabled) | No | Retention horizon for audit entries. A background sweeper runs at startup and every 6h, deleting entries older than this. Audit rows hold personal data (user ID, IP, user agent, fingerprint hash), so GDPR Art. 5(1)(e) caps how long they may be kept — an Operator processing personal data should set this. Left at `0`, nothing is ever purged: silently deleting security logs is not a safe default. `vault cleanup-audit` is retired: it prints an error and writes nothing. No admin tier holds an audit-delete permission. The sweeper is the only sanctioned removal path. |
| `VAULT_KEY_REFRESH_INTERVAL` | duration | `60s` | No | How often pods refresh signing keys from the database. Lower values provide faster rotation propagation at the cost of more DB queries. |

When `VAULT_KEY_ROTATION_DB=true`, signing keys are stored encrypted (AES-256-GCM with master key) in PostgreSQL. On first boot, if `SIGNING_KEY_FILE` is present, the PKCS#8 PEM is imported into the database (`LoadSigningKeyPEM`); otherwise, a new RSA-2048 key is generated. A PKCS#1 file, including `vault rotate-jwks` output, fails that import at startup. All pods share the same keys via periodic database polling. Runtime key management (rotate, list, revoke) is performed via the admin gateway (`cmd/admin-gateway/`), which provides mTLS + RBAC + session authentication. CLI admin commands remain available via pod exec.

Revocation is terminal. The kid is `KIDFromPublicKey` (SHA-256 of the PKIX DER of the public key, not the modulus alone), so an import of the same PKCS#8 PEM always addresses the same row; a revoked row is never reactivated by it. If `SIGNING_KEY_FILE` is still mounted when the key it holds is revoked, the next startup fails with `keystore: key is revoked` naming the kid instead of bringing the revoked key back as active. Rotate to a new key (which writes a new kid) rather than re-importing the revoked one. Revoking the only active key also leaves the deployment with nothing to sign with: pods stop issuing tokens and log `keystore: no active signing key` until a rotation supplies one. Rotate first, then revoke. `vault rotate-jwks` is not a rotation: it writes PKCS#1 the importer cannot parse.

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
| `VAULT_OIDC_<NAME>_CLIENT_SECRET_FILE` | string | *(none)* | Conditional | Path to file containing the client secret. There is no inline `VAULT_OIDC_<NAME>_CLIENT_SECRET` variable; only the `_FILE` form is read. |
| `VAULT_OIDC_<NAME>_SCOPES` | string | `openid email profile` | No | Space-separated scopes to request. |

### WebAuthn

WebAuthn/FIDO2 passkey configuration is derived from other settings rather than having its own env vars:

- **RP ID** (Relying Party Identifier) -- extracted as the hostname from `VAULT_ORIGIN`.
- **RP Origin** -- the full `VAULT_ORIGIN` value.
- **RP Display Name** -- the `VAULT_APP_NAME` value.

If `VAULT_ORIGIN` is unset or unparseable, RP ID falls back to `localhost`.

### IP intelligence

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `VAULT_IPINTEL_DATA` | string | *(none)* | No | Filesystem path to a replacement IP-intelligence blob. When set, readable and valid, that file is used instead of the blob compiled into the binary. An unreadable or structurally invalid override is ignored and the process falls back to the embedded table; it does not refuse to start. Empty uses the embedded blob. The table is what flags VPN, hosting and Tor addresses. Those addresses consume the login, register and password-reset buckets at triple weight so they meet the ordinary 429 sooner (`internal/server/server.go:420`). They are never answered 403. The OAuth callback is not weighted. A failed load of the embedded table leaves an empty one and the weight is inert. |

---

## Secret Loading (`_FILE` Convention)

All sensitive configuration values use the `_FILE` suffix convention. The env var contains a **file path**, not the secret itself. At startup, Vault42:

1. Reads the env var (e.g., `MASTER_KEY_FILE=/run/secrets/master-key`).
2. Reads the file at that path.
3. Trims leading/trailing whitespace from the contents.
4. If `VAULT_SECRET_FILE_CONSUME=true` (exact string), zeros **and removes** the file (defense in depth). By default the file is left intact: the canonical deployment mounts secrets read-only where zeroing is a no-op, and on a writable real keyfile an unconditional wipe would destroy the operator's secret on first read.
5. Stores the value in memory only.

This design ensures secrets never appear in environment variable listings (`/proc/*/environ`, `docker inspect`, Kubernetes `kubectl describe pod`, etc.).

`VAULT_SECRET_FILE_CONSUME` (bool, default `false`): when `true`, secrets the **vault** binary loads through `config.LoadSecret` / `LoadSecretBinary` (and `ADMIN_TOKEN_FILE` when the CLI reads it) are zeroed and deleted from disk after they are read. Leave it unset when the same keyfile must survive a restart. Two readers do not follow that convention:

- `BRIDGE_ADMIN_TOKEN_FILE` is always overwritten with zeros after the first read (`cmd/bridge/config.go`). The flag is ignored. The file is not deleted. A writable token file is destroyed on first start; a read-only Secret mount leaves the file intact because the overwrite fails.
- The admin gateway's own `loadSecret` (`DB_ADMIN_PASSWORD_FILE`, `VAULT_PEPPER_FILE`, `HMAC_SECRET_FILE`, `VAULT_RECOVERY_PUBLIC_KEY_FILE`) never consumes. Its `MASTER_KEY_FILE` still goes through `config.LoadSecretBinary`, so consume applies there: if vault and the gateway share that file and consume is on, whichever starts first wipes it.

### Variables with `_FILE` Variants

| Secret Variable | Env Var (file path) | Description |
|----------------|---------------------|-------------|
| Master Key | `MASTER_KEY_FILE` | AES-256 key (32 bytes) for TOTP secret encryption |
| Admin Token | `ADMIN_TOKEN_FILE` | Admin CLI token, or its Argon2id hash |
| Pepper | `VAULT_PEPPER_FILE` | Server-side secret added to password hashes |
| HMAC Secret | `HMAC_SECRET_FILE` | HMAC-SHA256 signing key (min 32 bytes in production) |
| Signing Key | `SIGNING_KEY_FILE` | RSA-2048 private key (PKCS#8 PEM, `BEGIN PRIVATE KEY`) for JWT signing. `vault rotate-jwks` writes PKCS#1 and will not load. |
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

### Admin Token Provisioning

The credential the admin CLI accepts lives in `auth.admin_config` under
`admin_token_hash`. `ADMIN_TOKEN_FILE` is how an operator chooses that credential
instead of taking whatever the server mints; it is read by `cli.New` and applied by
`InitAdminToken` before any command runs.

Two file contents are accepted, told apart by the `$argon2id$` prefix:

| File holds | What happens | When to use it |
|---|---|---|
| An Argon2id hash (`$argon2id$v=19$...`) | Stored verbatim | Preferred. The mount then holds no usable credential, so reading the file does not hand anyone the token. |
| A plaintext token | Hashed with Argon2id, then stored | What `scripts/generate-secrets.sh` writes. Simplest, but the token is recoverable from the mount. |

Rules that startup enforces. `Config.Validate` fails in every profile, including `dev`, and the server does not come up:

- The path must exist and be readable. A typo in the path is a startup failure, not a silently generated token.
- The file must not be empty.
- Anything beginning with `$argon2id$` must be a complete PHC hash. A truncated hash can never verify and would lock the CLI out permanently.
- A plaintext token must be at least 16 characters outside the `dev` profile. `dev` warns instead.

With no `ADMIN_TOKEN_FILE` set, first boot generates a 256-bit token and delivers
it through `VAULT_FIRST_BOOT_CREDENTIAL_FILE`, or to stdout only when stdout is a
terminal. It is never written to the process log. Under Kubernetes stdout is not a
terminal, so without that path first boot refuses rather than storing a hash nobody
holds. Provisioning `ADMIN_TOKEN_FILE` is still the better default for anything
beyond a single container you are watching.

The file seeds the credential; it does not keep enforcing it. `vault rotate-admin-token`
replaces the stored hash, and every later boot leaves that rotated hash alone rather
than reverting to the file. When the mounted file is no longer the credential in force,
startup says so on stderr.

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

# TLS. All profiles default to enabled, so this block serves HTTPS directly.
# For ingress or tunnel termination, turn it off and keep the Secure cookie flag:
# export VAULT_TLS_ENABLED=false
# export VAULT_FORCE_SECURE_COOKIES=true
export VAULT_TLS_CERT_FILE=/etc/vault42-tls/tls.crt
export VAULT_TLS_KEY_FILE=/etc/vault42-tls/tls.key

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

When deployed via the Helm chart (`charts/vault/`), environment variables are set through two mechanisms:

1. **ConfigMap** (non-sensitive values) -- generated from `values.yaml` fields like `profile`, `listenAddr`, `origin`, etc. These map directly to the env vars documented above.
2. **Secret volume mounts** (sensitive values) -- a Kubernetes Secret is mounted at `secrets.mountPath` (default: `/run/secrets`), and `_FILE` env vars point to the individual files within it.

**Seed data is a Secret, not a ConfigMap.** `seed.users[].password` is a
credential, and a ConfigMap is stored unencrypted and is readable by anything
holding `get configmaps` in the namespace -- a much wider set than the Secret
readers an operator thinks about. The seed document renders into a Secret and is
mounted read-only at `/etc/vault/seed.json`. If a doc, a values comment or a
runbook of yours still says the seed lives in a ConfigMap, it predates that
change and the passwords it describes were in plaintext.

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
| `forceSecureCookies` | `VAULT_FORCE_SECURE_COOKIES` |
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
| `seed.enabled` | `VAULT_SEED_FILE` (set to `/etc/vault/seed.json` when enabled) |
| `firstBootCredential.path` | `VAULT_FIRST_BOOT_CREDENTIAL_FILE` |
| `database.allowPlaintext` | `VAULT_ALLOW_PLAINTEXT_DB` |
| `metrics.enabled` | `VAULT_METRICS_ENABLED` |
| `metrics.port` | `VAULT_METRICS_ADDR` (`:<port>`) |
| `keyRotation.enabled` | `VAULT_KEY_ROTATION_DB` |
| `adminGateway.clientCNAllowlist` | `ADMIN_GW_CLIENT_CN_ALLOWLIST` |
| `adminGateway.clientCRLFile` | `ADMIN_GW_CLIENT_CRL_FILE` |

Secrets are mapped via `secrets.keys.*`:

| Helm Secret Key | Env Var |
|----------------|---------|
| `secrets.keys.masterKey` | `MASTER_KEY_FILE` |
| `secrets.keys.dbMigPassword` | `DB_MIG_PASSWORD_FILE` |
| `secrets.keys.dbAppPassword` | `DB_APP_PASSWORD_FILE` |
| `secrets.keys.hmacSecret` | `HMAC_SECRET_FILE` |
| `secrets.keys.adminToken` | `ADMIN_TOKEN_FILE` |
| `secrets.keys.redisPassword` | `REDIS_PASS_FILE` |

`forceSecureCookies` defaults to `true`, because `tls.enabled` defaults to `false`:
the chart expects TLS to terminate at an ingress or a tunnel. Outside the `dev`
profile the chart refuses to render when both are false, and names them in the
error. That combination sends the `__Host-refresh_token` cookie without `Secure`,
which a browser discards, and `Config.Validate` refuses to start on it, so the
install would reach the operator as a `CrashLoopBackOff` rather than as a
message. See [TLS and Cookies](#tls-and-cookies).

See `charts/vault/values.yaml` for production defaults and `charts/vault/values-dev.yaml` for the dev overlay.

**Minimum resource requirements (production):** Memory limit must be at least 512 MiB. Each Argon2id operation allocates 46 MiB, and the semaphore allows up to 4 concurrent operations (184 MiB peak). Pods with less than 512 MiB risk OOM kills under authentication load.

---

## Boolean Parsing

Boolean env vars accept `true`, `t`, `yes`, `y`, `on` and `1` as truthy, and
`false`, `f`, `no`, `n`, `off` and `0` as falsy. Case does not matter and
surrounding whitespace is trimmed. An empty value is the same as an unset one:
the profile default applies.

**Any other value refuses to start**, naming the variable. Two parsers used to
share this job and each answered "false" or "use the default" for everything
outside its own set, so `VAULT_MFA_REQUIRED=True` left the deployment
password-only, `VAULT_DPOP_ENABLED=True` left the token endpoints without proof
of possession, and `VAULT_AUTO_MIGRATE=no` on the embedded profile ran the
migrations anyway. A control that was configured must not be able to end up off
with nothing said.

## Duration and Number Parsing

A duration or number that is set but cannot be parsed, or that falls outside the
range its consumer can honor, refuses to start naming the variable. It used to
fall back to the default, so `VAULT_ACCESS_TOKEN_TTL=15` (no unit) silently
issued 15-minute tokens, `VAULT_AUDIT_RETENTION_DAYS=30d` silently disabled the
retention sweeper, and `VAULT_KEY_REFRESH_INTERVAL=0` panicked the key-refresh
goroutine after the listener was already up.

Duration env vars use Go's standard `time.ParseDuration` format:

| Format | Meaning |
|--------|---------|
| `5m` | 5 minutes |
| `1h` | 1 hour |
| `24h` | 24 hours |
| `168h` | 7 days |
| `720h` | 30 days |

There is no silent fallback. A value that cannot be parsed, or that is below the bound its consumer can honor, is a startup failure. The admin gateway and the bridge still fall back to their coded defaults on an unparseable duration or integer, because they do not share `internal/config`'s envcheck.
