# Admin Gateway

Vault42 Admin Gateway is a standalone binary (`cmd/admin-gateway/`) for RBAC-protected administrative operations. It binds exclusively to loopback, requires mutual TLS (mTLS) client certificates, and enforces role-based permissions through 6 layers of defense-in-depth.

All admin operations -- key management, user management, audit log access, client management, and admin account management -- are served exclusively through the admin gateway. The main vault42 binary does not expose any admin endpoints.

---

## Architecture

```
Operator (SSH tunnel) ──► 127.0.0.1:9443 (mTLS) ──► Admin Gateway
                                                       │
                                                       ├── RBAC + Session Auth
                                                       ├── Audit Logging
                                                       └── PostgreSQL (vault_admin role)
```

The admin gateway is a separate Go binary with its own:
- Database role (`vault_admin`) -- full CRUD on admin tables, read on user tables plus lock/unlock and erasure
- TLS configuration -- mTLS with client certificate verification
- Session system -- 64-byte tokens, SHA256-hashed, stored in `auth.admin_sessions`
- RBAC model -- hardcoded in Go (not configurable via SQL, preventing injection-based escalation)
- Server-rendered HTML dashboard -- no client-side JavaScript frameworks

---

## 6-Layer Local-Only Enforcement

Any single layer failure cannot compromise the gateway:

| Layer | Mechanism | Effect |
|-------|-----------|--------|
| 1 | Kubernetes `hostNetwork: true` | Binds to node loopback only |
| 2 | NetworkPolicy deny-all ingress | No pod-to-pod or external traffic |
| 3 | No Kubernetes Service created | Only SSH tunnel or direct node access |
| 4 | mTLS (`RequireAndVerifyClientCert`) | Client certificate required |
| 5 | `LocalOnly` middleware | Rejects non-loopback `RemoteAddr` |
| 6 | `RejectProxyHeaders` middleware | Blocks `X-Forwarded-*`, `Via`, `Forwarded` headers |

---

## RBAC Model

Three roles with strict hierarchy (hardcoded in `internal/rbac/`):

| Role | Inherits | Additional Permissions |
|------|----------|----------------------|
| `viewer` | -- | List/read keys, audit, users, sessions, clients, config, metrics |
| `operator` | `viewer` | Rotate/revoke keys, lock/unlock users, revoke sessions, create/revoke/rotate clients, write config |
| `super_admin` | `operator` | Manage/create/revoke admin accounts |

22 permissions total. Permission checks are Go code -- not database queries -- so SQL injection cannot escalate privileges.

---

## Configuration

All configuration via environment variables:

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `ADMIN_GW_LISTEN_ADDR` | string | `127.0.0.1:9443` | No | Bind address (must be loopback) |
| `ADMIN_GW_TLS_CERT_FILE` | string | -- | Yes | Server TLS certificate path |
| `ADMIN_GW_TLS_KEY_FILE` | string | -- | Yes | Server TLS private key path |
| `ADMIN_GW_CLIENT_CA_FILE` | string | -- | Yes | Client CA certificate for mTLS verification |
| `ADMIN_GW_SESSION_TTL` | duration | `1h` | No | Admin session lifetime |
| `ADMIN_GW_MAX_FAILED_LOGINS` | int | `5` | No | Failed login attempts before lockout |
| `ADMIN_GW_LOCKOUT_DURATION` | duration | `30m` | No | Account lockout duration |
| `ADMIN_GW_AUTO_MIGRATE` | bool | `false` | No | Run database migrations on startup |
| `ADMIN_GW_SHUTDOWN_TIMEOUT` | duration | `15s` | No | Graceful shutdown wait time |
| `ADMIN_GW_DEV_MODE` | bool | `false` | No | Relaxes loopback enforcement for development behind ingress controllers. Disables `LocalOnly` and `RejectProxyHeaders` middleware. Also disables killswitch by default. |
| `ADMIN_GW_KILLSWITCH` | bool | `true` | No | When enabled, a non-loopback request triggers a panic (pod crash) instead of a 403. The crash signals a security breach and triggers CrashLoopBackOff for immediate visibility. Defaults to `true` in production, `false` in dev mode. |
| `DB_HOST` | string | `localhost` | No | PostgreSQL host |
| `DB_PORT` | string | `5432` | No | PostgreSQL port |
| `DB_NAME` | string | `vault` | No | Database name |
| `DB_SSLMODE` | string | `require` | No | PostgreSQL SSL mode |
| `DB_MAX_CONNS` | int | `5` | No | Max database connections |
| `DB_ADMIN_PASSWORD_FILE` | string | -- | Yes | Path to `vault_admin` DB password |
| `MASTER_KEY_FILE` | string | -- | Yes | Path to 32-byte AES-256 master key |

---

## API Endpoints

All endpoints are prefixed with `/admin/`.

### Authentication

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `POST` | `/admin/auth/login` | None (rate-limited 10/min) | -- | Login with username + password + optional TOTP |
| `POST` | `/admin/auth/logout` | Session | -- | Revoke current session |
| `GET` | `/admin/status` | Session | -- | Current admin info + 2FA status |

### TOTP (Two-Factor)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `POST` | `/admin/admins/me/totp/setup` | Session | -- | Generate TOTP secret + QR URI |
| `POST` | `/admin/admins/me/totp/verify` | Session | -- | Verify TOTP code and enable 2FA |

### Key Management

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/keys` | Session + RBAC | `keys:list` | List signing key metadata |
| `POST` | `/admin/keys/rotate` | Session + RBAC | `keys:rotate` | Generate new signing key |
| `DELETE` | `/admin/keys/{kid}` | Session + RBAC | `keys:revoke` | Revoke a signing key |

### User Management

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/users` | Session + RBAC | `users:list` | List users (paginated) |
| `GET` | `/admin/users/{id}` | Session + RBAC | `users:read` | Get user details |
| `POST` | `/admin/users/{id}/lock` | Session + RBAC | `users:lock` | Lock user account |
| `POST` | `/admin/users/{id}/unlock` | Session + RBAC | `users:unlock` | Unlock user account |

### Session Management

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/sessions` | Session + RBAC | `sessions:list` | List active sessions |
| `POST` | `/admin/sessions/revoke-all` | Session + RBAC | `sessions:revoke` | Revoke all sessions |

### Audit Log

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/audit` | Session + RBAC | `audit:read` | Query audit logs (filters: user_id, event_type, since, until) |

### Client Management

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/clients` | Session + RBAC | `clients:list` | List service clients |
| `GET` | `/admin/clients/{id}` | Session + RBAC | `clients:read` | Get client details |
| `POST` | `/admin/clients` | Session + RBAC | `clients:create` | Create service client |
| `POST` | `/admin/clients/{id}/revoke` | Session + RBAC | `clients:revoke` | Revoke client |
| `POST` | `/admin/clients/{id}/rotate-secret` | Session + RBAC | `clients:rotate` | Rotate client secret |

### Config

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/config` | Session + RBAC | `config:read` | Read configuration |
| `PUT` | `/admin/config` | Session + RBAC | `config:write` | Update configuration |

### Metrics

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/metrics` | Session + RBAC | `metrics:read` | Get operational metrics |

### Admin User Management

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/admin/admins` | Session + RBAC | `admins:manage` | List admin accounts |
| `POST` | `/admin/admins` | Session + RBAC | `admins:create` | Create admin account (20-char min password) |
| `POST` | `/admin/admins/{id}/revoke` | Session + RBAC | `admins:revoke` | Revoke admin (prevents self-revocation) |

### HTML Dashboard

| Path | Description |
|------|-------------|
| `/admin/login` | Login form |
| `/admin/` | Dashboard |
| `/admin/ui/users` | User management |
| `/admin/ui/keys` | Signing key management |
| `/admin/ui/sessions` | Session browser |
| `/admin/ui/audit` | Audit log viewer |
| `/admin/ui/clients` | Service client management |
| `/admin/ui/admins` | Admin account management |
| `/admin/ui/config` | Configuration |
| `/admin/static/*` | CSS + JS assets |

---

## Database Schema

Migration `001_initial_schema.sql` creates (among other tables):

- **`auth.admin_roles`** -- Reference table: `viewer`, `operator`, `super_admin` with description and rank
- **`auth.admin_users`** -- UUID id, unique username, Argon2id password hash, role (FK), encrypted TOTP secret, TOTP verified flag, last_totp_counter (replay prevention), locked_until, failed_login_count, timestamps, created_by (self-referential FK)
- **`auth.admin_sessions`** -- Session id, admin_id (FK with CASCADE), SHA256 token hash, IP, user agent, timestamps, revoked flag

### Database Roles

| Role | Scope |
|------|-------|
| `vault_admin` | Full CRUD on admin tables, read on user tables plus lock/unlock and `EXECUTE` on the erasure tombstone, full on clients + config, read + append on audit |
| `vault_app` | SELECT only on admin tables (for verification), no INSERT/UPDATE/DELETE |

---

## First Boot

On first startup, if no admin accounts exist, the gateway automatically creates a `super_admin` account named `admin` with a random 64-character hex password. The credentials are printed to stdout (one-time only):

```
admin-gateway: FIRST BOOT -- created super_admin "admin" with password: <random>
```

Change this password immediately after first login.

---

## Killswitch

The admin gateway includes a killswitch mechanism that crashes the pod when a non-loopback request is detected. This is a defense-in-depth measure: if all other layers (bind address, NetworkPolicy, mTLS, etc.) fail and a remote attacker reaches the gateway, the hard crash:

1. **Stops the breach immediately** -- no response is sent, the process terminates
2. **Creates visibility** -- Kubernetes CrashLoopBackOff triggers alerting and is visible in `kubectl get pods`
3. **Leaves an audit trail** -- a best-effort audit entry (`admin:killswitch_triggered`, risk score 100) is written before the crash

The killswitch is enabled by default (`ADMIN_GW_KILLSWITCH=true`) and disabled automatically in dev mode. The Recovery middleware explicitly re-panics killswitch signals -- it cannot accidentally swallow them.

## Database Role Separation

The admin gateway uses its own database role (`vault_admin`) with different privileges from the main API role (`vault_app`):

| Table | `vault_app` | `vault_admin` |
|-------|-------------|---------------|
| `auth.users` | SELECT, INSERT, DELETE + column-level UPDATE (excludes `id`, `email`, `created_at`, `deleted`, `deleted_at`, `banned`, `ban_reason`, `disabled`; `email_verified` and `import_pending` narrowed by trigger, below) | SELECT, INSERT (import) + column-level UPDATE on `locked_until` and `failed_login_count` only |
| `auth.clients` | SELECT, INSERT (narrowed by trigger, below) | SELECT, INSERT, UPDATE |
| `auth.admin_config` | SELECT, INSERT, UPDATE | SELECT, INSERT, UPDATE, DELETE |
| `auth.admin_users` | none (revoked in 002) | Full CRUD |
| `auth.admin_sessions` | none (revoked in 002) | Full CRUD |
| `auth.app_roles` | SELECT | SELECT, INSERT, DELETE |
| `auth.signing_keys` | SELECT, INSERT, UPDATE, DELETE (narrowed by trigger, below) | SELECT, INSERT, UPDATE |
| `audit.audit_log` | SELECT, INSERT | SELECT, INSERT |

`vault_app`'s DELETE on `auth.signing_keys` is the one grant in this table that a
trigger, rather than the grant itself, makes safe. It exists so the retention
sweep can reap retired keys, and PostgreSQL has no row scope for a privilege, so
the bare grant would also cover the active key and every retired key still
verifying live tokens. Migration 020 pairs it with `signing_keys_reap_scope`, a
`BEFORE DELETE` trigger that refuses any row outside the sweep's predicate.

That trigger deliberately says nothing about a revoked row. Same-event triggers
fire in name order and `signing_keys_reap_scope` sorts ahead of
`signing_keys_revocation_terminal`, so excluding revoked rows from its `WHEN`
clause is what leaves migration 017 as the only guard that answers for a revoked
key. `vault_admin` holds no DELETE here, and 020 states the revoke explicitly so
the absence reads as a decision rather than an oversight.

`vault_app`'s INSERT on `auth.clients` is the other grant a trigger rather than
the grant itself makes safe. The grant exists so declarative seeding can register
clients at startup, and `scopes` is a plain `TEXT[]`, so it also authorized
writing a client row carrying `mint:token` and `kms:unwrap` with a chosen
`secret_hash` and then authenticating as it at `POST /client/token` -- the whole
authorization behind the two privileged endpoints, reachable by INSERT. Migration
023 pairs the grant with `clients_capability_scope_guard`, which refuses any row
carrying a scope in `auth.capability_scopes()` unless the writer holds
`vault_admin`. `POST /admin/clients` is therefore the only way to create a
privileged client: it is gated on `clients:create`, which belongs to
`super_admin` alone, and writes an `admin:client_create` audit row naming the
acting admin. A `VAULT_SEED_FILE` or a `vault add-client` that asks for a
capability scope now fails, loudly, naming the scope. Ordinary client seeding is
unchanged.

The account-state columns of `auth.users` are split the same way, by migration
024. `banned`, `ban_reason` and `disabled` have no UPDATE writer anywhere in the
tree -- they are set once at INSERT by the import path -- so the grant 004 made to
`vault_app` is revoked outright rather than guarded. `email_verified` and
`import_pending` keep theirs, because email confirmation and import claiming are
`vault_app`'s own work, and `users_account_state_transitions` narrows each to the
one direction its writer moves in: an address that is confirmed stays confirmed,
and an account that is claimed stays claimed. `locked_until` is deliberately not
narrowed; see AR-18 in [security.md](security.md).

The erasure cascade behind `DELETE /admin/users/{id}` additionally gives `vault_admin` DELETE on the per-user tables plus column-level `SELECT (user_id)` on `auth.social_accounts`, `auth.password_history`, `auth.totp_secrets`, `auth.webauthn_credentials` and `auth.backup_codes`. PostgreSQL requires SELECT on every column read in a `WHERE` clause, so DELETE alone is not enough to run `DELETE ... WHERE user_id = $1`; the grant is column-level so the role still cannot read the encrypted TOTP secret, the WebAuthn public keys, the backup-code hashes or the password history it is allowed to destroy.

The erasure tombstone is not in that table because it is not a grant. Scrubbing a user row writes `email`, `display_name` and `avatar_url`, and a column grant for those is standing: it authorises `UPDATE auth.users SET email = ... WHERE id = <anyone>` just as much as it authorises the scrub, which is an account takeover because password reset follows the address. Migration 009 made that grant to both roles and migration 015 revoked it. The tombstone now runs inside `auth.erase_user_identity(user_id, tombstone_email)`, a SECURITY DEFINER function owned by the migration role with `EXECUTE` revoked from `PUBLIC` and granted to `vault_app` and `vault_admin`. It refuses any address that is not `deleted-<the id of the row being scrubbed>@<domain>.invalid`, so the one write it can perform is one nobody can receive mail at.

Neither role may purge the audit log: `EXECUTE` on `audit.cleanup_old_entries()` is revoked from `PUBLIC` and granted to `vault_app` alone, which is where the retention sweeper runs.

This separation ensures that even if the main API is compromised (e.g., via SQL injection), the attacker cannot modify admin accounts, clients, or configuration. The admin gateway role is restricted from modifying user identity data (password, email, display name, avatar) -- it can lock/unlock an account and erase one, and nothing else on the user row.

Two database triggers back the Go RBAC model on `auth.admin_users`. `auth.deny_role_escalation` (BEFORE UPDATE) refuses to raise an existing admin's role, and `auth.deny_role_escalation_on_insert` (BEFORE INSERT, migration 016) refuses to create an admin that outranks the creator recorded in `created_by`, or to create one with no creator at all once the first admin exists.

The UPDATE half is a real ceiling: it compares against `OLD.role`, which comes from the row. The INSERT half is not, and this document used to claim otherwise. On an INSERT every value comes from the statement, and `vault_admin` can read `auth.admin_users`, so anything able to write that table can first look up a genuine `super_admin` id and put it in `created_by`. The trigger turns a one-statement backdoor into a two-statement one and enforces a useful invariant against RBAC regressions in Go; it is not a boundary against a caller that reaches the database. What actually closes SQL injection here is that every admin-plane query is parameterised. See AR-14 in [security.md](security.md).

## Security Properties

- **Anti-enumeration**: Login always runs Argon2id, even for non-existent usernames
- **Session tokens**: 64-byte random, SHA256-hashed before database storage
- **TOTP secrets**: Encrypted at rest with AES-256 (master key)
- **TOTP replay prevention**: Each accepted TOTP code's time-step counter is stored per admin. Replayed codes (same or earlier counter) are rejected within the ±1 period window
- **Account lockout**: Configurable failed attempts threshold and lockout duration. Lockout counter is atomic (SQL `RETURNING` clause) -- immune to race conditions under concurrent login attempts
- **Admin revocation**: Deleting an admin CASCADE deletes all sessions -- no race window between session revoke and admin revoke
- **Audit trail**: All admin mutations logged with admin ID, timestamp, IP, user agent
- **No external dependencies**: Uses stdlib HTTP only (no frameworks)
- **RBAC hardcoded**: Permission maps defined in Go code, not database -- immune to SQL injection escalation
- **Security headers**: CSP, HSTS (2 years), X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Permissions-Policy, Cache-Control: no-store (all responses including static assets)
- **Request ID**: Always server-generated (never trusts client `X-Request-ID`)
- **Max body size**: 64KB limit
- **Helm TLS validation**: `adminGateway.tls.secretName` is required when the gateway is enabled -- Helm template fails with a clear error if missing

### Accepted Risks

Full rationale in [Security Decisions & Accepted Risks](security.md) (AR-6 through AR-9).

- **Session timing oracle (AR-6)**: Invalid session tokens return slightly faster than valid ones
- **Session token in sessionStorage (AR-7)**: Required for JS API calls; protected by CSP + 6-layer enforcement
- **Global login rate limit (AR-8)**: Loopback-only means one IP; per-account lockout is the primary defense
- **Client cert CN not validated (AR-9)**: Single-purpose CA is the trust boundary
- **innerHTML for empty states (M5)**: Hardcoded strings only, no interpolated variables

---

## Deployment

### Generate mTLS Certificates

```bash
scripts/generate-admin-certs.sh
```

Generates CA, server, and client certificates in `secrets/admin-gateway/`:
- `ca.crt` -- Certificate Authority
- `server.key`, `server.crt` -- Server certificate (SANs: localhost, 127.0.0.1, ::1)
- `client.key`, `client.crt` -- Client certificate (CN: admin-operator)

### Kubernetes (Helm)

The admin gateway is deployed via Vault42 Helm chart (`charts/vault/templates/admin-gateway.yaml`):

```bash
helm upgrade --install vault42 charts/vault/ \
  -f charts/vault/values.yaml
```

Access via SSH tunnel to the node:

```bash
ssh -L 9443:127.0.0.1:9443 <node>
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:9443/admin/status
```

### Docker (Standalone)

```bash
docker build -t vault42-admin-gateway:dev -f Dockerfile.admin-gateway .

docker run --rm \
  -v ./secrets/admin-gateway:/certs:ro \
  -v ./secrets:/secrets:ro \
  -e ADMIN_GW_TLS_CERT_FILE=/certs/server.crt \
  -e ADMIN_GW_TLS_KEY_FILE=/certs/server.key \
  -e ADMIN_GW_CLIENT_CA_FILE=/certs/ca.crt \
  -e MASTER_KEY_FILE=/secrets/master.key \
  -e DB_ADMIN_PASSWORD_FILE=/secrets/db-admin-password \
  -e DB_HOST=host.docker.internal \
  vault42-admin-gateway:dev
```

### Release Images

Multi-arch images (amd64 + arm64) published to GHCR on release:

```
ghcr.io/42-v/vault42-admin-gateway:<version>
ghcr.io/42-v/vault42-admin-gateway:latest
```

---

## CLI Admin Commands

The main vault42 binary still provides CLI admin commands (rotate, list, revoke keys; manage clients; declarative seeding) via `--admin-*` flags. These require pod exec access (shell access to the running container), which provides equivalent security to the admin gateway's SSH tunnel. The CLI uses the DB-stored admin token hash for authentication.

Declarative seeding is also available at startup via the `VAULT_SEED_FILE` env var, which loads a JSON file and idempotently creates clients and users before the server starts. See `seed.example.json` for the file format. A seeded client may not carry a vault42 capability scope (`mint:token`, `kms:unwrap`, `svcdoc:read`, `svcdoc:write`, `admin`, `admin:read`, `admin:write`): the seeder runs under `vault_app` and migration 023 reserves those for `POST /admin/clients`, so a seed file asking for one aborts startup naming the scope.
