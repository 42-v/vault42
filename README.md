# Vault42

Production-grade JWT authentication server written in Go, with an integrated Vue frontend, honeypot mode for threat observation, and only 3 direct dependencies. JWT, Redis, TOTP, CORS, JWKS, and migrations are all hand-rolled.

<!-- badges -->
| | | |
|---|---|---|
| ![Go](https://img.shields.io/badge/Go-1.26.6-00ADD8?style=flat&logo=go&logoColor=white) | ![Vue](https://img.shields.io/badge/Vue-3.5.38-4FC08D?style=flat&logo=vuedotjs&logoColor=white) | ![License](https://img.shields.io/badge/License-MIT-155724?style=flat&labelColor=000) |
| ![Go Tests](https://img.shields.io/badge/Go_Tests-3385-155724?style=flat&labelColor=000) | ![Vue Tests](https://img.shields.io/badge/Vue_Tests-1207-155724?style=flat&labelColor=000) | ![Total](https://img.shields.io/badge/Total-4592_tests-155724?style=flat&labelColor=000) |
| ![Go Lines](https://img.shields.io/badge/Go-31410_lines-555?style=flat&labelColor=000) | ![Vue Lines](https://img.shields.io/badge/Vue-6334_lines-555?style=flat&labelColor=000) | ![Coverage](https://img.shields.io/badge/Coverage-100.00%25_reachable-155724?style=flat&labelColor=000) |
| ![Go Deps](https://img.shields.io/badge/Go-3_deps-555?style=flat&labelColor=000) | ![Vue Deps](https://img.shields.io/badge/Vue-3_deps-555?style=flat&labelColor=000) | ![Locales](https://img.shields.io/badge/Locales-38-555?style=flat&labelColor=000) |
<!-- /badges -->

## Highlights

- **RS256 JWT**: algorithm whitelist (rejects `none`, `HS256`, all others), fingerprint-bound, 8KB size limit
- **Argon2id**: 46 MiB / 1 iteration, per-password salt and server-side pepper, 15-char default password minimum over an enforced floor of 8 outside the dev profile (see [CR-31](docs/COMPLIANCE.md#accepted-risks)), HIBP breach check
- **Refresh token rotation**: family tracking, single-use, replay detection nukes the entire family
- **KMS unwrap oracle**: `POST /kms/unwrap` KEK envelope-unwrap, gated by the `kms:unwrap` scope, fail-closed rate limit, synchronous audit, every failure collapsed to one opaque error; the `vault kms wrap` CLI produces envelopes
- **WebAuthn/FIDO2**: passkey registration and authentication
- **TOTP 2FA**: RFC 6238, hand-rolled (~80 lines), backup codes for recovery
- **OAuth2/OIDC**: GitHub, Google, Facebook, plus generic OIDC (Okta, Auth0, Keycloak, Entra via `VAULT_OIDC_PROVIDERS`); PKCE S256 enforced, strict redirect URI matching
- **Encrypted identity store**: AES-256-GCM encrypted PII, HMAC-SHA256 pseudonymous keys
- **DB-backed signing keys**: encrypted at rest (AES-256-GCM, kid as AAD), multi-pod refresh, zero-downtime rotation via the admin gateway
- **Encrypted blob storage**: compress-then-encrypt (DEFLATE + AES-GCM), per-user quotas
- **Account erasure + escrow**: GDPR right-to-be-forgotten with recoverable encrypted escrow (server holds only a recovery public key), bounded by `VAULT_RECOVERY_RETENTION_DAYS` + sweeper
- **IP access control and geo-fencing**: allowlist/blocklist, dynamic runtime bans, proxy-agnostic
- **Append-only audit log**: DB-level enforcement (app role has no DELETE/TRUNCATE/DDL)
- **Integrated Vue frontend**: embedded in the Go binary via `go:embed`, served as an SPA.
  Built into the container images and the release archives; a `go install` build embeds a
  placeholder instead, because it cannot run a frontend build. Run `scripts/build-all.sh`
  first to embed the real dashboard.
- **Honeypot mode**: trap user detection, webhook alerts, full interaction capture
- **Honeypot bridge**: transparent reverse proxy with attacker detection, decoy pages, score-based routing
- **Client credentials**: service-to-service auth grant
- **Device tracking**: session management with fingerprint verification

DPoP (RFC 9449) is present but **experimental and not a working control**: `VAULT_DPOP_ENABLED`
mounts middleware that validates a presented proof's structure, method, URI, freshness and
single-use JTI, but no issuance path emits the `cnf.jkt` claim that would bind a token to a key,
so nothing is sender-constrained and a request with no proof passes through. Do not count it as
replay protection. See [docs/security.md](docs/security.md) AR-10.

## Architecture

```
cmd/vault/              Entry point (also hosts the `vault ...` admin CLI)
cmd/admin-gateway/      mTLS admin gateway (key rotation, erasure, RBAC)
cmd/bridge/             Honeypot bridge proxy (standalone, stdlib only)
cmd/recover/            Offline account-recovery tool (decrypts erasure escrow)
internal/
  handler/              HTTP handlers (auth, user, oauth, 2fa, password, identity, blobs, admin, kms)
  service/              Business logic (token lifecycle, MFA, HIBP, identity, blobs, erasure)
  repository/           PostgreSQL via pgx
  adminapi/             Admin gateway HTTP layer (RBAC, sessions, email branding)
  middleware/           Auth, fingerprint, rate limiting, CORS, DPoP, security headers, IP access
  jwt/                  Stdlib-only RS256 sign/verify, ES256 verify, parsing, claims
  crypto/               Argon2id, AES-256-GCM, HMAC, TOTP, JWKS, DPoP
  kms/                  KEK envelope-unwrap oracle (HKDF-derived per-kid KEKs)
  keystore/             DB-backed signing keys, encrypted at rest, multi-pod refresh
  redis/                RESP2 client + connection pool (stdlib net)
  cache/                Pluggable: Redis, in-memory, PostgreSQL
  config/               Env vars, _FILE secret loading, profiles
  server/               HTTP server, TLS 1.3, middleware wiring
  migrate/              SQL migration runner
  model/                Domain types + WebAuthn adapter (there is no internal/webauthn
                        package; WebAuthn lives in model, repository, service and handler)
  rbac/                 Admin role/permission checks
  metrics/              Hand-rolled Prometheus text exposition
  audit/                Append-only audit logger
  email/                SMTP + SendGrid, go:embed HTML templates, per-app white-label
  cli/                  Admin CLI (add-client, rotate-jwks, list-clients, seed, etc.)
  seed/                 Declarative JSON seeding for clients and users
  oauth2/               GitHub, Google, Facebook, and generic OIDC providers
  honeypot/             Trap user detection, webhook alerts
  frontend/             Embedded Vue SPA (go:embed)
  httputil/             JSON helpers, log sanitization
  sanitize/             Input validation
  useragent/            User-Agent parser
packages/vue/           @vault42/vue: composables + i18n (38 locales)
packages/dotnet/        Vault42.AspNetCore + Vault42.Blazor (published to nuget.org)
web/                    Vue 3 + Vite + Tailwind SPA
charts/vault/           Helm chart (production, embedded, honeypot profiles)
migrations/             PostgreSQL DDL (auth, audit, identity, objects schemas)
tests/
  unit/                 Table-driven unit tests
  attack/               Attack vector simulations (alg confusion, replay, injection, timing, DPoP)
  compliance/           NIST SP 800-63B + OWASP ASVS verification
  integration/          Testcontainers (real PostgreSQL + Redis)
  fuzz/                 Go native fuzzing (JWT, TOTP, Argon2, ES256, email, identity, kid, DPoP)
  browser/              Chromedp browser security tests (separate go.mod)
  honeypot/             Bridge + honeypot E2E tests (honeypot_e2e build tag)
```

## Quick Start

```bash
# Kubernetes dev environment (requires mkcert, docker, kubectl, helm, nginx-ingress)
scripts/deploy-dev.sh
# → https://vault.localhost

# Build from source
CGO_ENABLED=0 go build -ldflags="-s -w" -o vault42 ./cmd/vault

# ARM64 (RPi5)
CGO_ENABLED=0 GOARCH=arm64 go build -ldflags="-s -w" -o vault42 ./cmd/vault

# Tests
scripts/t.sh                        # all
scripts/t.sh ./tests/attack/...     # attack suite
scripts/tcount.sh                   # quick count

# Coverage report → docs/test-coverage.md (per-package + per-function breakdown)
scripts/coverage.sh

# Full security pass (govulncheck, gosec, trivy fs, attack suite, coverage).
# Run this before tagging a release; it mirrors the nightly CI workflow.
scripts/release-check.sh
```

## Deployment Profiles

| Profile | Cache | Use Case |
|---|---|---|
| `production` | Redis | Full features, TLS 1.3, external PostgreSQL + Redis |
| `embedded` | In-memory | RPi5 / edge (~60 MB RAM), in-cluster Postgres, 5 conns |
| `honeypot` | Memory | Trap user detection, webhook alerts, embedded frontend |
| `dev` | Inherits production | Debug logging, auto-migrate, permissive CORS, 24h refresh TTL |

## Dependencies

3 direct production dependencies ([full table](docs/deps.md)):

| Dependency | Purpose |
|---|---|
| `pgx/v5` | PostgreSQL driver + pool |
| `go-webauthn` | WebAuthn/FIDO2 passkeys |
| `x/crypto` | Argon2id hashing |

Everything else (JWT, Redis, TOTP, CORS, JWKS, config, migrations, password hashing) is stdlib or hand-written.

## Testing

Nine layers: unit, attack simulation (60+ vector files), NIST/OWASP compliance, integration (testcontainers), fuzz (11 targets), browser (chromedp), honeypot E2E (bridge + trap flows), frontend unit (vitest), frontend integration.

Coverage tooling lives in `scripts/`:

| Script | Purpose |
|---|---|
| `scripts/t.sh [path]` | Run Go tests (default: all packages, single path supported) |
| `scripts/tcount.sh` | Fast test-count summary, no execution |
| `scripts/coverage.sh` | Regenerate `docs/test-coverage.md` with per-package + per-function coverage |
| `scripts/security-scan.sh` | Standalone Go + frontend security pass (gosec, govulncheck, staticcheck, pnpm audit, hadolint) |
| `scripts/release-check.sh` | Full pre-release gate; mirrors nightly CI (govulncheck, gosec, trivy fs, attack suite, coverage) |
| `scripts/precommit.sh` | Pre-commit verification: build, vet, gosec, tests, badges, docs |

## Docs

Full index with one line on each document: [docs/README.md](docs/README.md).

| | |
|---|---|
| [Specification](docs/spec.md) | Authoritative spec (verified against implementation) |
| [Architecture](docs/architecture.md) | Auth flows, middleware chain, token architecture |
| [Configuration](docs/config.md) | Every env var, profiles, `_FILE` convention, fail-closed overrides |
| [API Reference](docs/api.md) | 54 endpoints, schemas, curl examples |
| [Deployment Guide](docs/deployment-guide.md) | Kubernetes install, KMS root key, upgrades, backup |
| [Admin Gateway](docs/admin-gateway.md) | mTLS admin plane, RBAC model, admin endpoints |
| [Bridge Deployment](docs/bridge.md) | Honeypot bridge proxy |
| [Security & Accepted Risks](docs/security.md) | AR-1 through AR-18: what is deliberately not defended |
| [Attack Cheatsheet](docs/cheatsheet.md) | Attack vectors with defenses and the tests that prove them |
| [Standards Compliance](docs/COMPLIANCE.md) | NIST SP 800-63B, OWASP ASVS, Top 10, RFC family |
| [Privacy Policy](docs/PRIVACY.md) | GDPR posture, data inventory, retention, breach procedure |
| [Test Coverage](docs/test-coverage.md) | Per-package coverage breakdown |
| [Dependencies](docs/deps.md) | Full dependency table with stars + versions |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. `scripts/precommit.sh` is the gate and no hook
runs it, and commits are commitlint-enforced. Releases are cut by pushing a `v*.*.*` tag at a
commit that is already on `main`; nothing in a commit subject triggers one.

## Security

Found a vulnerability? **Do not open a public issue.**

Email **vault@42-v.com** (Tuta, end-to-end encrypted). See [SECURITY.md](SECURITY.md) for the
intake process, how a security fix ships, the supported-version and semver policy, and how to
verify a release with `cosign`.

### Verifying a release

Images, the Helm chart and the release checksum file are all signed with keyless cosign, and
the images carry SBOM and SLSA provenance attestations:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/42-v/vault42/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/42-v/vault42:1.0.0
```

Full instructions, covering all four artifact classes, are in
[SECURITY.md](SECURITY.md#verifying-releases).

## Disclaimer

**This software is provided "as is", without warranty of any kind.** It is designed with security as a core principle (constant-time comparisons, algorithm whitelisting, least-privilege DB roles, append-only audit), but it is only as secure as the system it is deployed on. **Review the code before deploying to production.** See [LICENSE](LICENSE) (MIT).
