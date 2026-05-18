# Vault42

Production-grade JWT authentication server written in Go. Integrated Vue frontend, honeypot mode for threat observation, and only 3 direct dependencies — JWT, Redis, TOTP, CORS, JWKS, and migrations are all hand-rolled.

<!-- badges -->
| | | |
|---|---|---|
| ![Go](https://img.shields.io/badge/Go-1.26.0-00ADD8?style=flat&logo=go&logoColor=white) | ![Vue](https://img.shields.io/badge/Vue-3.5.0-4FC08D?style=flat&logo=vuedotjs&logoColor=white) | ![License](https://img.shields.io/badge/License-MIT-155724?style=flat&labelColor=000) |
| ![Go Tests](https://img.shields.io/badge/Go_Tests-1985-155724?style=flat&labelColor=000) | ![Vue Tests](https://img.shields.io/badge/Vue_Tests-190-155724?style=flat&labelColor=000) | ![Total](https://img.shields.io/badge/Total-2175_tests-155724?style=flat&labelColor=000) |
| ![Go Lines](https://img.shields.io/badge/Go-21194_lines-555?style=flat&labelColor=000) | ![Vue Lines](https://img.shields.io/badge/Vue-5098_lines-555?style=flat&labelColor=000) | ![Coverage](https://img.shields.io/badge/Coverage-70.69%25-7d6e00?style=flat&labelColor=000) |
| ![Go Deps](https://img.shields.io/badge/Go-3_deps-555?style=flat&labelColor=000) | ![Vue Deps](https://img.shields.io/badge/Vue-3_deps-555?style=flat&labelColor=000) | ![Locales](https://img.shields.io/badge/Locales-38-555?style=flat&labelColor=000) |
<!-- /badges -->

## Highlights

- **RS256 JWT** — algorithm whitelist (rejects `none`, `HS256`, all others), fingerprint-bound, 8KB size limit
- **Argon2id** — 46 MiB / 1 iteration, NIST SP 800-63B compliant, 15-char minimum, HIBP breach check
- **Refresh token rotation** — family tracking, single-use, replay detection nukes the entire family
- **WebAuthn/FIDO2** — passkey registration + authentication
- **TOTP 2FA** — RFC 6238, hand-rolled (~80 lines), backup codes for recovery
- **OAuth2/OIDC** — GitHub, Google + Facebook, PKCE S256 enforced, strict redirect URI matching
- **Encrypted identity store** — AES-256-GCM encrypted PII, HMAC-SHA256 pseudonymous keys
- **Encrypted blob storage** — compress-then-encrypt (DEFLATE + AES-GCM), per-user quotas
- **IP access control & geo-fencing** — allowlist/blocklist, dynamic runtime bans, proxy-agnostic
- **Append-only audit log** — DB-level enforcement (app role has no DELETE/TRUNCATE/DDL)
- **Integrated Vue frontend** — embedded in the Go binary via `go:embed`, serves as SPA
- **Honeypot mode** — trap user detection, webhook alerts, full interaction capture
- **Honeypot bridge** — transparent reverse proxy with attacker detection, decoy pages, score-based routing
- **Client credentials** — service-to-service auth grant
- **Device tracking** — session management with fingerprint verification

## Architecture

```
cmd/vault42/              Entry point
cmd/bridge/             Honeypot bridge proxy (standalone, stdlib only)
internal/
  handler/              HTTP handlers (auth, user, oauth, 2fa, password, identity, blobs, admin)
  service/              Business logic (token lifecycle, MFA, HIBP, identity, blobs)
  repository/           PostgreSQL via pgx
  middleware/            Auth, fingerprint, rate limiting, CORS, security headers, IP access
  jwt/                  Stdlib-only RS256 sign/verify, ES256 verify, parsing, claims
  crypto/               Argon2id, AES-256-GCM, HMAC, TOTP, JWKS
  redis/                RESP2 client + connection pool (stdlib net)
  cache/                Pluggable — Redis, in-memory, PostgreSQL
  config/               Env vars + _FILE secret loading + profiles
  server/               HTTP server, TLS 1.3, middleware wiring
  migrate/              SQL migration runner
  model/                Domain types + WebAuthn adapter
  audit/                Append-only audit logger
  email/                SMTP + SendGrid, go:embed HTML templates
  cli/                  Admin CLI (add-client, rotate-jwks, lock-user, seed, etc.)
  seed/                 Declarative JSON seeding for clients and users
  oauth2/               GitHub, Google + Facebook providers
  honeypot/             Trap user detection, webhook alerts
  frontend/             Embedded Vue SPA (go:embed)
  httputil/             JSON helpers, log sanitization
  sanitize/             Input validation
  useragent/            User-Agent parser
packages/vue/           @vault42/vue — composables + i18n (38 locales)
web/                    Vue 3 + Vite + Tailwind SPA
charts/vault42/           Helm chart (production, embedded, honeypot profiles)
migrations/             PostgreSQL DDL (auth, audit, identity, objects schemas)
tests/
  unit/                 Table-driven unit tests
  attack/               Attack vector simulations (alg confusion, replay, injection, timing)
  compliance/           NIST SP 800-63B + OWASP ASVS verification
  integration/          Testcontainers (real PostgreSQL + Redis)
  fuzz/                 Go native fuzzing (JWT, TOTP, registration, email, DPoP)
  browser/              Chromedp browser security tests (separate go.mod)
  honeypot/             Bridge + honeypot E2E tests (honeypot_e2e build tag)
```

## Quick Start

```bash
# Kubernetes dev environment (requires mkcert, docker, kubectl, helm, nginx-ingress)
scripts/deploy-dev.sh
# → https://vault.localhost

# Build from source
CGO_ENABLED=0 go build -ldflags="-s -w" -o vault42 ./cmd/vault42

# ARM64 (RPi5)
CGO_ENABLED=0 GOARCH=arm64 go build -ldflags="-s -w" -o vault42 ./cmd/vault42

# Tests
scripts/t.sh                        # all
scripts/t.sh ./tests/attack/...     # attack suite
scripts/tcount.sh                   # quick count

# Coverage report → docs/test-coverage.md (per-package + per-function breakdown)
scripts/coverage.sh

# Full security pass (govulncheck, gosec, trivy fs, attack suite, coverage).
# Run this before tagging a release — it mirrors the nightly CI workflow.
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

3 direct production dependencies — [full table](docs/deps.md):

| Dependency | Purpose |
|---|---|
| `pgx/v5` | PostgreSQL driver + pool |
| `go-webauthn` | WebAuthn/FIDO2 passkeys |
| `x/crypto` | Argon2id hashing |

Everything else — JWT, Redis, TOTP, CORS, JWKS, config, migrations, password hashing — is stdlib or hand-written.

## Testing

Eight layers: unit, attack simulation (27 vectors), NIST/OWASP compliance, integration (testcontainers), fuzz (5 targets), browser (chromedp), frontend unit (vitest), frontend integration.

Coverage tooling lives in `scripts/`:

| Script | Purpose |
|---|---|
| `scripts/t.sh [path]` | Run Go tests (default: all packages, single path supported) |
| `scripts/tcount.sh` | Fast test-count summary, no execution |
| `scripts/coverage.sh` | Regenerate `docs/test-coverage.md` with per-package + per-function coverage |
| `scripts/security-scan.sh` | Standalone Go + frontend security pass (gosec, govulncheck, staticcheck, pnpm audit, hadolint) |
| `scripts/release-check.sh` | Full pre-release gate — mirrors nightly CI (govulncheck, gosec, trivy fs, attack suite, coverage) |
| `scripts/precommit.sh` | Pre-commit verification: build, vet, gosec, tests, badges, docs |

## Docs

| | |
|---|---|
| [API Reference](docs/api.md) | 42 endpoints, schemas, curl examples |
| [Architecture](docs/architecture.md) | Auth flows, middleware chain, token architecture |
| [Configuration](docs/config.md) | All env vars, profiles, `_FILE` convention |
| [Attack Cheatsheet](docs/cheatsheet.md) | JWT/auth attack vectors with defenses |
| [Specification](docs/spec.md) | Authoritative spec (verified against implementation) |
| [Test Coverage](docs/test-coverage.md) | Per-package coverage breakdown |
| [Dependencies](docs/deps.md) | Full dependency table with stars + versions |

## Security

Found a vulnerability? **Do not open a public issue.**

Email **vault@42-v.com** (Tuta — end-to-end encrypted). See [SECURITY.md](SECURITY.md).

## Disclaimer

**This software is provided "as is", without warranty of any kind.** It is designed with security as a core principle — constant-time comparisons, algorithm whitelisting, least-privilege DB roles, append-only audit — but it is only as secure as the system it is deployed on. **Review the code before deploying to production.** See [LICENSE](LICENSE) (MIT).
