# Vault42

Production-grade JWT authentication server written in Go, with an integrated Vue frontend, honeypot mode for threat observation, and 3 direct production dependencies -- 18 Go modules once everything those three pull in is counted. JWT, Redis, TOTP, CORS, JWKS, and migrations are all hand-rolled.

Vault42 issues its own tokens and is an OAuth2 *client* of other providers. It is not an OAuth2 authorization server and not an OIDC provider: there is no authorize endpoint, no consent screen, and no `redirect_uri` a third-party client registers against it.

<!-- badges -->
| Go | Vue | C# | |
|---|---|---|---|
| ![Go](https://img.shields.io/badge/Go-1.26.6-00ADD8?style=flat&logo=go&logoColor=white) | ![Vue](https://img.shields.io/badge/Vue-3.5.41-4FC08D?style=flat&logo=vuedotjs&logoColor=white) | ![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat&logo=dotnet&logoColor=white) | ![License](https://img.shields.io/badge/License-MIT-155724?style=flat&labelColor=000) |
| ![Go Tests](https://img.shields.io/badge/Tests-4910-155724?style=flat&labelColor=000) | ![Vue Tests](https://img.shields.io/badge/Tests-1305-155724?style=flat&labelColor=000) | ![C# Tests](https://img.shields.io/badge/Tests-264-155724?style=flat&labelColor=000) | ![Total](https://img.shields.io/badge/Total-6479_tests-155724?style=flat&labelColor=000) |
| ![Go Coverage](https://img.shields.io/badge/Coverage-100.00%25_reachable-155724?style=flat&labelColor=000) | ![Vue Coverage](https://img.shields.io/badge/Coverage-99.76%25-155724?style=flat&labelColor=000) | ![C# Coverage](https://img.shields.io/badge/Coverage-100.00%25-155724?style=flat&labelColor=000) | ![Locales](https://img.shields.io/badge/Locales-38-555?style=flat&labelColor=000) |
| ![Go Lines](https://img.shields.io/badge/Lines-48129-555?style=flat&labelColor=000) | ![Vue Lines](https://img.shields.io/badge/Lines-6755-555?style=flat&labelColor=000) | ![C# Lines](https://img.shields.io/badge/Lines-2347-555?style=flat&labelColor=000) | ![Standards](https://img.shields.io/badge/Standards-11-555?style=flat&labelColor=000) |
| ![Go Deps](https://img.shields.io/badge/Deps-3-555?style=flat&labelColor=000) | ![Vue Deps](https://img.shields.io/badge/Deps-3-555?style=flat&labelColor=000) | ![C# Deps](https://img.shields.io/badge/Deps-6-555?style=flat&labelColor=000) | ![Requirements](https://img.shields.io/badge/Requirements-456-555?style=flat&labelColor=000) |
| ![Go Transitive Deps](https://img.shields.io/badge/Transitive-15-555?style=flat&labelColor=000) | ![Vue Transitive Deps](https://img.shields.io/badge/Transitive-95-555?style=flat&labelColor=000) | ![C# Transitive Deps](https://img.shields.io/badge/Transitive-26-555?style=flat&labelColor=000) | ![Total Deps](https://img.shields.io/badge/Deps-148_total-555?style=flat&labelColor=000) |
<!-- /badges -->

## Install

Every release publishes signed container images, a signed Helm chart and the two .NET SDKs.
The commands below need no clone.

```bash
# Helm chart, from the OCI registry the release pushes it to
helm pull oci://ghcr.io/42-v/charts/vault-auth --version 1.0.4

# Images: the server, the mTLS admin gateway, the honeypot bridge
docker pull ghcr.io/42-v/vault42:1.0.4
docker pull ghcr.io/42-v/vault42-admin-gateway:1.0.4
docker pull ghcr.io/42-v/vault42-bridge:1.0.4

# Client SDKs
dotnet add package Vault42.AspNetCore --version 1.0.4
dotnet add package Vault42.Blazor --version 1.0.4
```

A default `helm install` renders, but it will not come up on its own: the Deployment mounts
eight keys out of a Secret you supply and expects a PostgreSQL you already run, because the
chart's bundled one is a development convenience and is off by default.
[docs/deployment-guide.md](docs/deployment-guide.md) is the path from here to a running
install; `scripts/deploy-dev.sh` stands the whole thing up locally against a self-signed CA if
you only want to look at it.

Every artifact above is keyless-signed -- see [Verifying a release](#verifying-a-release).

## Highlights

- **RS256 JWT**: algorithm whitelist (rejects `none`, `HS256`, all others), fingerprint-bound, 8KB size limit
- **Argon2id**: 46 MiB / 1 iteration, per-password salt and server-side pepper, 15-char enforced password minimum outside dev (dev floor 8), HIBP breach check
- **Refresh token rotation**: family tracking, single-use, replay detection nukes the entire family
- **KMS unwrap oracle**: `POST /kms/unwrap` KEK envelope-unwrap, gated by the `kms:unwrap` scope, fail-closed rate limit, synchronous audit, every failure collapsed to one opaque error; the `vault kms wrap` CLI produces envelopes
- **WebAuthn/FIDO2**: passkey registration and authentication
- **TOTP 2FA**: RFC 6238, hand-rolled (~80 lines), backup codes for recovery
- **OAuth2/OIDC login**: GitHub, Google, Facebook, plus generic OIDC (Okta, Auth0, Keycloak, Entra via `VAULT_OIDC_PROVIDERS`); PKCE S256 on every provider with no downgrade path, single-use verifier, and the outbound authorize URL checked to be absolute HTTPS before the browser is sent to it
- **Delegated signing**: `POST /mint` signs an assertion about a subject vault42 never authenticated, for a service that already knows who its caller is. Off unless `VAULT_MINT_ENABLED` is set with a `VAULT_MINT_AUDIENCE` distinct from the origin, gated by the `mint:token` scope on a client credential, fail-closed rate limit, and every refusal audited. Read [docs/security.md](docs/security.md) AR-16 before enabling it
- **Encrypted identity store**: AES-256-GCM encrypted PII, HMAC-SHA256 pseudonymous keys
- **DB-backed signing keys**: encrypted at rest (AES-256-GCM, kid as AAD), multi-pod refresh, zero-downtime rotation via the admin gateway
- **Encrypted blob storage**: compress-then-encrypt (DEFLATE + AES-GCM), per-user quotas
- **Account erasure + escrow**: GDPR right-to-be-forgotten with recoverable encrypted escrow (server holds only a recovery public key), bounded by `VAULT_RECOVERY_RETENTION_DAYS` + sweeper
- **IP access control and geo-fencing**: allowlist/blocklist, dynamic runtime bans, proxy-agnostic
- **Append-only audit log**: DB-level enforcement (app role has no DELETE/TRUNCATE/DDL)
- **mTLS admin plane**: the admin gateway requires a client certificate, and beyond "signed by our CA" it pins the peer's CN and SANs against `ADMIN_GW_CLIENT_CN_ALLOWLIST` and checks `ADMIN_GW_CLIENT_CRL_FILE` on every handshake. Both are optional so an upgrade does not break, and an unset allowlist logs a warning naming what it costs: every certificate the CA ever signed reaches the admin plane, including a decommissioned operator's
- **Integrated Vue frontend**: embedded in the Go binary via `go:embed`, served as an SPA.
  Built into the container images and the release archives; a `go install` build embeds a
  placeholder instead, because it cannot run a frontend build. Run `scripts/build-all.sh`
  first to embed the real dashboard.
- **Honeypot mode**: trap user detection, webhook alerts, full interaction capture
- **Honeypot bridge**: transparent reverse proxy with attacker detection, decoy pages, score-based routing
- **Client credentials**: service-to-service auth grant
- **Device tracking**: session management with fingerprint verification

DPoP (RFC 9449) is a working sender-constraint. With `VAULT_DPOP_ENABLED`, a request that
presents a valid proof gets back a token stamped with that key's JWK thumbprint in `cnf.jkt`,
and every authenticated route then refuses that token unless the request carries a fresh
single-use proof over the matching key, presented under the `DPoP` authorization scheme rather
than `Bearer`. A token issued without a proof carries no `cnf.jkt` and stays an ordinary bearer
token, which is what keeps non-DPoP clients working with the flag on. The binding is what makes
the proof checking worth anything: a proof never compared against a key the token committed to
only demonstrates that the caller can sign something.

Two limits are real. Refresh tokens are not sender-bound: only the access token and the 2FA
challenge token carry `cnf.jkt`, so a stolen refresh token can still be redeemed on its own, and
the constraint on the pair it returns is whatever key that redemption presents. And there is no
`DPoP-Nonce`, so a proof's freshness rests on its own `iat` inside a five-minute window plus the
single-use JTI cache; the server cannot require a proof minted after a value it chose.

## Architecture

```text
cmd/vault/              Entry point (also hosts the `vault ...` admin CLI)
cmd/admin-gateway/      mTLS admin gateway (key rotation, erasure, RBAC), with the
                        client-certificate CN/SAN allowlist and CRL check
cmd/bridge/             Honeypot bridge proxy (standalone, stdlib only)
cmd/recover/            Offline account-recovery tool (decrypts erasure escrow)
internal/
  handler/              HTTP handlers (auth, user, oauth, 2fa, password, identity, blobs,
                        kms, mint, service documents). Admin HTTP is adminapi, not here
  service/              Business logic (token lifecycle, MFA, HIBP, identity, blobs,
                        erasure, mint, service documents, the retention sweepers)
  repository/           PostgreSQL via pgx
  adminapi/             Admin gateway HTTP layer (RBAC, sessions, email branding)
  middleware/           Auth, fingerprint, rate limiting, CORS, DPoP, security headers, IP access
  dpop/                 Carries a validated proof's thumbprint from middleware to issuance,
                        which is what lets a minted token commit to the key (cnf.jkt)
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
                        package; WebAuthn lives in model, repository, handler and server)
  rbac/                 Admin role/permission checks
  metrics/              Hand-rolled Prometheus text exposition
  audit/                Append-only audit logger
  email/                SMTP + SendGrid, go:embed HTML templates, per-app white-label
  deferwork/            Bounded pool for work that outlives its request, drained on shutdown,
                        so an unauthenticated caller cannot decide how many goroutines run
  firstboot/            Hands a once-only generated credential to the operator without
                        putting it in the process log
  ipintel/              Embedded IP-intelligence table (VPN, hosting, Tor) and its lookup
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
site/                   Static landing page for vault.42-v.com (no build step)
charts/vault/           Helm chart (default, embedded, honeypot, bridge, dev, local values)
migrations/             PostgreSQL DDL (auth, audit, identity, objects schemas)
tests/
  unit/                 Table-driven unit tests
  attack/               Attack vector simulations (alg confusion, replay, injection, timing, DPoP)
  compliance/           NIST SP 800-63B + OWASP ASVS verification
  spec/                 Executable assertions about the chart, the workflows and the wiring
  integration/          Testcontainers (real PostgreSQL + Redis)
  e2e/                  End-to-end flows, including a multi-replica keystore setup
  fuzz/                 Go native fuzzing (JWT, TOTP, Argon2, ES256, email, identity, kid,
                        DPoP, PKCE, OAuth state, mint, service documents)
  browser/              Chromedp browser security tests (separate go.mod)
  e2e-browser/          Playwright suite (separate toolchain)
  admin/                Admin-gateway E2E over real mTLS
  honeypot/             Bridge + honeypot E2E tests (honeypot_e2e build tag)
  stress/               Load suite (stress build tag)
  mocks/, testutil/     Shared fakes and container-runtime detection
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
| `embedded` | In-memory | RPi5 / edge (~60 MB RAM), 5 conns. Point it at a PostgreSQL you run; the chart's bundled one is a development convenience, off by default, and did not start on any released version -- see [deployment-guide](docs/deployment-guide.md#the-bundled-postgresql) |
| `honeypot` | Redis | Production defaults plus auto-migrate and the embedded SPA, so the trap looks like a real deployment. Trap user detection and webhook alerts |
| `dev` | Inherits production | Auto-migrate, permissive CORS, 24h refresh TTL, 5s shutdown. Logging is not louder in dev; there is no log-level setting |

## Dependencies

3 direct production dependencies, and 15 more the build links through them ([full table](docs/deps.md)):

| Dependency | Purpose |
|---|---|
| `pgx/v5` | PostgreSQL driver + pool |
| `go-webauthn` | WebAuthn/FIDO2 passkeys |
| `x/crypto` | Argon2id hashing |

Everything else (JWT, Redis, TOTP, CORS, JWKS, config, migrations, password hashing) is stdlib or hand-written.

The badge table splits the same way for the frontend and the .NET SDKs. The Deps row is what each of them declares and can drop; the Transitive row is what those declarations resolve to, and it is the one a supply-chain question is really about. The transitive figures come from what each toolchain resolves rather than from a manifest: `go list -deps ./...`, the pnpm lockfile, and the NuGet restore graph. Go's direct count is filtered through the same build closure, so requires only the test suites import are not credited to the release.

## Testing

Twelve Go suites under `tests/`: unit, attack simulation (93 vector files), NIST/OWASP/OpenSSF-Scorecard compliance, spec (chart and workflow assertions), integration (testcontainers), end-to-end including a multi-replica keystore, fuzz (18 targets), browser (chromedp), Playwright, admin-gateway E2E over real mTLS, honeypot E2E (bridge + trap flows), and stress. The frontend adds its own vitest runs in `web/` and `packages/vue/`, and the published .NET SDKs carry an xunit suite gated at 100.00% line coverage by `scripts/dotnet-coverage.sh`. Several suites need a container runtime, a build tag or a browser and are skipped without one; the `Suites CI cannot run` job fails the build if a suite neither ran nor said why.

Coverage tooling lives in `scripts/`:

| Script | Purpose |
|---|---|
| `scripts/t.sh [path]` | Run Go tests (default: all packages, single path supported) |
| `scripts/tcount.sh` | Test-count summary. It runs the suite; what it saves you is reading the output, not the wait |
| `scripts/coverage.sh` | Regenerate `docs/test-coverage.md` with per-package + per-function coverage |
| `scripts/dotnet-coverage.sh` | Build, test and coverage-gate the published .NET SDKs (floor 100.00, no exclusions) |
| `scripts/security-scan.sh` | Standalone Go + frontend security pass (go vet, gosec, govulncheck, staticcheck, pnpm audit, hadolint) |
| `scripts/release-check.sh` | Full pre-release gate, twelve of them: the security pass (govulncheck, gosec, trivy fs, attack suite, coverage) plus version consistency, module hygiene, golangci-lint at zero, helm, doc chart paths, a changelog section for the version, and a clean tree |
| `scripts/precommit.sh` | Pre-commit verification: build, vet, gosec, tests, badges, docs |

## Docs

Full index with one line on each document: [docs/README.md](docs/README.md).

| | |
|---|---|
| [Specification](docs/spec.md) | Authoritative spec (verified against implementation) |
| [Architecture](docs/architecture.md) | Auth flows, middleware chain, token architecture |
| [Configuration](docs/config.md) | Every env var, profiles, `_FILE` convention, fail-closed overrides |
| [API Reference](docs/api.md) | 105 endpoints, schemas, curl examples: 62 on the main server, 43 on the admin gateway |
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

Email **<vault@42-v.com>** (Tuta, end-to-end encrypted). See [SECURITY.md](SECURITY.md) for the
intake process, how a security fix ships, the supported-version and semver policy, and how to
verify a release with `cosign`.

### Verifying a release

Images, the Helm chart and the release checksum file are all signed with keyless cosign, and
the images carry SBOM and SLSA provenance attestations:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/42-v/vault42/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/42-v/vault42:1.0.4
```

Full instructions, covering all four artifact classes, are in
[SECURITY.md](SECURITY.md#verifying-releases).

## Disclaimer

**This software is provided "as is", without warranty of any kind.** It is designed with security as a core principle (constant-time comparisons, algorithm whitelisting, least-privilege DB roles, append-only audit), but it is only as secure as the system it is deployed on. **Review the code before deploying to production.** See [LICENSE](LICENSE) (MIT).
