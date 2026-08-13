# Test Coverage Report

Generated: 2026-08-13 | Tests: 3776 | Total: 99.36% statement coverage

Measured across the full suite (unit + attack + fuzz + integration +
compliance) against `./internal/...`. Regenerate with `scripts/coverage.sh`.

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.00% |
| `internal/server` | 100.00% |
| `internal/seed` | 100.00% |
| `internal/sanitize` | 100.00% |
| `internal/redis` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/model` | 100.00% |
| `internal/migrate` | 100.00% |
| `internal/middleware` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/kms` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/honeypot` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/config` | 100.00% |
| `internal/cli` | 100.00% |
| `internal/cache` | 100.00% |
| `internal/audit` | 100.00% |
| `internal/oauth2` | 99.71% |
| `internal/handler` | 99.65% |
| `internal/repository/postgres` | 99.59% |
| `internal/adminapi` | 99.54% |
| `internal/keystore` | 99.41% |
| `internal/jwt` | 99.20% |
| `internal/email` | 99.01% |
| `cmd/admin-gateway` | 98.77% |
| `cmd/bridge` | 98.73% |
| `internal/service` | 98.60% |
| `cmd/vault` | 98.33% |
| `internal/crypto` | 98.13% |
| `cmd/recover` | 98.00% |

## Uncovered Functions

| Function | File |
|----------|------|
| `envInt` | cmd/admin-gateway/config.go:213 |
| `envDuration` | cmd/admin-gateway/config.go:225 |
| `loadSecret` | cmd/admin-gateway/config.go:237 |
| `main` | cmd/recover/main.go:116 |
| `checkSessionLimit` | internal/service/auth.go:1360 |
| `storeRefreshToken` | internal/service/auth.go:1381 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `inboundPath` | cmd/bridge/proxy.go:129 | 66.7% |
