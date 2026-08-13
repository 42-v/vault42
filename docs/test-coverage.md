# Test Coverage Report

Generated: 2026-08-13 | Tests: 3891 | Total: 99.13% statement coverage

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
| `internal/metrics` | 100.00% |
| `internal/kms` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/honeypot` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/cache` | 100.00% |
| `internal/oauth2` | 99.71% |
| `internal/adminapi` | 99.54% |
| `internal/keystore` | 99.44% |
| `cmd/admin-gateway` | 99.41% |
| `internal/config` | 99.37% |
| `internal/repository/postgres` | 99.30% |
| `internal/middleware` | 99.28% |
| `internal/jwt` | 99.20% |
| `cmd/bridge` | 99.10% |
| `internal/handler` | 99.04% |
| `internal/email` | 99.01% |
| `cmd/recover` | 99.00% |
| `internal/service` | 98.61% |
| `internal/cli` | 98.57% |
| `cmd/vault` | 98.41% |
| `internal/crypto` | 98.14% |
| `internal/audit` | 95.83% |

## Uncovered Functions

| Function | File |
|----------|------|
| `main` | cmd/recover/main.go:116 |
| `recordFailedIP` | internal/service/auth.go:1320 |
| `storeRefreshToken` | internal/service/auth.go:1443 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `requeue` | internal/audit/audit.go:335 | 60.0% |
| `provisionedTokenMatches` | internal/cli/cli.go:449 | 50.0% |
