# Test Coverage Report

Generated: 2026-08-14 | Tests: 4202 | Total: 99.55% statement coverage

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
| `internal/repository/postgres` | 99.90% |
| `internal/adminapi` | 99.82% |
| `internal/oauth2` | 99.73% |
| `internal/handler` | 99.62% |
| `internal/keystore` | 99.53% |
| `cmd/bridge` | 99.49% |
| `cmd/admin-gateway` | 99.42% |
| `internal/jwt` | 99.22% |
| `internal/service` | 99.11% |
| `internal/email` | 99.01% |
| `cmd/vault` | 98.92% |
| `internal/crypto` | 98.17% |
| `cmd/recover` | 98.15% |

## Uncovered Functions

| Function | File |
|----------|------|
| `main` | cmd/recover/main.go:133 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `hardenProcess` | cmd/recover/harden_linux.go:23 | 66.7% |
