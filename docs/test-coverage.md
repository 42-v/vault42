# Test Coverage Report

Generated: 2026-08-18 | Tests: 4655 | Total: 99.58% statement coverage

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
| `internal/ipintel` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/honeypot` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/firstboot` | 100.00% |
| `internal/dpop` | 100.00% |
| `internal/deferwork` | 100.00% |
| `internal/config` | 100.00% |
| `internal/cli` | 100.00% |
| `internal/cache` | 100.00% |
| `internal/audit` | 100.00% |
| `internal/repository/postgres` | 99.91% |
| `internal/adminapi` | 99.82% |
| `internal/oauth2` | 99.73% |
| `internal/handler` | 99.68% |
| `internal/keystore` | 99.62% |
| `cmd/admin-gateway` | 99.60% |
| `cmd/bridge` | 99.55% |
| `internal/service` | 99.24% |
| `internal/jwt` | 99.22% |
| `internal/email` | 99.08% |
| `cmd/vault` | 98.36% |
| `internal/crypto` | 98.18% |
| `cmd/recover` | 98.15% |

## Uncovered Functions

| Function | File |
|----------|------|
| `main` | cmd/recover/main.go:134 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `hardenProcess` | cmd/recover/harden_linux.go:23 | 66.7% |
