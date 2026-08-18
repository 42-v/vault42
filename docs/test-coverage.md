# Test Coverage Report

Generated: 2026-08-18 | Tests: 4635 | Total: 99.40% statement coverage

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
| `internal/audit` | 100.00% |
| `internal/adminapi` | 99.82% |
| `internal/repository/postgres` | 99.81% |
| `internal/oauth2` | 99.73% |
| `internal/handler` | 99.63% |
| `internal/cache` | 99.47% |
| `cmd/bridge` | 99.24% |
| `internal/jwt` | 99.22% |
| `internal/email` | 99.08% |
| `internal/keystore` | 98.86% |
| `internal/service` | 98.83% |
| `internal/crypto` | 98.18% |
| `cmd/recover` | 98.15% |
| `cmd/vault` | 97.70% |
| `cmd/admin-gateway` | 97.18% |

## Uncovered Functions

| Function | File |
|----------|------|
| `main` | cmd/recover/main.go:134 |
| `Error` | internal/cache/cache.go:51 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `firstCertificate` | cmd/admin-gateway/clientauth.go:183 | 70.0% |
| `hardenProcess` | cmd/recover/harden_linux.go:23 | 66.7% |
