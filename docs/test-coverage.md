# Test Coverage Report

Generated: 2026-08-13 | Tests: 3675 | Total: 99.47% statement coverage

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
| `internal/httputil` | 100.00% |
| `internal/honeypot` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/config` | 100.00% |
| `internal/cli` | 100.00% |
| `internal/cache` | 100.00% |
| `internal/audit` | 100.00% |
| `internal/repository/postgres` | 99.90% |
| `internal/adminapi` | 99.72% |
| `internal/oauth2` | 99.71% |
| `internal/handler` | 99.65% |
| `internal/keystore` | 99.35% |
| `internal/jwt` | 99.20% |
| `internal/service` | 99.01% |
| `internal/email` | 99.01% |
| `cmd/bridge` | 98.83% |
| `cmd/admin-gateway` | 98.77% |
| `cmd/recover` | 98.73% |
| `cmd/vault` | 98.33% |
| `internal/crypto` | 98.19% |
| `internal/kms` | 91.67% |

## Uncovered Functions

| Function | File |
|----------|------|
| `main` | cmd/recover/main.go:76 |
| `decryptTOTPSecret` | internal/adminapi/auth.go:472 |
| `encodeRSAExponent` | internal/crypto/jwt.go:221 |
| `SerializeJWKSJSON` | internal/crypto/jwt.go:235 |
| `Unwrap` | internal/kms/kms.go:125 |
| `Close` | internal/kms/kms.go:145 |
| `wipe` | internal/kms/kms.go:156 |
| `parseCORSOrigins` | internal/server/server.go:595 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
