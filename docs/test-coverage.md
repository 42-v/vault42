# Test Coverage Report

Generated: 2026-07-16 | Tests: 2966 | Total: 96.67% statement coverage

Measured across the full suite (unit + attack + fuzz + integration +
compliance) against `./internal/...`. Regenerate with `scripts/coverage.sh`.

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.00% |
| `internal/server` | 100.00% |
| `internal/sanitize` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/model` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/config` | 98.87% |
| `internal/jwt` | 98.80% |
| `internal/oauth2` | 98.56% |
| `internal/redis` | 98.22% |
| `internal/middleware` | 97.74% |
| `internal/email` | 97.70% |
| `internal/seed` | 97.69% |
| `internal/crypto` | 97.52% |
| `internal/migrate` | 97.50% |
| `internal/adminapi` | 97.29% |
| `internal/keystore` | 97.24% |
| `internal/audit` | 96.67% |
| `internal/repository/postgres` | 96.52% |
| `internal/cache` | 96.10% |
| `internal/service` | 95.75% |
| `internal/cli` | 95.34% |
| `internal/handler` | 94.24% |
| `internal/honeypot` | 92.08% |
| `internal/kms` | 91.67% |

## Uncovered Functions

| Function | File |
|----------|------|

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateDummyHashLoop` | internal/crypto/argon2.go:142 | 50.0% |
| `VerifyFinish` | internal/handler/webauthn.go:199 | 65.1% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
