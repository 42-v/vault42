# Test Coverage Report

Generated: 2026-07-14 | Tests: 2858 | Total: 94.67% statement coverage

Measured across the full suite (unit + attack + fuzz + integration +
compliance) against `./internal/...`. Regenerate with `scripts/coverage.sh`.

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.00% |
| `internal/sanitize` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/model` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/config` | 98.11% |
| `internal/middleware` | 97.74% |
| `internal/oauth2` | 97.69% |
| `internal/server` | 97.38% |
| `internal/adminapi` | 97.01% |
| `internal/jwt` | 96.81% |
| `internal/audit` | 96.67% |
| `internal/crypto` | 95.60% |
| `internal/redis` | 95.56% |
| `internal/cache` | 95.45% |
| `internal/repository/postgres` | 94.79% |
| `internal/seed` | 94.62% |
| `internal/service` | 93.11% |
| `internal/handler` | 92.74% |
| `internal/email` | 91.48% |
| `internal/honeypot` | 89.11% |
| `internal/keystore` | 88.97% |
| `internal/cli` | 88.14% |
| `internal/kms` | 87.50% |
| `internal/migrate` | 77.50% |

## Uncovered Functions

| Function | File |
|----------|------|

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `VerifyFinish` | internal/handler/webauthn.go:199 | 65.1% |
| `Wrap` | internal/kms/kms.go:78 | 71.4% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `UpsertCAS` | internal/repository/postgres/identity.go:34 | 55.6% |
| `sendImportClaimLink` | internal/service/auth.go:363 | 66.7% |
