# Test Coverage Report

Generated: 2026-07-14 | Tests: 2777 | Total: 92.42% statement coverage

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
| `internal/jwt` | 96.81% |
| `internal/audit` | 96.67% |
| `internal/seed` | 93.85% |
| `internal/crypto` | 93.52% |
| `internal/adminapi` | 93.36% |
| `internal/redis` | 93.20% |
| `internal/service` | 92.42% |
| `internal/cache` | 92.21% |
| `internal/server` | 92.15% |
| `internal/email` | 91.15% |
| `internal/handler` | 90.05% |
| `internal/honeypot` | 89.11% |
| `internal/keystore` | 88.97% |
| `internal/cli` | 88.14% |
| `internal/repository/postgres` | 87.60% |
| `internal/kms` | 87.50% |
| `internal/migrate` | 77.50% |

## Uncovered Functions

| Function | File |
|----------|------|
| `SetIdentityService` | internal/adminapi/handler.go:71 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `actor` | internal/adminapi/email.go:18 | 66.7% |
| `RotateKey` | internal/adminapi/handler.go:126 | 70.0% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 70.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `Delete` | internal/handler/account.go:31 | 67.9% |
| `VerifyFinish` | internal/handler/webauthn.go:199 | 65.1% |
| `Wrap` | internal/kms/kms.go:78 | 71.4% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `Create` | internal/repository/postgres/app_role.go:79 | 71.4% |
| `UpsertCAS` | internal/repository/postgres/identity.go:34 | 44.4% |
| `sendImportClaimLink` | internal/service/auth.go:363 | 66.7% |
