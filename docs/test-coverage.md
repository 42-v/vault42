# Test Coverage Report

Generated: 2026-07-14 | Tests: 2715 | Total: 90.12% statement coverage

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
| `internal/oauth2` | 97.69% |
| `internal/jwt` | 96.81% |
| `internal/audit` | 95.18% |
| `internal/middleware` | 94.35% |
| `internal/seed` | 93.85% |
| `internal/crypto` | 93.52% |
| `internal/cache` | 92.21% |
| `internal/adminapi` | 91.96% |
| `internal/service` | 90.87% |
| `internal/handler` | 89.53% |
| `internal/email` | 89.51% |
| `internal/redis` | 89.35% |
| `internal/honeypot` | 89.11% |
| `internal/kms` | 87.50% |
| `internal/cli` | 86.44% |
| `internal/keystore` | 84.83% |
| `internal/repository/postgres` | 79.72% |
| `internal/migrate` | 77.50% |
| `internal/server` | 74.87% |

## Uncovered Functions

| Function | File |
|----------|------|
| `SetIdentityService` | internal/adminapi/handler.go:71 |
| `CleanupLocked` | internal/repository/postgres/audit.go:152 |
| `UpsertCAS` | internal/repository/postgres/identity.go:34 |
| `Start` | internal/server/server.go:128 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `actor` | internal/adminapi/email.go:18 | 66.7% |
| `ListKeys` | internal/adminapi/handler.go:109 | 70.0% |
| `RotateKey` | internal/adminapi/handler.go:126 | 30.0% |
| `RevokeKey` | internal/adminapi/handler.go:146 | 53.8% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 70.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `fromDomainAllowed` | internal/email/mailer.go:181 | 66.7% |
| `base64MIMEBody` | internal/email/smtp.go:138 | 72.7% |
| `Delete` | internal/handler/account.go:31 | 67.9% |
| `Export` | internal/handler/data_export.go:62 | 74.5% |
| `VerifyFinish` | internal/handler/webauthn.go:199 | 65.1% |
| `Import` | internal/keystore/keystore.go:107 | 71.4% |
| `Wrap` | internal/kms/kms.go:78 | 71.4% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `Expire` | internal/redis/client.go:187 | 71.4% |
| `writeCommand` | internal/redis/resp.go:22 | 61.1% |
| `Create` | internal/repository/postgres/app_role.go:79 | 71.4% |
| `DeleteByRefAndPseudonym` | internal/repository/postgres/blob.go:82 | 66.7% |
| `Delete` | internal/repository/postgres/email_branding.go:99 | 66.7% |
| `Delete` | internal/repository/postgres/email_template.go:105 | 66.7% |
| `sendImportClaimLink` | internal/service/auth.go:363 | 66.7% |
