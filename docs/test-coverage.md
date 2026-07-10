# Test Coverage Report

Generated: 2026-07-10 | Tests: 2625 | Total: 86.69% statement coverage

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
| `internal/oauth2` | 97.69% |
| `internal/jwt` | 96.81% |
| `internal/audit` | 96.55% |
| `internal/config` | 95.47% |
| `internal/middleware` | 93.03% |
| `internal/cache` | 92.21% |
| `internal/adminapi` | 90.74% |
| `internal/crypto` | 89.58% |
| `internal/redis` | 89.35% |
| `internal/handler` | 89.35% |
| `internal/seed` | 89.23% |
| `internal/honeypot` | 89.11% |
| `internal/service` | 86.39% |
| `internal/keystore` | 84.83% |
| `internal/kms` | 83.33% |
| `internal/migrate` | 77.50% |
| `internal/server` | 74.33% |
| `internal/repository/postgres` | 71.83% |
| `internal/email` | 67.81% |
| `internal/cli` | 63.56% |

## Uncovered Functions

| Function | File |
|----------|------|
| `runSeed` | internal/cli/cli.go:350 |
| `cleanupAudit` | internal/cli/cli.go:372 |
| `exportAudit` | internal/cli/cli.go:397 |
| `WithStore` | internal/email/mailer.go:73 |
| `fromDomainAllowed` | internal/email/mailer.go:181 |
| `getBranding` | internal/email/mailer.go:241 |
| `putBranding` | internal/email/mailer.go:251 |
| `getTemplate` | internal/email/mailer.go:260 |
| `putTemplate` | internal/email/mailer.go:270 |
| `Close` | internal/kms/kms.go:112 |
| `AppContext` | internal/middleware/appcontext.go:16 |
| `NewAccountRecoveryRepo` | internal/repository/postgres/account_recovery.go:18 |
| `Append` | internal/repository/postgres/account_recovery.go:24 |
| `List` | internal/repository/postgres/account_recovery.go:38 |
| `List` | internal/repository/postgres/admin_config.go:22 |
| `RevokeAll` | internal/repository/postgres/admin_session.go:109 |
| `ListNames` | internal/repository/postgres/app_role.go:45 |
| `Cleanup` | internal/repository/postgres/audit.go:141 |
| `GetByRefAndPseudonym` | internal/repository/postgres/blob.go:62 |
| `DeleteByRefAndPseudonym` | internal/repository/postgres/blob.go:82 |
| `DeleteAllForPseudonym` | internal/repository/postgres/blob.go:146 |
| `DeleteAllForUser` | internal/repository/postgres/device.go:130 |
| `DeleteAllForUser` | internal/repository/postgres/password_history.go:54 |
| `RevokeByDeviceID` | internal/repository/postgres/refresh_token.go:81 |
| `RevokeAll` | internal/repository/postgres/refresh_token.go:108 |
| `CountActiveFamilies` | internal/repository/postgres/refresh_token.go:117 |
| `DeleteAllForUser` | internal/repository/postgres/social_account.go:83 |
| `SoftDeleteScrub` | internal/repository/postgres/user.go:120 |
| `SetLastLogin` | internal/repository/postgres/user.go:178 |
| `Start` | internal/server/server.go:128 |
| `SetMailer` | internal/service/auth.go:154 |
| `NewEmailOverrideStore` | internal/service/email_overrides.go:22 |
| `Branding` | internal/service/email_overrides.go:27 |
| `Template` | internal/service/email_overrides.go:50 |
| `AALForMethods` | internal/service/mfa.go:57 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `actor` | internal/adminapi/email.go:18 | 66.7% |
| `ListKeys` | internal/adminapi/handler.go:100 | 30.0% |
| `RotateKey` | internal/adminapi/handler.go:117 | 30.0% |
| `RevokeKey` | internal/adminapi/handler.go:137 | 53.8% |
| `GetClient` | internal/adminapi/handler.go:559 | 66.7% |
| `RevokeClient` | internal/adminapi/handler.go:645 | 60.0% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `presence` | internal/config/config.go:686 | 66.7% |
| `splitTrimLower` | internal/config/config.go:708 | 28.6% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 70.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `EncryptRecovery` | internal/crypto/recovery.go:36 | 72.2% |
| `LoadRSAPublicKeyPEM` | internal/crypto/recovery.go:100 | 50.0% |
| `LoadRSAPrivateKeyPEM` | internal/crypto/recovery.go:124 | 50.0% |
| `NewMailer` | internal/email/mailer.go:46 | 71.4% |
| `resolveBranding` | internal/email/mailer.go:104 | 11.1% |
| `renderOverride` | internal/email/mailer.go:135 | 8.7% |
| `Delete` | internal/handler/account.go:31 | 67.9% |
| `Export` | internal/handler/data_export.go:62 | 74.5% |
| `SetMailer` | internal/handler/password.go:91 | 50.0% |
| `VerifyFinish` | internal/handler/webauthn.go:199 | 65.1% |
| `Import` | internal/keystore/keystore.go:107 | 71.4% |
| `Wrap` | internal/kms/kms.go:78 | 71.4% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `Expire` | internal/redis/client.go:187 | 71.4% |
| `writeCommand` | internal/redis/resp.go:22 | 61.1% |
| `Create` | internal/repository/postgres/app_role.go:79 | 71.4% |
| `Create` | internal/repository/postgres/blob.go:24 | 71.4% |
| `Delete` | internal/repository/postgres/email_branding.go:99 | 66.7% |
| `Delete` | internal/repository/postgres/email_template.go:105 | 66.7% |
| `CreateImported` | internal/repository/postgres/user.go:46 | 71.4% |
| `sendImportClaimLink` | internal/service/auth.go:363 | 66.7% |
| `DeleteAccount` | internal/service/erasure.go:76 | 69.2% |
