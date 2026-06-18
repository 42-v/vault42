# Test Coverage Report

Generated: 2026-06-19 | Tests: 2292 | Total: 78.02% statement coverage

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
| `internal/config` | 98.37% |
| `internal/jwt` | 96.81% |
| `internal/audit` | 96.55% |
| `internal/middleware` | 93.76% |
| `internal/oauth2` | 93.37% |
| `internal/crypto` | 91.44% |
| `internal/email` | 90.91% |
| `internal/service` | 90.31% |
| `internal/handler` | 90.15% |
| `internal/seed` | 89.23% |
| `internal/honeypot` | 89.11% |
| `internal/adminapi` | 86.64% |
| `internal/redis` | 84.91% |
| `internal/cache` | 82.47% |
| `internal/server` | 76.02% |
| `internal/cli` | 63.56% |
| `internal/keystore` | 12.77% |
| `internal/migrate` | 2.50% |
| `internal/repository/postgres` | 0.00% |

## Uncovered Functions

| Function | File |
|----------|------|
| `runSeed` | internal/cli/cli.go:350 |
| `cleanupAudit` | internal/cli/cli.go:372 |
| `exportAudit` | internal/cli/cli.go:397 |
| `Import` | internal/keystore/keystore.go:105 |
| `Rotate` | internal/keystore/keystore.go:170 |
| `Revoke` | internal/keystore/keystore.go:180 |
| `Refresh` | internal/keystore/keystore.go:196 |
| `ListKeys` | internal/keystore/keystore.go:271 |
| `StartRefreshLoop` | internal/keystore/keystore.go:305 |
| `EnsureKey` | internal/keystore/keystore.go:336 |
| `CleanupExpired` | internal/keystore/keystore.go:369 |
| `NewAdminConfigRepo` | internal/repository/postgres/admin_config.go:17 |
| `List` | internal/repository/postgres/admin_config.go:22 |
| `Get` | internal/repository/postgres/admin_config.go:41 |
| `Set` | internal/repository/postgres/admin_config.go:54 |
| `Delete` | internal/repository/postgres/admin_config.go:65 |
| `NewAdminSessionRepo` | internal/repository/postgres/admin_session.go:19 |
| `Create` | internal/repository/postgres/admin_session.go:24 |
| `GetByTokenHash` | internal/repository/postgres/admin_session.go:39 |
| `ListByAdmin` | internal/repository/postgres/admin_session.go:61 |
| `ListActive` | internal/repository/postgres/admin_session.go:75 |
| `Revoke` | internal/repository/postgres/admin_session.go:89 |
| `RevokeAllForAdmin` | internal/repository/postgres/admin_session.go:99 |
| `RevokeAll` | internal/repository/postgres/admin_session.go:109 |
| `DeleteExpired` | internal/repository/postgres/admin_session.go:119 |
| `scanSessions` | internal/repository/postgres/admin_session.go:128 |
| `NewAdminUserRepo` | internal/repository/postgres/admin_user.go:20 |
| `Create` | internal/repository/postgres/admin_user.go:25 |
| `GetByID` | internal/repository/postgres/admin_user.go:42 |
| `GetByUsername` | internal/repository/postgres/admin_user.go:54 |
| `List` | internal/repository/postgres/admin_user.go:66 |
| `Count` | internal/repository/postgres/admin_user.go:92 |
| `Update` | internal/repository/postgres/admin_user.go:102 |
| `IncrementFailedLogin` | internal/repository/postgres/admin_user.go:117 |
| `ResetFailedLogin` | internal/repository/postgres/admin_user.go:128 |
| `LockUntil` | internal/repository/postgres/admin_user.go:138 |
| `UpdateLastTOTPCounter` | internal/repository/postgres/admin_user.go:148 |
| `UpdateLastLogin` | internal/repository/postgres/admin_user.go:158 |
| `Revoke` | internal/repository/postgres/admin_user.go:168 |
| `scanAdminUser` | internal/repository/postgres/admin_user.go:176 |
| `scanAdminUserRow` | internal/repository/postgres/admin_user.go:193 |
| `NewAppRoleRepo` | internal/repository/postgres/app_role.go:20 |
| `List` | internal/repository/postgres/app_role.go:25 |
| `ListNames` | internal/repository/postgres/app_role.go:45 |
| `Get` | internal/repository/postgres/app_role.go:63 |
| `Create` | internal/repository/postgres/app_role.go:79 |
| `Delete` | internal/repository/postgres/app_role.go:96 |
| `NewAuditRepo` | internal/repository/postgres/audit.go:19 |
| `Insert` | internal/repository/postgres/audit.go:24 |
| `InsertBatch` | internal/repository/postgres/audit.go:41 |
| `Query` | internal/repository/postgres/audit.go:71 |
| `Cleanup` | internal/repository/postgres/audit.go:141 |
| `NewBackupCodeRepo` | internal/repository/postgres/backup_code.go:15 |
| `CreateBatch` | internal/repository/postgres/backup_code.go:19 |
| `ListUnusedByUser` | internal/repository/postgres/backup_code.go:41 |
| `MarkUsed` | internal/repository/postgres/backup_code.go:65 |
| `DeleteAllForUser` | internal/repository/postgres/backup_code.go:75 |
| `NewBlobRepo` | internal/repository/postgres/blob.go:19 |
| `Create` | internal/repository/postgres/blob.go:24 |
| `GetByIDAndPseudonym` | internal/repository/postgres/blob.go:42 |
| `GetByRefAndPseudonym` | internal/repository/postgres/blob.go:62 |
| `DeleteByRefAndPseudonym` | internal/repository/postgres/blob.go:82 |
| `ListByPseudonym` | internal/repository/postgres/blob.go:94 |
| `GetQuota` | internal/repository/postgres/blob.go:119 |
| `Delete` | internal/repository/postgres/blob.go:132 |
| `NewClientRepo` | internal/repository/postgres/client.go:19 |
| `Create` | internal/repository/postgres/client.go:24 |
| `GetByID` | internal/repository/postgres/client.go:39 |
| `GetByName` | internal/repository/postgres/client.go:57 |
| `List` | internal/repository/postgres/client.go:75 |
| `Update` | internal/repository/postgres/client.go:100 |
| `Deactivate` | internal/repository/postgres/client.go:114 |
| `New` | internal/repository/postgres/db.go:18 |
| `Close` | internal/repository/postgres/db.go:43 |
| `NewDeviceRepo` | internal/repository/postgres/device.go:20 |
| `Create` | internal/repository/postgres/device.go:25 |
| `GetByID` | internal/repository/postgres/device.go:40 |
| `GetByFingerprint` | internal/repository/postgres/device.go:55 |
| `ListByUser` | internal/repository/postgres/device.go:70 |
| `UpdateLastSeen` | internal/repository/postgres/device.go:94 |
| `UpdateFriendlyName` | internal/repository/postgres/device.go:103 |
| `Trust` | internal/repository/postgres/device.go:112 |
| `Delete` | internal/repository/postgres/device.go:121 |
| `DeleteAllForUser` | internal/repository/postgres/device.go:130 |
| `NewIdentityRepo` | internal/repository/postgres/identity.go:19 |
| `Upsert` | internal/repository/postgres/identity.go:24 |
| `GetByPseudonym` | internal/repository/postgres/identity.go:41 |
| `Delete` | internal/repository/postgres/identity.go:57 |
| `NewPasswordHistoryRepo` | internal/repository/postgres/password_history.go:15 |
| `Create` | internal/repository/postgres/password_history.go:20 |
| `GetRecentByUser` | internal/repository/postgres/password_history.go:31 |
| `NewRateLimitRepo` | internal/repository/postgres/rate_limit.go:18 |
| `Increment` | internal/repository/postgres/rate_limit.go:21 |
| `Get` | internal/repository/postgres/rate_limit.go:36 |
| `DeleteExpired` | internal/repository/postgres/rate_limit.go:51 |
| `NewRefreshTokenRepo` | internal/repository/postgres/refresh_token.go:19 |
| `Create` | internal/repository/postgres/refresh_token.go:24 |
| `GetByTokenHash` | internal/repository/postgres/refresh_token.go:39 |
| `MarkUsed` | internal/repository/postgres/refresh_token.go:63 |
| `RevokeByID` | internal/repository/postgres/refresh_token.go:72 |
| `RevokeByDeviceID` | internal/repository/postgres/refresh_token.go:81 |
| `RevokeFamily` | internal/repository/postgres/refresh_token.go:90 |
| `RevokeAllForUser` | internal/repository/postgres/refresh_token.go:99 |
| `RevokeAll` | internal/repository/postgres/refresh_token.go:108 |
| `CountActiveFamilies` | internal/repository/postgres/refresh_token.go:117 |
| `DeleteExpired` | internal/repository/postgres/refresh_token.go:129 |
| `deref` | internal/repository/postgres/scan.go:6 |
| `newDeviceScan` | internal/repository/postgres/scan.go:23 |
| `ptrs` | internal/repository/postgres/scan.go:25 |
| `device` | internal/repository/postgres/scan.go:32 |
| `NewSocialAccountRepo` | internal/repository/postgres/social_account.go:18 |
| `Create` | internal/repository/postgres/social_account.go:23 |
| `GetByProviderAndID` | internal/repository/postgres/social_account.go:35 |
| `ListByUser` | internal/repository/postgres/social_account.go:51 |
| `Delete` | internal/repository/postgres/social_account.go:74 |
| `NewTOTPRepo` | internal/repository/postgres/totp.go:18 |
| `Create` | internal/repository/postgres/totp.go:21 |
| `GetByUserID` | internal/repository/postgres/totp.go:32 |
| `MarkVerified` | internal/repository/postgres/totp.go:47 |
| `DeleteByUserID` | internal/repository/postgres/totp.go:56 |
| `NewUserRepo` | internal/repository/postgres/user.go:20 |
| `Create` | internal/repository/postgres/user.go:25 |
| `CreateImported` | internal/repository/postgres/user.go:46 |
| `ClearImportPending` | internal/repository/postgres/user.go:72 |
| `GetByID` | internal/repository/postgres/user.go:81 |
| `GetByEmail` | internal/repository/postgres/user.go:91 |
| `Update` | internal/repository/postgres/user.go:101 |
| `UpdatePassword` | internal/repository/postgres/user.go:116 |
| `IncrementFailedLogin` | internal/repository/postgres/user.go:125 |
| `ResetFailedLogin` | internal/repository/postgres/user.go:134 |
| `LockUntil` | internal/repository/postgres/user.go:143 |
| `Unlock` | internal/repository/postgres/user.go:152 |
| `SetLastLogin` | internal/repository/postgres/user.go:161 |
| `VerifyEmail` | internal/repository/postgres/user.go:170 |
| `scanUser` | internal/repository/postgres/user.go:178 |
| `nullStr` | internal/repository/postgres/user.go:204 |
| `NewWebAuthnRepo` | internal/repository/postgres/webauthn.go:18 |
| `Create` | internal/repository/postgres/webauthn.go:21 |
| `GetByCredentialID` | internal/repository/postgres/webauthn.go:33 |
| `ListByUser` | internal/repository/postgres/webauthn.go:49 |
| `UpdateSignCount` | internal/repository/postgres/webauthn.go:72 |
| `Delete` | internal/repository/postgres/webauthn.go:81 |
| `Start` | internal/server/server.go:106 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `ListKeys` | internal/adminapi/handler.go:77 | 30.0% |
| `RotateKey` | internal/adminapi/handler.go:94 | 30.0% |
| `RevokeKey` | internal/adminapi/handler.go:114 | 53.8% |
| `ListSessions` | internal/adminapi/handler.go:315 | 72.7% |
| `ListClients` | internal/adminapi/handler.go:415 | 66.7% |
| `GetClient` | internal/adminapi/handler.go:449 | 66.7% |
| `RevokeClient` | internal/adminapi/handler.go:535 | 60.0% |
| `GetConfig` | internal/adminapi/handler.go:598 | 60.0% |
| `DeleteConfig` | internal/adminapi/handler.go:643 | 60.0% |
| `ListAdmins` | internal/adminapi/handler.go:678 | 66.7% |
| `CreateRole` | internal/adminapi/roles.go:46 | 69.2% |
| `DeleteRole` | internal/adminapi/roles.go:90 | 56.2% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `Get` | internal/cache/postgres.go:24 | 42.9% |
| `GetAndDelete` | internal/cache/postgres.go:59 | 42.9% |
| `Exists` | internal/cache/postgres.go:128 | 33.3% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 70.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `VerifyFinish` | internal/handler/webauthn.go:197 | 65.1% |
| `addLimiter` | internal/middleware/ratelimit.go:143 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `Run` | internal/migrate/migrate.go:17 | 2.5% |
| `httpClient` | internal/oauth2/facebook.go:26 | 66.7% |
| `httpClient` | internal/oauth2/github.go:26 | 66.7% |
| `httpClient` | internal/oauth2/google.go:26 | 66.7% |
| `httpClient` | internal/oauth2/oidc.go:59 | 66.7% |
| `Expire` | internal/redis/client.go:187 | 71.4% |
| `exec` | internal/redis/client.go:240 | 72.0% |
| `put` | internal/redis/pool.go:130 | 72.2% |
| `initSelect` | internal/redis/pool.go:248 | 72.7% |
| `writeCommand` | internal/redis/resp.go:22 | 61.1% |
| `sendImportClaimLink` | internal/service/auth.go:338 | 70.6% |
