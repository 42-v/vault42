# Test Coverage Report

Generated: 2026-05-14 | Tests: 1940 | Total: 67.69% statement coverage

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/model` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/sanitize` | 97.22% |
| `internal/jwt` | 96.81% |
| `internal/oauth2` | 94.29% |
| `internal/httputil` | 93.33% |
| `internal/crypto` | 91.40% |
| `internal/email` | 88.64% |
| `internal/middleware` | 87.38% |
| `internal/honeypot` | 87.13% |
| `internal/seed` | 85.38% |
| `internal/config` | 83.02% |
| `internal/audit` | 82.76% |
| `internal/redis` | 79.59% |
| `internal/handler` | 75.04% |
| `internal/service` | 72.46% |
| `internal/cli` | 63.56% |
| `internal/adminapi` | 62.98% |
| `internal/server` | 60.00% |
| `internal/cache` | 51.95% |
| `internal/keystore` | 12.77% |
| `internal/migrate` | 2.50% |
| `internal/repository/postgres` | 0.00% |

## Uncovered Functions

| Function | File |
|----------|------|
| `Get` | internal/cache/postgres.go:24 |
| `Set` | internal/cache/postgres.go:39 |
| `Delete` | internal/cache/postgres.go:53 |
| `GetAndDelete` | internal/cache/postgres.go:59 |
| `SetIfNotExists` | internal/cache/postgres.go:76 |
| `Increment` | internal/cache/postgres.go:100 |
| `Exists` | internal/cache/postgres.go:128 |
| `Get` | internal/cache/redis.go:38 |
| `Set` | internal/cache/redis.go:47 |
| `Delete` | internal/cache/redis.go:52 |
| `GetAndDelete` | internal/cache/redis.go:58 |
| `SetIfNotExists` | internal/cache/redis.go:67 |
| `Increment` | internal/cache/redis.go:79 |
| `Exists` | internal/cache/redis.go:92 |
| `Close` | internal/cache/redis.go:97 |
| `runSeed` | internal/cli/cli.go:350 |
| `cleanupAudit` | internal/cli/cli.go:372 |
| `exportAudit` | internal/cli/cli.go:397 |
| `DownloadNamed` | internal/handler/blob.go:182 |
| `DeleteNamed` | internal/handler/blob.go:223 |
| `Import` | internal/keystore/keystore.go:105 |
| `Rotate` | internal/keystore/keystore.go:170 |
| `Revoke` | internal/keystore/keystore.go:180 |
| `Refresh` | internal/keystore/keystore.go:196 |
| `ListKeys` | internal/keystore/keystore.go:271 |
| `StartRefreshLoop` | internal/keystore/keystore.go:305 |
| `EnsureKey` | internal/keystore/keystore.go:336 |
| `CleanupExpired` | internal/keystore/keystore.go:369 |
| `increment` | internal/middleware/ratelimit.go:111 |
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
| `GetByID` | internal/repository/postgres/user.go:44 |
| `GetByEmail` | internal/repository/postgres/user.go:52 |
| `Update` | internal/repository/postgres/user.go:60 |
| `UpdatePassword` | internal/repository/postgres/user.go:75 |
| `IncrementFailedLogin` | internal/repository/postgres/user.go:84 |
| `ResetFailedLogin` | internal/repository/postgres/user.go:93 |
| `LockUntil` | internal/repository/postgres/user.go:102 |
| `Unlock` | internal/repository/postgres/user.go:111 |
| `VerifyEmail` | internal/repository/postgres/user.go:120 |
| `scanUser` | internal/repository/postgres/user.go:128 |
| `nullStr` | internal/repository/postgres/user.go:152 |
| `NewWebAuthnRepo` | internal/repository/postgres/webauthn.go:18 |
| `Create` | internal/repository/postgres/webauthn.go:21 |
| `GetByCredentialID` | internal/repository/postgres/webauthn.go:33 |
| `ListByUser` | internal/repository/postgres/webauthn.go:49 |
| `UpdateSignCount` | internal/repository/postgres/webauthn.go:72 |
| `Delete` | internal/repository/postgres/webauthn.go:81 |
| `Start` | internal/server/server.go:106 |
| `RevokeAllTokensForUser` | internal/service/auth.go:643 |
| `CompleteMFALogin` | internal/service/auth.go:650 |
| `sendEmailOTP` | internal/service/auth.go:715 |
| `refHash` | internal/service/blob.go:55 |
| `UploadNamed` | internal/service/blob.go:66 |
| `DownloadNamed` | internal/service/blob.go:176 |
| `DeleteNamed` | internal/service/blob.go:280 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `Login` | internal/adminapi/auth.go:83 | 68.2% |
| `TOTPSetup` | internal/adminapi/auth.go:265 | 54.5% |
| `TOTPVerify` | internal/adminapi/auth.go:308 | 21.9% |
| `render` | internal/adminapi/frontend.go:58 | 61.5% |
| `ListKeys` | internal/adminapi/handler.go:70 | 30.0% |
| `RotateKey` | internal/adminapi/handler.go:87 | 30.0% |
| `RevokeKey` | internal/adminapi/handler.go:107 | 23.1% |
| `ListUsers` | internal/adminapi/handler.go:152 | 73.9% |
| `GetUser` | internal/adminapi/handler.go:213 | 58.3% |
| `LockUser` | internal/adminapi/handler.go:242 | 70.6% |
| `UnlockUser` | internal/adminapi/handler.go:276 | 60.0% |
| `ListSessions` | internal/adminapi/handler.go:299 | 72.7% |
| `RevokeAllSessions` | internal/adminapi/handler.go:334 | 66.7% |
| `QueryAudit` | internal/adminapi/handler.go:351 | 52.4% |
| `ListClients` | internal/adminapi/handler.go:399 | 66.7% |
| `GetClient` | internal/adminapi/handler.go:433 | 58.3% |
| `CreateClient` | internal/adminapi/handler.go:454 | 14.3% |
| `RevokeClient` | internal/adminapi/handler.go:519 | 60.0% |
| `RotateClientSecret` | internal/adminapi/handler.go:538 | 24.0% |
| `GetConfig` | internal/adminapi/handler.go:582 | 60.0% |
| `UpdateConfig` | internal/adminapi/handler.go:592 | 23.5% |
| `DeleteConfig` | internal/adminapi/handler.go:627 | 60.0% |
| `ListAdmins` | internal/adminapi/handler.go:662 | 66.7% |
| `CreateAdmin` | internal/adminapi/handler.go:698 | 11.1% |
| `LocalOnly` | internal/adminapi/middleware.go:51 | 68.4% |
| `SessionAuth` | internal/adminapi/middleware.go:117 | 48.7% |
| `Log` | internal/audit/audit.go:164 | 52.6% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:267 | 69.2% |
| `Load` | internal/config/config.go:256 | 56.2% |
| `loadSecrets` | internal/config/config.go:441 | 73.1% |
| `isValidHexColor` | internal/config/config.go:552 | 66.7% |
| `setDefaultBool` | internal/config/profiles.go:123 | 44.4% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 70.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `safeFuncMap` | internal/email/templates.go:78 | 57.1% |
| `ConfirmPassword` | internal/handler/auth.go:207 | 10.8% |
| `UploadNamed` | internal/handler/blob.go:122 | 13.8% |
| `writeUploadError` | internal/handler/blob.go:351 | 60.0% |
| `Capabilities` | internal/handler/capabilities.go:14 | 60.0% |
| `Verify` | internal/handler/email_otp.go:24 | 57.1% |
| `Resend` | internal/handler/email_otp.go:53 | 33.3% |
| `completeMFAIfChallenge` | internal/handler/mfa_helper.go:16 | 11.1% |
| `Authorize` | internal/handler/oauth.go:68 | 73.1% |
| `NewPasswordHandler` | internal/handler/password.go:55 | 50.0% |
| `Disable` | internal/handler/totp.go:159 | 33.3% |
| `UpdateProfile` | internal/handler/user.go:65 | 14.3% |
| `VerifyFinish` | internal/handler/webauthn.go:197 | 65.1% |
| `ListCredentials` | internal/handler/webauthn.go:272 | 33.3% |
| `DeleteCredential` | internal/handler/webauthn.go:299 | 16.7% |
| `Alert` | internal/honeypot/honeypot.go:75 | 72.7% |
| `DPoP` | internal/middleware/dpop.go:18 | 56.5% |
| `MaxBodyWithExemptions` | internal/middleware/maxbody.go:18 | 72.7% |
| `addLimiter` | internal/middleware/ratelimit.go:136 | 47.1% |
| `RequestID` | internal/middleware/requestid.go:19 | 66.7% |
| `Run` | internal/migrate/migrate.go:17 | 2.5% |
| `httpClient` | internal/oauth2/facebook.go:26 | 66.7% |
| `httpClient` | internal/oauth2/github.go:26 | 66.7% |
| `httpClient` | internal/oauth2/google.go:26 | 66.7% |
| `Incr` | internal/redis/client.go:172 | 71.4% |
| `Expire` | internal/redis/client.go:187 | 71.4% |
| `Exists` | internal/redis/client.go:201 | 71.4% |
| `exec` | internal/redis/client.go:240 | 60.0% |
| `put` | internal/redis/pool.go:130 | 50.0% |
| `initSelect` | internal/redis/pool.go:248 | 72.7% |
| `writeCommand` | internal/redis/resp.go:22 | 55.6% |
| `setupRoutes` | internal/server/server.go:172 | 73.8% |
| `Login` | internal/service/auth.go:305 | 61.3% |
| `findOrCreateDevice` | internal/service/auth.go:767 | 57.9% |
| `isAccountLocked` | internal/service/auth.go:804 | 53.3% |
| `isIPLocked` | internal/service/auth.go:850 | 47.4% |
| `recordFailedIP` | internal/service/auth.go:879 | 58.3% |
| `checkSessionLimit` | internal/service/auth.go:902 | 22.2% |
