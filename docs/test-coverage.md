# Test Coverage Report

Generated: 2026-04-23 | Tests: 2011 | Total: 59.4% statement coverage

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.0% |
| `internal/rbac` | 100.0% |
| `internal/model` | 100.0% |
| `internal/metrics` | 100.0% |
| `internal/frontend` | 100.0% |
| `internal/oauth2` | 97.5% |
| `internal/sanitize` | 97.2% |
| `internal/jwt` | 94.8% |
| `internal/crypto` | 89.5% |
| `internal/honeypot` | 87.1% |
| `internal/email` | 86.4% |
| `internal/middleware` | 82.8% |
| `internal/redis` | 79.0% |
| `internal/config` | 78.9% |
| `internal/audit` | 75.9% |
| `internal/handler` | 71.3% |
| `internal/service` | 70.2% |
| `internal/seed` | 64.2% |
| `internal/cli` | 63.6% |
| `internal/server` | 55.3% |
| `internal/cache` | 51.9% |
| `internal/httputil` | 44.4% |
| `internal/adminapi` | 12.1% |
| `internal/keystore` | 9.3% |
| `internal/migrate` | 2.5% |
| `tests/testutil` | — |
| `tests/mocks` | — |
| `internal/repository/postgres` | 0.0% |

## Uncovered Functions

| Function | File |
|----------|------|
| `NewAuthHandler` | internal/adminapi/auth.go:33 |
| `Login` | internal/adminapi/auth.go:78 |
| `Logout` | internal/adminapi/auth.go:217 |
| `Status` | internal/adminapi/auth.go:240 |
| `TOTPSetup` | internal/adminapi/auth.go:260 |
| `TOTPVerify` | internal/adminapi/auth.go:303 |
| `EnsureFirstAdmin` | internal/adminapi/auth.go:363 |
| `handleFailedLogin` | internal/adminapi/auth.go:413 |
| `NewFrontendHandler` | internal/adminapi/frontend.go:35 |
| `render` | internal/adminapi/frontend.go:58 |
| `LoginPage` | internal/adminapi/frontend.go:85 |
| `Dashboard` | internal/adminapi/frontend.go:90 |
| `UsersPage` | internal/adminapi/frontend.go:95 |
| `KeysPage` | internal/adminapi/frontend.go:100 |
| `SessionsPage` | internal/adminapi/frontend.go:105 |
| `AuditPage` | internal/adminapi/frontend.go:110 |
| `ClientsPage` | internal/adminapi/frontend.go:115 |
| `AdminsPage` | internal/adminapi/frontend.go:120 |
| `ConfigPage` | internal/adminapi/frontend.go:125 |
| `UserDetailPage` | internal/adminapi/frontend.go:130 |
| `TOTPSetupPage` | internal/adminapi/frontend.go:135 |
| `ServeStatic` | internal/adminapi/frontend.go:140 |
| `NewHandler` | internal/adminapi/handler.go:36 |
| `ListKeys` | internal/adminapi/handler.go:65 |
| `RotateKey` | internal/adminapi/handler.go:82 |
| `RevokeKey` | internal/adminapi/handler.go:102 |
| `ListUsers` | internal/adminapi/handler.go:147 |
| `GetUser` | internal/adminapi/handler.go:208 |
| `LockUser` | internal/adminapi/handler.go:237 |
| `UnlockUser` | internal/adminapi/handler.go:271 |
| `ListSessions` | internal/adminapi/handler.go:294 |
| `RevokeAllSessions` | internal/adminapi/handler.go:329 |
| `QueryAudit` | internal/adminapi/handler.go:346 |
| `ListClients` | internal/adminapi/handler.go:394 |
| `GetClient` | internal/adminapi/handler.go:428 |
| `CreateClient` | internal/adminapi/handler.go:449 |
| `RevokeClient` | internal/adminapi/handler.go:514 |
| `RotateClientSecret` | internal/adminapi/handler.go:533 |
| `GetConfig` | internal/adminapi/handler.go:577 |
| `UpdateConfig` | internal/adminapi/handler.go:587 |
| `DeleteConfig` | internal/adminapi/handler.go:622 |
| `GetMetrics` | internal/adminapi/handler.go:646 |
| `ListAdmins` | internal/adminapi/handler.go:657 |
| `CreateAdmin` | internal/adminapi/handler.go:693 |
| `RevokeAdmin` | internal/adminapi/handler.go:774 |
| `SessionAuth` | internal/adminapi/middleware.go:115 |
| `GetSession` | internal/adminapi/middleware.go:207 |
| `NewRouter` | internal/adminapi/router.go:26 |
| `withPerm` | internal/adminapi/router.go:123 |
| `isCriticalEvent` | internal/audit/audit.go:123 |
| `DroppedTotal` | internal/audit/audit.go:132 |
| `Get` | internal/cache/postgres.go:24 |
| `Set` | internal/cache/postgres.go:39 |
| `Delete` | internal/cache/postgres.go:53 |
| `GetAndDelete` | internal/cache/postgres.go:59 |
| `SetIfNotExists` | internal/cache/postgres.go:76 |
| `Increment` | internal/cache/postgres.go:100 |
| `Exists` | internal/cache/postgres.go:128 |
| `Get` | internal/cache/redis.go:37 |
| `Set` | internal/cache/redis.go:46 |
| `Delete` | internal/cache/redis.go:51 |
| `GetAndDelete` | internal/cache/redis.go:57 |
| `SetIfNotExists` | internal/cache/redis.go:66 |
| `Increment` | internal/cache/redis.go:78 |
| `Exists` | internal/cache/redis.go:91 |
| `Close` | internal/cache/redis.go:96 |
| `runSeed` | internal/cli/cli.go:347 |
| `cleanupAudit` | internal/cli/cli.go:369 |
| `exportAudit` | internal/cli/cli.go:394 |
| `Argon2ActiveCount` | internal/crypto/argon2.go:77 |
| `Argon2RejectedCount` | internal/crypto/argon2.go:82 |
| `Argon2MaxConcurrent` | internal/crypto/argon2.go:87 |
| `SetDefaults` | internal/email/templates.go:164 |
| `SetRenderer` | internal/email/templates.go:248 |
| `ConfirmPassword` | internal/handler/auth.go:207 |
| `Verify` | internal/handler/backup_codes.go:83 |
| `UploadNamed` | internal/handler/blob.go:122 |
| `DownloadNamed` | internal/handler/blob.go:182 |
| `DeleteNamed` | internal/handler/blob.go:223 |
| `Capabilities` | internal/handler/capabilities.go:14 |
| `Disable` | internal/handler/totp.go:157 |
| `UpdateProfile` | internal/handler/user.go:65 |
| `ListCredentials` | internal/handler/webauthn.go:260 |
| `DeleteCredential` | internal/handler/webauthn.go:287 |
| `NewDynamicWellKnownHandler` | internal/handler/wellknown.go:26 |
| `SafeLogValue` | internal/httputil/safelog.go:8 |
| `New` | internal/keystore/keystore.go:59 |
| `SetOnKeyChange` | internal/keystore/keystore.go:73 |
| `KeyProvider` | internal/keystore/keystore.go:98 |
| `Import` | internal/keystore/keystore.go:104 |
| `Rotate` | internal/keystore/keystore.go:169 |
| `Revoke` | internal/keystore/keystore.go:179 |
| `Refresh` | internal/keystore/keystore.go:195 |
| `ListKeys` | internal/keystore/keystore.go:270 |
| `StartRefreshLoop` | internal/keystore/keystore.go:304 |
| `EnsureKey` | internal/keystore/keystore.go:335 |
| `CleanupExpired` | internal/keystore/keystore.go:368 |
| `AdminAuth` | internal/middleware/admin.go:13 |
| `StaticTokenAuth` | internal/middleware/admin.go:47 |
| `AuthDynamic` | internal/middleware/auth.go:37 |
| `AuthChallengeDynamic` | internal/middleware/auth.go:42 |
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
| `NewBlobRepo` | internal/repository/postgres/blob.go:18 |
| `Create` | internal/repository/postgres/blob.go:23 |
| `GetByIDAndPseudonym` | internal/repository/postgres/blob.go:41 |
| `GetByRefAndPseudonym` | internal/repository/postgres/blob.go:61 |
| `DeleteByRefAndPseudonym` | internal/repository/postgres/blob.go:81 |
| `ListByPseudonym` | internal/repository/postgres/blob.go:93 |
| `GetQuota` | internal/repository/postgres/blob.go:118 |
| `Delete` | internal/repository/postgres/blob.go:131 |
| `NewClientRepo` | internal/repository/postgres/client.go:18 |
| `Create` | internal/repository/postgres/client.go:23 |
| `GetByID` | internal/repository/postgres/client.go:38 |
| `GetByName` | internal/repository/postgres/client.go:56 |
| `List` | internal/repository/postgres/client.go:74 |
| `Update` | internal/repository/postgres/client.go:99 |
| `Deactivate` | internal/repository/postgres/client.go:113 |
| `New` | internal/repository/postgres/db.go:18 |
| `Close` | internal/repository/postgres/db.go:43 |
| `NewDeviceRepo` | internal/repository/postgres/device.go:19 |
| `Create` | internal/repository/postgres/device.go:24 |
| `GetByID` | internal/repository/postgres/device.go:39 |
| `GetByFingerprint` | internal/repository/postgres/device.go:54 |
| `ListByUser` | internal/repository/postgres/device.go:69 |
| `UpdateLastSeen` | internal/repository/postgres/device.go:93 |
| `UpdateFriendlyName` | internal/repository/postgres/device.go:102 |
| `Trust` | internal/repository/postgres/device.go:111 |
| `Delete` | internal/repository/postgres/device.go:120 |
| `DeleteAllForUser` | internal/repository/postgres/device.go:129 |
| `NewIdentityRepo` | internal/repository/postgres/identity.go:18 |
| `Upsert` | internal/repository/postgres/identity.go:23 |
| `GetByPseudonym` | internal/repository/postgres/identity.go:40 |
| `Delete` | internal/repository/postgres/identity.go:56 |
| `NewPasswordHistoryRepo` | internal/repository/postgres/password_history.go:15 |
| `Create` | internal/repository/postgres/password_history.go:20 |
| `GetRecentByUser` | internal/repository/postgres/password_history.go:31 |
| `NewRateLimitRepo` | internal/repository/postgres/rate_limit.go:17 |
| `Increment` | internal/repository/postgres/rate_limit.go:20 |
| `Get` | internal/repository/postgres/rate_limit.go:35 |
| `DeleteExpired` | internal/repository/postgres/rate_limit.go:50 |
| `NewRefreshTokenRepo` | internal/repository/postgres/refresh_token.go:18 |
| `Create` | internal/repository/postgres/refresh_token.go:23 |
| `GetByTokenHash` | internal/repository/postgres/refresh_token.go:38 |
| `MarkUsed` | internal/repository/postgres/refresh_token.go:62 |
| `RevokeByID` | internal/repository/postgres/refresh_token.go:71 |
| `RevokeByDeviceID` | internal/repository/postgres/refresh_token.go:80 |
| `RevokeFamily` | internal/repository/postgres/refresh_token.go:89 |
| `RevokeAllForUser` | internal/repository/postgres/refresh_token.go:98 |
| `RevokeAll` | internal/repository/postgres/refresh_token.go:107 |
| `CountActiveFamilies` | internal/repository/postgres/refresh_token.go:116 |
| `DeleteExpired` | internal/repository/postgres/refresh_token.go:128 |
| `deref` | internal/repository/postgres/scan.go:6 |
| `newDeviceScan` | internal/repository/postgres/scan.go:23 |
| `ptrs` | internal/repository/postgres/scan.go:25 |
| `device` | internal/repository/postgres/scan.go:32 |
| `NewSocialAccountRepo` | internal/repository/postgres/social_account.go:17 |
| `Create` | internal/repository/postgres/social_account.go:22 |
| `GetByProviderAndID` | internal/repository/postgres/social_account.go:34 |
| `ListByUser` | internal/repository/postgres/social_account.go:50 |
| `Delete` | internal/repository/postgres/social_account.go:73 |
| `NewTOTPRepo` | internal/repository/postgres/totp.go:17 |
| `Create` | internal/repository/postgres/totp.go:20 |
| `GetByUserID` | internal/repository/postgres/totp.go:31 |
| `MarkVerified` | internal/repository/postgres/totp.go:46 |
| `DeleteByUserID` | internal/repository/postgres/totp.go:55 |
| `NewUserRepo` | internal/repository/postgres/user.go:19 |
| `Create` | internal/repository/postgres/user.go:24 |
| `GetByID` | internal/repository/postgres/user.go:39 |
| `GetByEmail` | internal/repository/postgres/user.go:47 |
| `Update` | internal/repository/postgres/user.go:55 |
| `UpdatePassword` | internal/repository/postgres/user.go:70 |
| `IncrementFailedLogin` | internal/repository/postgres/user.go:79 |
| `ResetFailedLogin` | internal/repository/postgres/user.go:88 |
| `LockUntil` | internal/repository/postgres/user.go:97 |
| `Unlock` | internal/repository/postgres/user.go:106 |
| `VerifyEmail` | internal/repository/postgres/user.go:115 |
| `scanUser` | internal/repository/postgres/user.go:123 |
| `nullStr` | internal/repository/postgres/user.go:146 |
| `NewWebAuthnRepo` | internal/repository/postgres/webauthn.go:17 |
| `Create` | internal/repository/postgres/webauthn.go:20 |
| `GetByCredentialID` | internal/repository/postgres/webauthn.go:32 |
| `ListByUser` | internal/repository/postgres/webauthn.go:48 |
| `UpdateSignCount` | internal/repository/postgres/webauthn.go:71 |
| `Delete` | internal/repository/postgres/webauthn.go:80 |
| `RunAdmins` | internal/seed/seed.go:205 |
| `seedAdmin` | internal/seed/seed.go:214 |
| `Start` | internal/server/server.go:105 |
| `parseCORSOrigins` | internal/server/server.go:414 |
| `SetRateLimitRepo` | internal/service/auth.go:132 |
| `SetHoneypotAlerter` | internal/service/auth.go:139 |
| `SetMetrics` | internal/service/auth.go:144 |
| `SetMaxSessionsPerUser` | internal/service/auth.go:151 |
| `CompleteMFALogin` | internal/service/auth.go:619 |
| `sendEmailOTP` | internal/service/auth.go:675 |
| `refHash` | internal/service/blob.go:55 |
| `UploadNamed` | internal/service/blob.go:66 |
| `DownloadNamed` | internal/service/blob.go:176 |
| `DeleteNamed` | internal/service/blob.go:280 |
| `AccessTokenTTL` | internal/service/token.go:139 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `LocalOnly` | internal/adminapi/middleware.go:51 | 68.4% |
| `RBACCheck` | internal/adminapi/middleware.go:187 | 60.0% |
| `Log` | internal/audit/audit.go:164 | 52.6% |
| `cleanup` | internal/cache/memory.go:132 | 45.5% |
| `rotateAdminToken` | internal/cli/cli.go:264 | 69.2% |
| `Load` | internal/config/config.go:244 | 51.2% |
| `loadSecrets` | internal/config/config.go:405 | 73.1% |
| `isValidHexColor` | internal/config/config.go:506 | 66.7% |
| `setDefaultBool` | internal/config/profiles.go:123 | 44.4% |
| `acquireArgon2` | internal/crypto/argon2.go:53 | 60.0% |
| `init` | internal/crypto/argon2.go:97 | 60.0% |
| `safeFuncMap` | internal/email/templates.go:78 | 57.1% |
| `writeUploadError` | internal/handler/blob.go:351 | 60.0% |
| `Verify` | internal/handler/email_otp.go:24 | 57.1% |
| `Resend` | internal/handler/email_otp.go:53 | 33.3% |
| `completeMFAIfChallenge` | internal/handler/mfa_helper.go:16 | 11.1% |
| `Authorize` | internal/handler/oauth.go:67 | 73.1% |
| `NewPasswordHandler` | internal/handler/password.go:55 | 50.0% |
| `VerifyFinish` | internal/handler/webauthn.go:196 | 73.7% |
| `Alert` | internal/honeypot/honeypot.go:75 | 72.7% |
| `DPoP` | internal/middleware/dpop.go:16 | 56.5% |
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
| `dial` | internal/redis/pool.go:167 | 73.3% |
| `initSelect` | internal/redis/pool.go:248 | 72.7% |
| `writeCommand` | internal/redis/resp.go:22 | 55.6% |
| `validate` | internal/seed/seed.go:81 | 70.3% |
| `setupRoutes` | internal/server/server.go:170 | 73.8% |
| `Login` | internal/service/auth.go:302 | 60.0% |
| `findOrCreateDevice` | internal/service/auth.go:727 | 57.9% |
| `isAccountLocked` | internal/service/auth.go:764 | 33.3% |
| `isIPLocked` | internal/service/auth.go:810 | 31.6% |
| `recordFailedIP` | internal/service/auth.go:839 | 33.3% |
| `checkSessionLimit` | internal/service/auth.go:862 | 22.2% |
