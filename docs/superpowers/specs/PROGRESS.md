# vault42 0.8.9 — overnight build PROGRESS

**Branch:** `release/0.8.9` · **Started:** 2026-06-18 ~22:15 · **Stop at:** ~04:00 2026-06-19
**Spec:** `2026-06-18-vault42-beon3-parity-design.md`
**Hard rules:** local only — NEVER push, NEVER touch `main`; no sudo; no destructive ops;
never clear the Nitrokey. Commit per cycle ONLY when `scripts/release-check.sh` is green.
**Loop:** 5-min session cron job id `24acf589` — after 04:00 run CronList+CronDelete it.
**Test env:** `DOCKER_HOST=unix:///run/user/1000/podman/podman.sock TESTCONTAINERS_RYUK_DISABLED=true GOTOOLCHAIN=auto GOFLAGS=-mod=mod`

## Metrics (update each cycle)
- Coverage: baseline ~70.7% → **target ≥89%** → current: _measuring_
- govulncheck: **CLEAN** (go1.26.4) · gosec HIGH/CRIT: 0 · frontend audit: clean
- Security audit: 16 confirmed (2 HIGH/7 MED/7 LOW) → **H1+H2 FIXED**; 7 MED/7 LOW remain
- Tests: internal + attack + compliance + fuzz must stay green

## Per-cycle protocol
1. `git -C /mnt/projects/vault42 log --oneline -5` + read this file → know where we are.
2. Pick the next unchecked item in priority order (0→1→2→3→4 below).
3. TDD: write/extend tests first, then implement. One behavior per test.
4. Verify: targeted `go test` for touched pkgs + `DOCKER_HOST=unix:///run/user/1000/podman/podman.sock TESTCONTAINERS_RYUK_DISABLED=true` for DB tests; run `scripts/release-check.sh` before committing.
5. If green → commit to `release/0.8.9` (conventional msg, no Claude co-author trailer) → tick the box here + append a one-line cycle-log entry.
6. If time > 04:00 → final wrap-up commit + summary, do NOT reschedule.
7. Use Workflow fan-out for independent test files; grok fleet for the security audit + self-contained additive tests. Keep source WRITES serialized on this branch.

## Workstreams

### WS0 — security/deps baseline
- [x] go.mod toolchain → go1.26.4
- [x] Dockerfiles golang→1.26.4-alpine + node digest refresh
- [x] `go get -u ./...` + `go mod tidy` (webauthn 0.17.4, pgx 5.10.0, crypto 0.53.0)
- [x] frontend `pnpm update -r` + audit clean + builds/tests green
- [x] govulncheck CLEAN, build, vet pass
- [x] gosec G710 open-redirect guard in `internal/handler/oauth.go`
- [x] CHANGELOG + version bump to 0.8.9

### WS1 — BeOn3 profile/user parity (hybrid)
- [x] Extend `IdentityData` (Username, State, MarketingEmails, Dynamic map) + validation + tests
- [x] Migration `004_user_account_flags.sql` (disabled, banned, ban_reason, last_login_at, deleted, deleted_at) + vault_app grants
- [x] User model + repo: scan/write new columns; login gate (banned/disabled/deleted); set last_login_at
- [x] Identity handler accepts/returns new fields; dynamic-JSON size/shape guard
- [x] Tests: profile round-trip, gate rejections, dynamic abuse

### WS2 — custom roles catalog
- [x] Migration `005_app_roles.sql` + seed (moderator, premium_user, business, creator, user, viewer, operator)
- [x] `app_roles` repo + catalog cache; catalog-aware `FilterUserRoles`
- [x] Admin-gateway endpoints: list/create/delete app_roles (super_admin; can't delete reserved)
- [x] Tests: catalog validation, reserved rejection, JWT roles path, escalation attack

### WS3 — account import + magic-link forced reset
- [x] Migration: `import_pending`, `imported_from`, `legacy_id` (+unique idx) on auth.users + model/repo (CreateImported/ClearImportPending)
- [x] `POST /admin/users/import` (super_admin) batch create, idempotent, roles+flags+legacy_id, hash NULL (profile PII via identity API post-claim)
- [x] Login interception: import_pending → skip pw verify, mint magic link, 202 (rate-limited by existing login RL)
- [x] Reset-confirm clears import_pending + sets Argon2; audit import_claimed
- [x] Tests: import idempotency, login→claim email, reset clears import_pending (replay/expiry inherited from reset-token single-use)

### WS5 — generic OIDC / OAuth authority (Okta & any OpenID Connect issuer)
Requested by v 2026-06-18: support a configurable generic OIDC provider (Okta, Auth0,
Authentik, Keycloak, Entra, Google-OIDC, etc.) alongside the hardcoded GitHub/Facebook.
- [x] `internal/oauth2/oidc.go`: OIDCProvider discovery+authorize+exchange+userinfo + ID-token JWKS validation (alg allowlist, iss/aud/exp/nonce, embedded-key-header reject, 2048-bit min).
- [x] Config: VAULT_OIDC_PROVIDERS + per-name env (issuer/client_id/scopes + CLIENT_SECRET_FILE); wired into providers map in cmd/vault.
- [x] Nonce-bound ID-token verification in the OAuth callback (prefers verified id_token; falls back to userinfo for non-OIDC); maps onto the existing social-account/user-link path.
- [x] Tests: discovery, authorize URL, exchange/userinfo, ID-token good/expired/bad-aud/bad-iss/bad-sig/bad-nonce + alg=none + forgery, config loader.

### WS4 — coverage ≥89% + hardening
- [ ] Map under-covered packages; fan out test-writing (workflow + grok)
- [ ] Attack tests for the new flows; keep fuzz green
- [ ] Reach ≥89% statement coverage; final hardening pass + CHANGELOG

### WS6 — multi-replica E2E verification (grok-delegated NOW, 16 agents, TEST-ONLY)
Requested by v 2026-06-18: verify vault42 runs correctly as ≥2 replicas under multiple
config matrices, with extensive e2e tests. Delegated to grok on its own trunk branch
`grok/multireplica-e2e` (off release/0.8.9). Stage-2 gate: **merge ONLY test-file diffs** —
reject any non-test source change (grok must surface real bugs, not patch source to pass).
- [x] grok wrote Go e2e tests under tests/e2e/multireplica/: TWO in-process vault
  instances sharing ONE postgres + ONE redis testcontainer; assert cross-replica:
  token issued on A verifies on B (shared JWKS); refresh rotation on B + replay of A's token
  detected; account/MFA lockout counter shared; MFA challenge on A completed on B; rate-limit
  + session-count shared; signing-key rotation on A seen by B; verify/reset/import token minted
  on A consumed on B.
- [x] Config matrix: redis (shared) + dev/production profiles; MemoryCacheNotShared proves in-memory per-process.
  Document that the in-memory cache is per-process → NOT multi-replica safe.
- [x] Claude Stage-2: test-only diff gate PASSED; fixed migrations-dir/shared-master-key/per-profile-DB; all green on release/0.8.9 (mig 001-006); merged.

## Cycle log
- C0 (22:15) — WS0: go1.26.4 + all deps updated; govulncheck clean; frontend green; spec+progress written. Committed 86f2cb9/2b3b4bf/9fb3162.
- C1 (22:55) — WS1.1: extended IdentityData (Username/State/MarketingEmails/Dynamic) + Validate() + 15 test cases; service pkg green. Committed 75c4404. Mark TODO: identity HANDLER must call Validate() + accept/return new fields (next WS1 slice).
- C2 (22:30) — WS0: gosec G710 oauth open-redirect guard (isSafeAuthorizeRedirect + nosec) + 8 test cases; gosec now 0 HIGH/CRIT/MEDIUM. Committed 02ada6a. NEW: added WS5 (generic OIDC/Okta authority) per v request — loop should build it after WS3.
- C3 (22:35) — WS1.2: migration 004 account flags + partial index + grant; TestMigrateRun green (applies+idempotent). Committed. NEXT WS1.3: scan/write columns in model.User + repo + login gate (banned/disabled/deleted) + set last_login_at.
- C4 (22:43) — AUDIT H1 (MFA email-OTP downgrade) FIXED: emailOTPAllowed gate on send+verify + 7 tests; updated 3 existing tests; service/handler/attack suites green. Committed. NEXT: audit H2 (per-account MFA lockout), then resume WS1.3 (user model/repo/login-gate).
- C5 (22:48) — AUDIT H2 (no per-account MFA lockout) FIXED: MFAVerifyLocked/RecordMFAFailure reuse password lockout counter; gated TOTP+email-OTP+backup verify; clear on success; 3 tests. service/handler/attack green. Committed. NEXT: resume WS1.3 (user model/repo/login-gate) then WS2.
- C6 (22:55) — WS1.3: model.User flags + repo scan + SetLastLogin + login gate (banned→ErrAccountBanned, disabled→ErrAccountDisabled, deleted→invalid-creds) + last_login stamp; 3 gate tests. BONUS: fixed tests/integration fixture (dynamic migrations) — repaired the whole integration suite (silently broken since mig 003, not in CI). internal-race + integration + attack all green. Committed 085d609. NEXT WS1.4: identity handler accepts/returns new fields + dynamic guard.
- C7 (23:01) — WS1.4 (completes WS1): identity API exposes username/state/marketing_emails/dynamic; Validate() rejections → 400; round-trip + dynamic-abuse tests. handler pkg green. Committed. WS1 DONE. NEXT: WS2 (roles catalog, migration 005).
- C8 (23:05) — WS2.1: migration 005 app_roles catalog + seed (3 core reserved + 4 beon3); vault_app SELECT grant; TestMigrateRun green. Committed. NEXT WS2.2: app_roles repo + catalog cache + catalog-aware FilterUserRoles.
- C9 (23:10) — WS2.2a: model.AppRole + AppRoleRepository + postgres AppRoleRepo (List/ListNames/Get/Create/Delete, reserved-protected, idempotent) + integration test (6 cases) green. Committed. NEXT WS2.2b: catalog cache + catalog-aware FilterUserRoles at JWT issuance.
- C10 (23:20) — WS2.2b: RoleCatalog (TTL cache, fail-open) + effectiveRoles (admin-filter ∩ catalog, [user] fallback); centralized 3 JWT role sites; wired SetRoleCatalog in cmd/vault; MockAppRoleRepo + 5 tests; service green. GROK task 001 (multireplica e2e) still running. NEXT WS2.3: admin-gateway app_roles CRUD endpoints.
- C11 (23:26) — WS2.3 (completes WS2): /admin/roles CRUD (rbac roles:list/create/delete), name+reserved+dup validation, reserved-delete 403; wired SetAppRoleRepo in cmd/admin-gateway; 9 tests; adminapi+rbac green. WS2 DONE. NEXT: WS3 (account import + magic-link). grok 001 still running.
- C12 (23:30) — WS3.1: migration 006 import cols + model.User fields + repo scan + CreateImported (idempotent, passwordless, email-verified) + ClearImportPending; integration test green. Committed. NEXT WS3.2: POST /admin/users/import endpoint, then login interception + magic link.
- C13 (23:35) — WS3.2: login interception (import_pending → dummy hash, mint reset token, magic link email, 202 ImportClaimRequired) + ResetConfirm clears import_pending (import_claimed audit) + map banned/disabled→403. Service+handler tests green. NEXT WS3.3: POST /admin/users/import batch endpoint + enumeration/replay tests.
- C14 (23:40) — WS3.3 (completes WS3): POST /admin/users/import (rbac users:import, idempotent, admin-role strip, flags+legacy_id, per-row results, 1000 cap); 4 tests; adminapi+rbac green. WS3 DONE. NEXT: WS5 (generic OIDC authority).
- C15 (23:50) — WS6 DONE: grok 16-agent multireplica e2e suite reviewed+merged (test-only). 8 cross-replica behaviors × dev+production + MemoryCacheNotShared all green. Stage-2 fixes: migrations-dir walk-up, shared MASTER_KEY across replicas, per-profile DB isolation. NOTE: one transient FAIL observed under overlapping container runs (port/resource contention) — passes cleanly in isolation; flag suite for a port-allocation hardening pass if it recurs in CI. NEXT: WS5 (generic OIDC).
- C16 (23:54) — WS5.1: generic OIDCProvider (discovery cache + issuer-match, authorize openid+nonce+PKCE, exchange, userinfo) + 3 httptest-fake-issuer tests; oauth2 green. NEXT WS5.2: ID-token JWKS validation (alg=none/forgery attack test), then config registration + bootstrap wiring.
- C17 (00:02) — WS5.2: VerifyIDToken (JWKS fetch+cache+rotation, RS256/384/512 only, iss/aud/exp/nonce, reject alg=none/HMAC/jku/x5u/x5c/jwk/<2048bit) + 7 tests incl. alg=none + forgery; oauth2 green. NEXT WS5.3: config registration of N OIDC providers + bootstrap wiring + callback ID-token verification.
- C18 (00:05) — WS5.3+5.4 (completes WS5): OIDC provider config (VAULT_OIDC_PROVIDERS + per-name env, _FILE secret) + bootstrap wiring + callback prefers verified nonce-bound id_token; config tests green. WS5 DONE.
- C19 (00:20) — AUDIT batch 1 (M4/M5/M6/L3): Config.Validate() fail-closed startup guard (HMAC/pepper/origin presence + TLS-disable + TLS-no-cert) wired in cmd/vault; 10 tests; config green. Parallel: grok coverage campaign (task 002) + audit workflow done (AUDIT-FIXES.md). NEXT batches: L2/L7/M2/L1/L6/M7/L4/L5 then M1+M3 (test-migrating).
- C20 (00:23) — AUDIT batch 2 (L2 RSA upper bound in dpop parseJWKHeader, L7 lock-duration clamp helper) + 2 tests; crypto+adminapi green. grok coverage campaign round 0 = 60.3% (cross-pkg), climbing. NEXT: M2 authorize rate-limit, L1 session fail-closed, L6 audit target-id, M7/L4, L5, then M1+M3.
- C21 (00:27) — AUDIT batch 3 (M2 authorize rate-limit, L6 admin audit target column); build/vet/adminapi/server green. grok campaign round1=71.4%. 8/14 audit fixed. NEXT: L1 (strict session opt-in), M7/L4 (proxy trust), L5, then M1+M3 (test-migrating).
- C22 (00:33) — AUDIT M1: enforce 2fa_challenge device-fingerprint binding on MFA completion (ChallengeFingerprintMatches + audit) ; service/handler green. 9/14 audit fixed. grok campaign task002 at grok-review. NEXT: M3 (OAuth CSRF cookie-binding + migrate ~18 tests), L1, M7/L4, L5.
- C23 (00:36) — AUDIT M7: gate VAULT_EMBEDDED_TRUSTED_UPSTREAM to embedded profile (hard error elsewhere); negative test + migrated 1 test; config green. 10/14 audit fixed. grok campaign plateauing ~71.4% (round 2/8) — DB/cache/shellout paths cap pure-unit coverage; monitoring. NEXT: L1, L4, L5, M3.
- C24 (00:45) — AUDIT L1: opt-in VAULT_STRICT_SESSION_LIMIT fail-closed on session-count error (default preserved) + test; service/config green. 11/14 audit fixed. Remaining: M3 (CSRF, grok-delegate after coverage), L4 (rate-limit FailClosed), L5 (LoadSecret zeroing opt-in). grok coverage round3=73.4%.
- C25 (00:48) — AUDIT L5: secret-file zeroing/removal now opt-in (VAULT_SECRET_FILE_CONSUME) + logs failures; migrated 2 tests + default test; config green. 12/14 audit fixed. Remaining: L4 (rate-limit FailClosed flag), M3 (CSRF — grok-delegate after coverage parks).
- C26 (00:53) — AUDIT L4: RateLimitConfig.FailClosed (503 on cache outage for login/register/pwreset/TOTP, no per-pod fallback) + test; middleware/server green. 13/14 audit fixed — only M3 (CSRF) remains (grok-delegate after coverage campaign parks). grok coverage round4=73.7% (plateauing).
- C27 (00:56) — WS0 final: comprehensive 0.8.9 CHANGELOG entry (features + security/audit + tests). grok coverage round5=75.6% (3 rounds left, ~80% ceiling). NEXT: park campaign → merge coverage tests + finalize coverage number; grok-delegate M3; final release-check.
- C28 (01:00) — HEALTH CHECK: full build OK, govulncheck CLEAN, gosec 0 HIGH/CRIT; vet caught attack stubUserRepo missing 3 new UserRepository methods (latent CI compile break) → fixed. grok coverage oscillating 73-76% (round 6=73.1%, ceiling ~76%). NEXT: campaign parks → merge best test state + record honest %; then M3 + final release-check.
