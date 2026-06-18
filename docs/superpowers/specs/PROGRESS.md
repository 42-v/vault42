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
- [ ] gosec G710 open-redirect guard in `internal/handler/oauth.go`
- [ ] CHANGELOG + version bump to 0.8.9

### WS1 — BeOn3 profile/user parity (hybrid)
- [x] Extend `IdentityData` (Username, State, MarketingEmails, Dynamic map) + validation + tests
- [ ] Migration `004_user_account_flags.sql` (disabled, banned, ban_reason, last_login_at, deleted, deleted_at) + vault_app grants
- [ ] User model + repo: scan/write new columns; login gate (banned/disabled/deleted); set last_login_at
- [ ] Identity handler accepts/returns new fields; dynamic-JSON size/shape guard
- [ ] Tests: profile round-trip, gate rejections, dynamic abuse

### WS2 — custom roles catalog
- [ ] Migration `005_app_roles.sql` + seed (moderator, premium_user, business, creator, user, viewer, operator)
- [ ] `app_roles` repo + catalog cache; catalog-aware `FilterUserRoles`
- [ ] Admin-gateway endpoints: list/create/delete app_roles (super_admin; can't delete reserved)
- [ ] Tests: catalog validation, reserved rejection, JWT roles path, escalation attack

### WS3 — account import + magic-link forced reset
- [ ] Migration: `import_pending`, `imported_from`, `legacy_id` (+unique idx) on auth.users
- [ ] `POST /admin/users/import` (super_admin) batch create, idempotent, profile+roles+flags, hash NULL
- [ ] Login interception: import_pending → skip pw verify, mint magic link, neutral 202, rate-limit
- [ ] Reset-confirm clears import_pending + sets Argon2; audit import_claimed
- [ ] Tests: import idempotency, login→email, magic-link replay/expiry, enumeration-safety

### WS4 — coverage ≥89% + hardening
- [ ] Map under-covered packages; fan out test-writing (workflow + grok)
- [ ] Attack tests for the new flows; keep fuzz green
- [ ] Reach ≥89% statement coverage; final hardening pass + CHANGELOG

## Cycle log
- C0 (22:15) — WS0: go1.26.4 + all deps updated; govulncheck clean; frontend green; spec+progress written. Committed 86f2cb9/2b3b4bf/9fb3162.
- C1 (22:55) — WS1.1: extended IdentityData (Username/State/MarketingEmails/Dynamic) + Validate() + 15 test cases; service pkg green. Committed 75c4404. Mark TODO: identity HANDLER must call Validate() + accept/return new fields (next WS1 slice).
