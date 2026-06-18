# vault42 0.8.9 — BeOn3 parity, custom roles, account import, hardening

**Date:** 2026-06-18
**Branch:** `release/0.8.9` (local only — NEVER push, NEVER touch `main`)
**Target:** prod-grade, all vuln scans green, all deps current, **≥89% statement coverage**,
fully tested. Driven by an overnight autonomous loop (commit per cycle).

## Locked decisions (from v, 2026-06-18)
1. **BeOn3 data storage = hybrid**: PII into the existing AES-GCM encrypted identity blob;
   account-level flags as columns on `auth.users`; a free-form encrypted `dynamic` JSON
   sub-area for BeOn3/forum-specific data.
2. **Custom roles = catalog table** (`auth.app_roles`); `user.roles` validated against it;
   admin-tier names stay reserved.
3. **Imported accounts = force reset via magic LINK**, ignore old password. BeOn3 SHA-256
   hashes are NOT imported/verified (incompatible crypto). Any login on an import-pending
   account → email a magic reset link → user sets a new Argon2 password.
4. **Loop policy = build + harden + test, commit per cycle to `release/0.8.9`**, no push.

---

## 0. Security/deps baseline (cycle 0 — DONE)
- `go.mod` toolchain → **go1.26.4**; Dockerfiles golang builder → `golang:1.26.4-alpine`
  (index digest), node → refreshed `node:22-alpine` digest. Clears govulncheck
  GO-2026-5039 (net/textproto) + GO-2026-5037 (crypto/x509) and the Trivy image stdlib CVEs.
- `go get -u ./... && go mod tidy` (all Go deps current); frontend `pnpm update` in `web/` +
  `packages/vue/`.
- **Standing rule for the loop:** every cycle re-runs `scripts/release-check.sh` (govulncheck,
  gosec HIGH/CRITICAL, build, vet, tests). Cycle only commits if it is green.
- gosec G710 open-redirect in `internal/handler/oauth.go`: add allowlist guard so the OAuth
  authorize redirect can only target a configured provider authorize URL.

## 1. BeOn3 profile/user parity (hybrid)

### 1a. Encrypted identity blob (`internal/service/identity.go` `IdentityData`)
Extend the struct (JSON, AES-GCM encrypted, keyed by HMAC pseudonym). Backward-compatible —
new fields are `omitempty`, old blobs decode fine.

| vault42 field            | type                         | BeOn3 source                         |
|--------------------------|------------------------------|--------------------------------------|
| `GivenName` (exists)     | string                       | UserProfile.FirstName                |
| `FamilyName` (exists)    | string                       | UserProfile.LastName                 |
| `Username`               | string                       | UserProfile.UserName (3–32)          |
| `Country` (exists)       | string (ISO 3166-1 alpha2)   | UserProfile.Country                  |
| `State`                  | string (ISO 3166-2, ≤3)      | UserProfile.State                    |
| `DateOfBirth` (exists)   | string (RFC3339 date)        | UserProfile.BirthDate                |
| `Sex` (exists)           | string ("male"/"female")     | UserProfile.Gender (0/1)             |
| `MarketingEmails`        | bool                         | UserProfile.MarketingEmails          |
| `Billing` (exists)       | *BillingInfo                 | —                                    |
| `Dynamic`                | map[string]json.RawMessage   | forum/garage/notif app data          |

`Dynamic` is namespaced by app, e.g. `{"beon3.forum": {...}, "beon3.garage": {...}}`. vault42
treats it as opaque, encrypted at rest, validated only for size + valid-JSON + namespace shape.
Forum data that lives here: ForumProfile (bio, location, website, avatarFileId, reputation,
postCount, rank, isModerator, mute state), subscriptions, garage/vehicle refs, notification prefs.

Validation: `Username` 3–32 chars; `Country` 2-letter; `State` ≤3; `Sex` in {male,female,""};
`Dynamic` total encoded size ≤ 64 KiB, keys match `^[a-z0-9]+(\.[a-z0-9]+)*$`.

### 1b. Account-level flags — migration `004_user_account_flags.sql`
Add to `auth.users` (all additive, defaults preserve existing rows):
- `disabled BOOLEAN NOT NULL DEFAULT FALSE` (admin disable; BeOn3 Active=false → disabled=true)
- `banned BOOLEAN NOT NULL DEFAULT FALSE` + `ban_reason VARCHAR(500)` (BeOn3 Banned/BanReason)
- `last_login_at TIMESTAMPTZ` (BeOn3 LastLogin; set on successful login)
- `deleted BOOLEAN NOT NULL DEFAULT FALSE` + `deleted_at TIMESTAMPTZ` (BeOn3 soft-delete)

Login gate: reject `banned` (audit `auth:login_banned`), `disabled`, `deleted` before password
verify, constant-time-ish (still run dummy hash to avoid enumeration). New `vault_app` column
grants for the added columns.

## 2. Custom roles catalog — migration `005_app_roles.sql`
```
CREATE TABLE auth.app_roles (
  name        VARCHAR(64) PRIMARY KEY,        -- e.g. 'moderator'
  namespace   VARCHAR(64) NOT NULL DEFAULT 'app',
  description VARCHAR(255) NOT NULL DEFAULT '',
  reserved    BOOLEAN NOT NULL DEFAULT FALSE, -- catalog-protected
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```
Seed BeOn3 roles: `moderator`, `premium_user`, `business`, `creator` (BeOn3 `Admin` maps to the
vault42 admin gateway, NOT a user role — `admin`/`super_admin` remain hard-reserved and rejected).
- `user`/`viewer`/`operator` baseline roles seeded too.
- Validation (`internal/seed` + service): every entry in `user.roles` must exist in `app_roles`
  and not be admin-reserved; unknown/reserved roles are dropped (audited), JWT still issued.
- Admin gateway endpoints (super_admin): list/create/delete `app_roles` (cannot delete `reserved`).
- `FilterUserRoles` becomes catalog-aware (cache the catalog, refresh on change).

## 3. Account import + magic-link forced reset
### 3a. Import — migration adds to `auth.users`:
- `import_pending BOOLEAN NOT NULL DEFAULT FALSE`
- `imported_from VARCHAR(64)` (e.g. 'beon3')
- `legacy_id UUID` (BeOn3 Users.Id, for cross-service join) + unique index on (imported_from, legacy_id)

Admin import endpoint `POST /admin/users/import` (super_admin, admin gateway):
batch of `{email, roles[], profile{...}, dynamic{...}, flags{banned,disabled,...}, legacy_id}`.
Creates users with `password_hash = NULL`, `import_pending = true`, `email_verified = true`
(they were verified in BeOn3), encrypted identity blob populated, roles validated against catalog.
Idempotent on email and on (imported_from, legacy_id). BeOn3 Hash/Salt are **discarded**.

### 3b. Login interception (`internal/service/auth.go` Login)
If the resolved user has `import_pending = true` (or `password_hash IS NULL`):
- Do NOT verify the supplied password (run dummy hash for timing).
- Mint a magic reset link token (reuse reset-token cache flow; key `import:<hash>` → userID,
  TTL 1h, single-use via GetAndDelete), email "Welcome to vault42 — set your password" with link
  `{origin}/reset-password?token=...&import=1`.
- Return a neutral `202`/`{status:"reset_email_sent"}` regardless of whether the email exists
  (anti-enumeration); rate-limited per email + per IP.

### 3c. Reset confirm
Existing `POST /auth/password/reset/confirm` accepts the token; on success sets new Argon2 hash,
clears `import_pending`, audits `auth:import_claimed`. Subsequent logins are normal.

## 4. Coverage to ≥89% + hardening
- Baseline ~70.7%. Fan out test-writing (workflows + grok fleet) across under-covered packages,
  one behavior per test (no coverage theatre, per v's test-minimalism rule).
- Attack-suite + compliance + fuzz must stay green. Add attack tests for: import-account login
  enumeration, banned/disabled login, role-catalog escalation, magic-link replay/expiry,
  dynamic-JSON size/shape abuse.
- Address gosec MEDIUM (G710) + tidy LOW findings where genuine.

## 5. Overnight loop mechanics
- One source of truth: `docs/superpowers/specs/PROGRESS.md` (workstream checklist + metrics).
- Each cycle: pull current metrics (coverage, scan status) → pick next unchecked item in priority
  order (0 → 1 → 2 → 3 → 4) → implement via TDD → run `release-check.sh` + targeted tests →
  if green, commit to `release/0.8.9` with a conventional message → update PROGRESS.md.
- Parallelism: use Workflow fan-out for independent test files / audits; use grok fleet for the
  security audit and self-contained additive test packages. The WRITE path to source stays
  serialized on this branch to avoid unattended merge conflicts.
- Stop at ~04:00. Never push. Never touch `main`. Gate on: no sudo, no destructive ops,
  never clear the Nitrokey.

## Non-goals
- No PayPal/billing changes. No admin-gateway auth model change. No frontend redesign (only
  wire new fields/flows into existing Vue where needed). No data migration FROM a live BeOn3 DB
  in this branch (import endpoint + format only; actual ETL is a separate run).
