# vault42 KMS unwrap-oracle + life42 clients — Implementation Plan (Plan A)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or executing-plans. Checkbox steps.

**Goal:** Give vault42 an envelope wrap/unwrap (KMS `Decrypt`) capability and the clients life42 needs, so life42 can release its data-root via a workload identity and get MCP/dashboard JWTs.

**Architecture:** Reuse `internal/keystore` AES-256-GCM (kid as AAD) for a named KEK class distinct from JWT signing keys. New `internal/handler/kms.go` exposes `POST /kms/unwrap` (client_credentials + scope `kms:unwrap`) and admin-only `POST /kms/wrap`. Add a per-client access-token TTL override so the `life42-mcp` client can mint 12h tokens. Declarative seed for `life42-gateway`, `life42-mcp`, `life42-dash`.

**Tech Stack:** Go 1.26, stdlib + pgx (no new deps — vault42 invariant). All vault42 security invariants apply (constant-time, no enumeration, 8KB cap, RS256-only, audit append-only). Docs sync mandatory.

**Counterpart:** life42 Plan B `~/Projects/life42/docs/superpowers/plans/2026-06-13-life42-vault42-reroot.md`.

---

## Pre-work
- [ ] Read `internal/keystore/keystore.go`, `internal/handler/client.go` (the `/client/token` grant), `internal/service/*` token issuance, `internal/seed`, `docs/api.md` + `docs/config.md`. Confirm the client_credentials scope plumbing and where access-token TTL is decided.

## Task 1: KEK class in keystore (wrap/unwrap primitive)
**Files:** `internal/keystore/kek.go` (+ `_test.go`)
- [ ] Failing test: `Wrap(kid, plaintext)`→ciphertext, `Unwrap(kid, ciphertext)`→plaintext round-trips; wrong kid as AAD fails; tampered ciphertext fails (constant-time). Distinct namespace from signing keys.
- [ ] Run → FAIL.
- [ ] Implement over existing AES-256-GCM + DB-encrypted key storage; kid is AAD; never export the KEK.
- [ ] Run → PASS. `/security` clean (gosec/govulncheck/staticcheck).
- [ ] Commit: `feat(keystore): named KEK class for envelope wrap/unwrap`.

## Task 2: unwrap/wrap handlers + scope auth
**Files:** `internal/handler/kms.go` (+ `_test.go`), route registration in `internal/server/server.go`
- [ ] Failing tests: `POST /kms/unwrap` requires a valid access token with scope `kms:unwrap` bound to the requested kid → 200 plaintext; missing/insufficient scope → 403 (generic, no enumeration); body > 8KB → 413; bad ciphertext → 400 generic; `POST /kms/wrap` admin-gateway only.
- [ ] Run → FAIL.
- [ ] Implement: parse Bearer, validate scope+kid binding, call keystore Unwrap, audit (append-only) every call (success+fail), rate-limit. Constant-time tag compares.
- [ ] Run → PASS.
- [ ] Add attack vectors in `tests/attack/`: scope confusion (user token used on /kms/unwrap), kid traversal, replay, oversized body. Add fuzz target for the unwrap body in `tests/fuzz/`.
- [ ] Commit: `feat(handler): /kms/unwrap + /kms/wrap envelope oracle with scope auth`.

## Task 3: per-client access-token TTL override
**Files:** client model/config + token issuance service (+ tests)
- [ ] Failing test: a client configured with `access_token_ttl=12h` issues a 12h access token; clients without the override keep the 5–15min default; the override cannot exceed a configured ceiling (e.g. `VAULT_MAX_CLIENT_ACCESS_TTL`).
- [ ] Run → FAIL.
- [ ] Implement: optional per-client TTL, clamped to the ceiling; never widen the global default.
- [ ] Run → PASS.
- [ ] Commit: `feat(client): optional per-client access-token TTL (clamped)`.

## Task 4: declarative seed for life42 clients
**Files:** `internal/seed/*`, a seed JSON example in `docs/`
- [ ] Add clients: `life42-gateway` (grant client_credentials, scope `kms:unwrap`, kid binding `life42-root-kek`), `life42-mcp` (aud `life42-mcp`, access_token_ttl 12h, scope `mcp`), `life42-dash` (auth-code+PKCE, aud `life42-dash`). Test the seed loads and the clients validate.
- [ ] Commit: `feat(seed): life42 gateway/mcp/dash clients`.

## Task 5: docs sync (mandatory, same change)
**Files:** `docs/config.md`, `docs/api.md`, `docs/spec.md`, `docs/security.md` (new `AR-N`: unattended workload-credential trade-off; 12h MCP token rationale), `docs/cheatsheet.md`, `README.md`, `CLAUDE.md`.
- [ ] Document the new endpoints, scopes, config vars, and accepted risks.
- [ ] `scripts/precommit.sh` → OK. `scripts/release-check.sh` (nightly-mirror) → OK.
- [ ] Commit: `docs: KMS unwrap oracle, per-client TTL, life42 clients`.

## Self-Review
- Endpoints (§5.2 spec) → T2; KEK (§5.1) → T1; per-client TTL (§5.3) → T3; seed (§5.4) → T4; docs (§5.5) → T5. ✓
- No new deps. All invariants enforced in T2 tests. Audit + attack + fuzz coverage present. ✓
