-- Migration 002 — A-10: revoke vault_app SELECT on admin_users / admin_sessions
--
-- The user-facing Vault service (vault_app role) historically had SELECT on
-- auth.admin_users and auth.admin_sessions. Those tables expose
-- password_hash and session token_hash columns. Even though the hashes are
-- one-way, least-privilege says vault_app should not see them: it has no
-- code path that needs to query admin metadata.
--
-- Verified before this migration: no `cmd/vault/...` or `internal/service/...`
-- or `internal/handler/...` source file constructs AdminUserRepo or
-- AdminSessionRepo. The repos are wired exclusively from
-- `cmd/admin-gateway/main.go`, which uses the `vault_admin` DB role.
--
-- auth.admin_roles is left readable (no credential material; role-name
-- definitions are non-sensitive metadata).

REVOKE SELECT ON auth.admin_users    FROM vault_app;
REVOKE SELECT ON auth.admin_sessions FROM vault_app;
