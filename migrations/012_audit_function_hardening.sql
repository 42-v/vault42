-- ============================================================================
-- 012: audit purge hardening + the admin-gateway grants that were never made
-- ============================================================================
--
-- Part 1: audit.cleanup_old_entries()
--
-- The append-only audit log is enforced by a trigger that refuses DELETE, plus
-- `REVOKE UPDATE, DELETE ON audit.audit_log FROM vault_app` in 001. The one
-- sanctioned removal path is audit.cleanup_old_entries(), which is SECURITY
-- DEFINER because it has to disable that trigger to purge past the retention
-- horizon.
--
-- Three things were wrong with it, all verified against a real database:
--
--   1. Its owner is vault_mig, the role that runs migrations, which in the
--      shipped chart is POSTGRES_USER and therefore the superuser that also owns
--      audit.audit_log. SECURITY DEFINER escalates every caller to it, and it is
--      the table owner, so ALTER TABLE ... DISABLE TRIGGER succeeds.
--   2. Nothing revoked EXECUTE, and PostgreSQL grants EXECUTE on functions to
--      PUBLIC by default. Both application roles could call it.
--   3. It trusted its argument. `SELECT audit.cleanup_old_entries(interval '0
--      seconds')` deletes every row whose timestamp is in the past, i.e. the
--      whole log; a negative interval does the same. vault_app is refused a
--      direct DELETE with 42501 and then wipes the table through this function.
--      That is the append-only invariant, gone.
--
-- The Go side already refuses a non-positive window (`vault cleanup-audit`
-- validates --retention-days, and the sweeper is disabled unless
-- VAULT_AUDIT_RETENTION_DAYS is set), but nothing enforced it where it matters.
-- The horizon is configured in whole days, so the function now requires at least
-- one: a caller that reaches the database through SQL injection can no longer
-- destroy the record of what it is doing.
--
-- EXECUTE goes to vault_app alone, because the retention sweeper runs in-process in
-- cmd/vault under that role, and `vault cleanup-audit` uses the same pool. The
-- admin gateway never purges; it only reads and appends. The residual risk (a
-- compromised vault_app can still purge past the horizon) is AR-12 in
-- docs/security.md.
--
-- The function is also given an explicit search_path. Without one it resolved
-- unqualified names through the caller's search_path while running as the
-- definer, which is CVE-2018-1058. It is the only SECURITY DEFINER function in
-- the schema; audit.deny_modify, objects.deny_update and
-- auth.deny_role_escalation are all SECURITY INVOKER.
-- ============================================================================

CREATE OR REPLACE FUNCTION audit.cleanup_old_entries(retention_interval INTERVAL)
RETURNS BIGINT AS $$
DECLARE deleted BIGINT;
BEGIN
    IF retention_interval IS NULL OR retention_interval < INTERVAL '1 day' THEN
        RAISE EXCEPTION 'audit retention horizon must be at least 1 day, got %', retention_interval
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_no_delete;
    DELETE FROM audit.audit_log WHERE timestamp < NOW() - retention_interval;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

REVOKE ALL ON FUNCTION audit.cleanup_old_entries(INTERVAL) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.cleanup_old_entries(INTERVAL) TO vault_app;

-- ============================================================================
-- Part 2: grants the admin gateway has always been missing
--
-- cmd/admin-gateway connects as vault_admin. Every table added after 001 has to
-- be granted to it explicitly, and four endpoints were shipped against tables it
-- had no privilege on. The integration suite cannot see this: it connects as the
-- container owner and stripRoleGrants() removes every GRANT/REVOKE before the
-- migrations are applied, so the privilege model is never exercised. Each of the
-- failures below was reproduced against a real PostgreSQL 16 with the migrations
-- applied verbatim and a session authenticated as vault_admin.
-- ============================================================================

-- auth.app_roles (005) granted SELECT to vault_app and nothing to vault_admin,
-- yet main.go wires NewAppRoleRepo onto the vault_admin pool. GET, POST and
-- DELETE /admin/roles all failed with 42501 -> 500.
GRANT SELECT, INSERT, DELETE ON auth.app_roles TO vault_admin;

-- POST /admin/users/import runs UserRepo.CreateImported, an INSERT into
-- auth.users. vault_admin held SELECT and column-level UPDATE only.
GRANT INSERT ON auth.users TO vault_admin;

-- DELETE /admin/config/{key} runs AdminConfigRepo.Delete. 001 grants
-- SELECT, INSERT, UPDATE to vault_admin under a comment reserving DELETE for the
-- admin gateway, and then never grants it.
GRANT DELETE ON auth.admin_config TO vault_admin;

-- The erasure cascade behind DELETE /admin/users/{id}. 009 granted DELETE on
-- these five tables, which is not sufficient: PostgreSQL also requires SELECT on
-- every column read by the WHERE clause, and each repository issues
-- `DELETE FROM ... WHERE user_id = $1`. vault_admin has table-level SELECT on
-- auth.devices and auth.refresh_tokens from 001, so those two worked and the
-- rest returned 42501, after the account had already been tombstoned, leaving a
-- half-erased user. Column-level so the admin role still cannot read the
-- encrypted TOTP secret, the WebAuthn public keys, the backup-code hashes or the
-- password history it is allowed to delete.
GRANT SELECT (user_id) ON auth.social_accounts TO vault_admin;
GRANT SELECT (user_id) ON auth.password_history TO vault_admin;
GRANT SELECT (user_id) ON auth.totp_secrets TO vault_admin;
GRANT SELECT (user_id) ON auth.webauthn_credentials TO vault_admin;
GRANT SELECT (user_id) ON auth.backup_codes TO vault_admin;
