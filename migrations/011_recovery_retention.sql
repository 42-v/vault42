-- ============================================================================
-- 011: retention horizon for the account-recovery escrow
-- ============================================================================
--
-- auth.account_recovery (migration 007) is written on every account erasure and
-- holds an RSA-encrypted copy of the erased user's email, creation date, roles
-- and display name. The table shipped append-only and unbounded: UPDATE and
-- DELETE are blocked by triggers, both application roles have those privileges
-- revoked, and nothing anywhere removed a row. An escrow record written on the
-- day a deployment went live was still there years later, and no supported path
-- existed to remove it.
--
-- That is the same shape as the audit log, which is likewise exempt from the
-- erasure cascade and is therefore bounded by time instead (Art. 5(1)(e)): a
-- retention horizon plus a sweeper. This migration gives the escrow the same
-- mechanism, modelled on audit.cleanup_old_entries() in migration 001.
--
-- The function is SECURITY DEFINER because the delete has to pass the
-- append-only trigger it temporarily disables, and the trigger is exactly what
-- the application roles must not be able to work around directly. Removal stays
-- a single, named, auditable operation rather than a DELETE privilege handed to
-- vault_app.
--
-- Nothing here deletes anything on its own. VAULT_RECOVERY_RETENTION_DAYS is
-- unset (disabled) by default and `vault cleanup-recovery` must be run
-- explicitly, exactly as for the audit log: silently destroying the only
-- recoverable copy of an erased account is not a safe default.

CREATE OR REPLACE FUNCTION auth.cleanup_old_recovery(retention_interval INTERVAL)
RETURNS BIGINT AS $$
DECLARE deleted BIGINT;
BEGIN
    ALTER TABLE auth.account_recovery DISABLE TRIGGER account_recovery_no_delete;
    DELETE FROM auth.account_recovery WHERE deleted_at < NOW() - retention_interval;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE auth.account_recovery ENABLE TRIGGER account_recovery_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
