-- ============================================================================
-- Migration 018: the audit retention guard must validate the value it uses
--
-- audit.cleanup_old_entries is the only path that can delete an audit row. The
-- audit_log_no_delete trigger blocks every other one, and this function is
-- SECURITY DEFINER precisely so it can turn that trigger off for the length of
-- one DELETE. Its minimum-horizon check is therefore not a usability guard. It
-- is the only limit on how much of the audit log a single call can destroy, and
-- vault_app holds EXECUTE on it.
--
-- Migration 012 wrote that check against the wrong value:
--
--     IF retention_interval < INTERVAL '1 day' THEN RAISE
--     DELETE ... WHERE timestamp < NOW() - retention_interval
--
-- Comparing two intervals and subtracting an interval from a timestamp are
-- different operations in Postgres. Comparison canonicalizes a month to 30 days
-- so that intervals are totally ordered without a reference date. Subtraction
-- has a reference date, so it uses the real calendar month. For any interval
-- carrying a month component the two disagree, and a caller chooses the
-- disagreement by mixing units.
--
-- INTERVAL '1 mon -29 days' compares as 30 - 29 = 1 day and passes. Evaluated in
-- February it subtracts to NOW() - 28 days + 29 days, one day in the FUTURE, so
-- the DELETE takes every row in the table including the ones written by the
-- intrusion that made the call. The guard reports the horizon was respected.
--
-- Neither Go caller can reach this. AuditRepo.Cleanup and CleanupLocked both
-- build the argument as fmt.Sprintf("%d seconds", ...) from a time.Duration, and
-- a seconds-only interval has no month component, so for them the two operations
-- agree exactly. That is what makes this worth fixing rather than urgent: the
-- exposure is a compromised vault_app calling the function directly, which is
-- the same threat model migrations 002, 015, 016 and 017 are written against.
--
-- The fix is structural rather than a corrected constant. The cutoff is computed
-- once into a variable, the guard tests that variable, and the DELETE uses the
-- same variable, so the validated value and the applied value cannot drift apart
-- again. A guard that recomputes what it checks is one edit away from checking
-- something else.
--
-- NOW() is the transaction timestamp in plpgsql, so it is stable across both
-- references within a single call.
--
-- The NULL check stays separate and first. NOW() - NULL is NULL and NULL > x is
-- NULL rather than true, so folding NULL into the cutoff comparison would let a
-- NULL argument through to a DELETE with a NULL predicate.
-- ============================================================================

CREATE OR REPLACE FUNCTION audit.cleanup_old_entries(retention_interval INTERVAL)
RETURNS BIGINT AS $$
DECLARE
    deleted BIGINT;
    cutoff  TIMESTAMPTZ;
BEGIN
    IF retention_interval IS NULL THEN
        RAISE EXCEPTION 'audit retention horizon must not be NULL'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    cutoff := NOW() - retention_interval;

    IF cutoff > NOW() - INTERVAL '1 day' THEN
        RAISE EXCEPTION 'audit retention horizon must be at least 1 day, got % (cutoff %)',
            retention_interval, cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_no_delete;
    DELETE FROM audit.audit_log WHERE timestamp < cutoff;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Unchanged from 012 and restated because CREATE OR REPLACE keeps the existing
-- ACL: stated here so the grant is readable in one place rather than inferred
-- from the absence of a change.
REVOKE ALL ON FUNCTION audit.cleanup_old_entries(INTERVAL) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.cleanup_old_entries(INTERVAL) TO vault_app;
