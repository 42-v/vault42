-- ============================================================================
-- Migration 032: the audit retention purge has to be able to run in batches
--
-- audit.cleanup_old_entries is the only path that can delete an audit row: the
-- audit_log_no_delete trigger blocks every other one, and this function is
-- SECURITY DEFINER precisely so it can turn that trigger off for the length of
-- one DELETE. Disabling a trigger is ALTER TABLE, which takes ACCESS EXCLUSIVE
-- on audit.audit_log, and the single-argument form holds it for one unbounded
-- DELETE over every row past the horizon.
--
-- That matters because of what else writes to this table. A failed login is a
-- critical event, so it is written synchronously even when the 1000-entry
-- buffer is full, and a login flood therefore inserts one row per attempt on
-- the request path. Against a table that has been accumulating for the length
-- of a retention horizon, a single unbatched purge holds the exclusive lock for
-- as long as that DELETE takes and every one of those inserts waits behind it.
--
-- The two-argument form deletes at most max_rows and reports how many went, so
-- the caller can loop. Each call is its own transaction, so the exclusive lock
-- is taken and released once per batch: an insert arriving mid-purge waits for
-- one batch rather than for the whole horizon. The horizon guard, the NULL
-- check and the cutoff-computed-once structure are unchanged from migration
-- 018 and are restated here rather than shared, because a guard that lives in
-- a different function from the DELETE it protects is one edit away from
-- protecting nothing.
--
-- ctid rather than a primary key: the LIMIT needs an ordering the planner can
-- satisfy without sorting the whole horizon, and physical order is both cheap
-- and irrelevant to correctness — every row in the subquery is past the cutoff,
-- so any max_rows of them are equally eligible.
--
-- The single-argument form is left exactly as migration 018 wrote it. The CLI
-- and AuditRepo.Cleanup still call it, and an operator running a one-off purge
-- against a table nobody is inserting into has no reason to pay for batching.
-- ============================================================================

CREATE OR REPLACE FUNCTION audit.cleanup_old_entries(retention_interval INTERVAL, max_rows INTEGER)
RETURNS BIGINT AS $$
DECLARE
    deleted BIGINT;
    cutoff  TIMESTAMPTZ;
BEGIN
    IF retention_interval IS NULL THEN
        RAISE EXCEPTION 'audit retention horizon must not be NULL'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF max_rows IS NULL OR max_rows < 1 THEN
        RAISE EXCEPTION 'audit retention batch size must be a positive integer, got %', max_rows
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    cutoff := NOW() - retention_interval;

    IF cutoff > NOW() - INTERVAL '1 day' THEN
        RAISE EXCEPTION 'audit retention horizon must be at least 1 day, got % (cutoff %)',
            retention_interval, cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_no_delete;
    DELETE FROM audit.audit_log
     WHERE ctid IN (
        SELECT ctid FROM audit.audit_log WHERE timestamp < cutoff LIMIT max_rows
     );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Same ACL as the single-argument form: PUBLIC has no business deleting audit
-- rows, and vault_app is the role the sweeper runs as.
REVOKE ALL ON FUNCTION audit.cleanup_old_entries(INTERVAL, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.cleanup_old_entries(INTERVAL, INTEGER) TO vault_app;
