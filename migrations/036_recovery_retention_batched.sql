-- ============================================================================
-- Migration 036: the escrow purge has to be able to run in batches
-- ============================================================================
--
-- 032 gave audit.cleanup_old_entries a batched form and said why. 034 gave
-- auth.cleanup_old_recovery the other three properties 018 had established and
-- did not carry the batching across, so the escrow purge still does
--
--   ALTER TABLE auth.account_recovery DISABLE TRIGGER account_recovery_no_delete;
--   DELETE FROM auth.account_recovery WHERE deleted_at < cutoff;
--
-- which is the exact pattern 032 exists to remove, on the scheduled path:
-- AccountRecoveryRepo.PruneLocked is what the in-process sweeper calls every six
-- hours.
--
-- Disabling a trigger is ALTER TABLE, which takes ACCESS EXCLUSIVE on
-- auth.account_recovery. The single-argument form holds it for one unbounded
-- DELETE over every row past the horizon, and everything that writes to this
-- table waits behind it. What writes to it is the erasure path: every Art. 17
-- deletion with a recovery key configured appends the encrypted escrow record
-- before the account goes. So on a deployment that has been accumulating escrow
-- for the length of a retention horizon, one purge stalls erasures for as long
-- as the DELETE takes.
--
-- The advisory lock in PruneLocked (4243) keeps replicas from piling up on that
-- lock. It does nothing about how long one replica holds it.
--
-- The two-argument form deletes at most max_rows and reports how many went, so
-- the caller loops. Each call is its own transaction, so the exclusive lock is
-- taken and released once per batch: an erasure arriving mid-purge waits for one
-- batch rather than for the whole horizon.
--
-- ctid rather than the primary key, as in 032: the LIMIT needs an ordering the
-- planner can satisfy without sorting the whole horizon, and physical order is
-- irrelevant to correctness here -- every row in the subquery is already past
-- the cutoff, so any max_rows of them are equally eligible.
--
-- The NULL check, the cutoff-computed-once structure and the one-day floor are
-- 034's, restated rather than shared, for the reason 032 gives: a guard that
-- lives in a different function from the DELETE it protects is one edit away
-- from protecting nothing. tests/spec/retention_guard_test.go gates the shape.
--
-- The single-argument form is left exactly as 034 wrote it. `vault
-- cleanup-recovery` still calls it, and an operator running a one-off purge
-- against a table nobody is erasing into has no reason to pay for batching. As
-- with 032, changing the arity means CREATE OR REPLACE leaves both overloads
-- present, which is also what lets a rolled-back binary keep working.
--
-- Locks: CREATE OR REPLACE FUNCTION, REVOKE and GRANT touch catalog rows only.
-- Nothing here locks auth.account_recovery, reads it or rewrites a row, so this
-- migration is safe on a live deployment of any size.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.cleanup_old_recovery(retention_interval INTERVAL, max_rows INTEGER)
RETURNS BIGINT AS $$
DECLARE
    deleted BIGINT;
    cutoff  TIMESTAMPTZ;
BEGIN
    IF retention_interval IS NULL THEN
        RAISE EXCEPTION 'recovery retention horizon must not be NULL'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF max_rows IS NULL OR max_rows < 1 THEN
        RAISE EXCEPTION 'recovery retention batch size must be a positive integer, got %', max_rows
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    cutoff := NOW() - retention_interval;

    IF cutoff > NOW() - INTERVAL '1 day' THEN
        RAISE EXCEPTION 'recovery retention horizon must be at least 1 day, got % (cutoff %)',
            retention_interval, cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    ALTER TABLE auth.account_recovery DISABLE TRIGGER account_recovery_no_delete;
    DELETE FROM auth.account_recovery
     WHERE ctid IN (
        SELECT ctid FROM auth.account_recovery WHERE deleted_at < cutoff LIMIT max_rows
     );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE auth.account_recovery ENABLE TRIGGER account_recovery_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Same ACL as the single-argument form: PUBLIC has no business deleting the only
-- recoverable copy of an erased account, and vault_app is the role the sweeper
-- runs as. Bare and unindented, per tests/spec/grant_line_shape_test.go.
REVOKE ALL ON FUNCTION auth.cleanup_old_recovery(INTERVAL, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.cleanup_old_recovery(INTERVAL, INTEGER) TO vault_app;
