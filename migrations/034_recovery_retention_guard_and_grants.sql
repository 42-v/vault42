-- ============================================================================
-- 034: the account-recovery purge gets the three properties its twin already has
-- ============================================================================
--
-- auth.cleanup_old_recovery (011) is the only path that can delete an escrow
-- row. auth.account_recovery is append-only: 007 blocks DELETE and UPDATE with
-- BEFORE ROW triggers and grants neither application role DELETE, and this
-- function is SECURITY DEFINER precisely so it can turn the DELETE trigger off
-- for the length of one statement. Its definer owns the table.
--
-- 012 and 018 identified three defects in exactly that shape and fixed them in
-- audit.cleanup_old_entries. 011 shipped the same day and was left as written,
-- so the escrow — which 007 introduced to survive "an accidental or malicious
-- deletion", and which is the only recoverable copy of an erased account — was
-- destroyable in one call by the role the erasure runs as. All three were
-- reproduced against PostgreSQL 16.15 with every migration applied verbatim, as
-- vault_app, and each is independently sufficient to take the whole table:
--
--   1. Nothing revoked EXECUTE. PostgreSQL grants EXECUTE on a function to
--      PUBLIC by default, so every role in the cluster held the purge.
--
--        SELECT auth.cleanup_old_recovery(INTERVAL '0 seconds');  -> 3 of 3 rows
--
--   2. The argument was trusted. A zero horizon deletes every row whose
--      deleted_at is in the past, which is all of them; a negative horizon puts
--      the cutoff in the future and takes the rest. The twin refuses the
--      identical call.
--
--   3. No search_path. The body says NOW() unqualified while running as the
--      definer, so a caller that names pg_catalog late in its own search_path
--      chooses which now() the function executes (CVE-2018-1058), and with it
--      which side of the horizon the DELETE lands on. Reproduced: a decoy now()
--      returning 2999 made a legitimate 365-day sweep destroy escrow written an
--      hour earlier, with the minimum-horizon guard satisfied.
--
-- The fix is 018's, applied to the twin it was never applied to.
--
-- The cutoff is computed once into a variable, the guard tests that variable,
-- and the DELETE uses the same variable. This is not stylistic. Comparing two
-- intervals canonicalizes a month to 30 days because intervals must be ordered
-- without a reference date, while subtracting an interval from a timestamp uses
-- the real calendar month, so a guard written as `retention_interval < INTERVAL
-- '1 day'` checks something the DELETE does not apply and INTERVAL '1 mon -29
-- days' walks through it. tests/spec/retention_guard_test.go gates that shape
-- across every migration, including ones not yet written.
--
-- The NULL check stays separate and first: NOW() - NULL is NULL, and NULL > x is
-- NULL rather than true, so folding NULL into the cutoff comparison would let a
-- NULL argument reach a DELETE with a NULL predicate.
--
-- EXECUTE goes to vault_app and to nobody else. Both callers run under it:
-- AccountRecoveryRepo.PruneLocked is the in-process sweeper in cmd/vault and
-- AccountRecoveryRepo.Prune is `vault cleanup-recovery`, and both sit on the
-- vault pool. cmd/admin-gateway builds an AccountRecoveryRepo to append escrow
-- rows during erasure and calls neither, so vault_admin needs nothing here.
--
-- Both Go callers render the horizon with fmt.Sprintf("%d seconds", ...) from a
-- time.Duration and `vault cleanup-recovery` already refuses --retention-days
-- below 1, so no product path meets any of this. That is what makes it worth
-- fixing rather than urgent: the exposure is a caller that never goes through
-- Go, which is the threat model 002, 012, 015, 016, 017, 023, 024 and 025 are
-- each written against.
--
-- Residual, and the same one AR-12 records for the audit log: a compromised
-- vault_app can still purge escrow older than one day. The floor bounds the
-- blast radius of a single call; it does not remove the capability, which the
-- sweeper needs to exist at all.
--
-- Locks. CREATE OR REPLACE FUNCTION, REVOKE and GRANT touch catalog rows only.
-- Nothing here locks auth.account_recovery, reads it, or rewrites a row, so this
-- migration is safe on a live deployment of any size.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.cleanup_old_recovery(retention_interval INTERVAL)
RETURNS BIGINT AS $$
DECLARE
    deleted BIGINT;
    cutoff  TIMESTAMPTZ;
BEGIN
    IF retention_interval IS NULL THEN
        RAISE EXCEPTION 'recovery retention horizon must not be NULL'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    cutoff := NOW() - retention_interval;

    IF cutoff > NOW() - INTERVAL '1 day' THEN
        RAISE EXCEPTION 'recovery retention horizon must be at least 1 day, got % (cutoff %)',
            retention_interval, cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    ALTER TABLE auth.account_recovery DISABLE TRIGGER account_recovery_no_delete;
    DELETE FROM auth.account_recovery WHERE deleted_at < cutoff;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE auth.account_recovery ENABLE TRIGGER account_recovery_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Bare and unindented, per tests/spec/grant_line_shape_test.go: the integration
-- fixture strips grants only at column zero and leaves the tail of a wrapped one
-- behind as a syntax error.
REVOKE ALL ON FUNCTION auth.cleanup_old_recovery(INTERVAL) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.cleanup_old_recovery(INTERVAL) TO vault_app;
