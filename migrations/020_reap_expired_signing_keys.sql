-- ============================================================================
-- 020: let the vault reap its own expired signing keys, and bound what that
--      privilege can reach
-- ============================================================================
--
-- keystore.CleanupExpired has existed since the DB-backed keystore shipped:
--
--   DELETE FROM auth.signing_keys
--    WHERE status = 'retired' AND expires_at IS NOT NULL AND expires_at < NOW()
--
-- Its comment says it is "called periodically during refresh to prevent table
-- bloat". Nothing called it. The refresh loop only refreshes, no handler reaches
-- it, no CLI subcommand runs it, and its only callers in the whole tree were
-- tests. So auth.signing_keys grew by one row per rotation and never shrank.
--
-- The other half is here. 001 grants vault_app SELECT, INSERT and UPDATE on this
-- table and comments the omission ("no DELETE -- revoke only"), so the sweep
-- could not have removed a row even once something called it: it would have
-- failed with 42501 on every attempt. Two defects that each hide the other, which
-- is why neither showed up as a broken deployment.
--
-- What accumulates is not just rows. Every retired row carries the AES-256-GCM
-- ciphertext of a private signing key that stopped verifying anything at its
-- expires_at. Keeping decommissioned key material indefinitely, under a master
-- key that itself has to be rotatable one day, is the part that makes this worth
-- a migration rather than a VACUUM.
--
-- vault_app gets the privilege, not vault_admin. The sweep is a background loop
-- on a 6-hour interval, and vault_app is the role that runs continuously and
-- already owns the audit and account-recovery retention sweeps in the same
-- process. vault_admin is the admin plane: it rotates and revokes on an
-- operator's command and its gateway need not be deployed at all, so a reap
-- privilege there would be one nothing uses, attached to the role with the wider
-- reach over admin tables. The REVOKE below states that rather than leaving it to
-- be inferred from an absence.
--
-- ----------------------------------------------------------------------------
-- Why a grant alone is not the boundary
-- ----------------------------------------------------------------------------
--
-- PostgreSQL has no row scope for a privilege, and unlike UPDATE, DELETE takes no
-- column list. GRANT DELETE on this table is therefore every row in it, and the
-- rows the sweep must not touch are the ones that matter most:
--
--   * The ACTIVE key. Its row holds the only copy of the private material that
--     exists anywhere; the process has it in memory and nothing else does. One
--     DELETE and no pod can ever load it again.
--
--   * A RETIRED key still inside its retention window. Refresh publishes it and
--     tokens signed under it are still verifying. Deleting it early breaks live
--     tokens at every service polling this issuer, not just here.
--
--   * A REVOKED key. 017 already refuses this and explains why at length: the row
--     is the tombstone, and while it exists the kid is taken and cannot be
--     re-inserted by an attacker who read its ciphertext.
--
-- 017 wrote itself against exactly this migration. Its header notes that no role
-- holds DELETE today, "so this guards against a future grant rather than a
-- present hole". This is that future grant. Nothing here touches 017's trigger or
-- its function, and the exclusion in the WHEN clause below keeps this migration
-- from having any opinion at all about a revoked row.
--
-- The trigger is what narrows the privilege to the sweep's own predicate, so the
-- reachable set is "retired and past expires_at" rather than "the table". Those
-- are the rows Refresh has already stopped loading, which makes the two sets
-- exactly complementary: Refresh publishes `expires_at IS NULL OR expires_at >
-- NOW()`, this permits `status = 'retired' AND expires_at < NOW()`, and no row
-- satisfies both. A reap can therefore never remove a key that is still in a
-- published JWKS. The row and its key leave the verification set at expires_at
-- and are deleted at some point after that, in that order, always.
--
-- ----------------------------------------------------------------------------
-- Why a trigger and not a SECURITY DEFINER function
-- ----------------------------------------------------------------------------
--
-- audit.cleanup_old_entries (001) and auth.cleanup_old_recovery (011) are the
-- house pattern for a bounded delete, and both are SECURITY DEFINER for one
-- reason: they must disable an append-only trigger to do their work, which is
-- precisely what the application role must not be able to do directly.
--
-- That reason inverts here. This delete must NOT bypass a trigger. 017's freeze
-- has to keep firing on every DELETE that reaches a revoked row, and wrapping the
-- sweep in a definer-rights function would put the whole table behind the
-- migration role, one predicate edit away from a delete with owner privileges.
-- Leaving the sweep as an ordinary statement by vault_app keeps both triggers in
-- the path and keeps the predicate in reviewed Go rather than in a function body
-- that reads as trusted.
--
-- The same limits as 016, 017 and AR-14 apply and are not papered over. ALTER
-- TABLE ... DISABLE TRIGGER, session_replication_role = replica and TRUNCATE all
-- bypass row triggers, and the migration role holds them. This closes the path
-- available to the two least-privilege roles the services connect as, which is
-- the threat model 001 states for auth.signing_keys.
-- ============================================================================

GRANT DELETE ON auth.signing_keys TO vault_app;
REVOKE DELETE ON auth.signing_keys FROM vault_admin;

CREATE OR REPLACE FUNCTION auth.deny_unreapable_signing_key_delete() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'signing key % is not reapable: only a retired key past its expiry may be deleted (status %, expires_at %)',
        OLD.kid, OLD.status, OLD.expires_at;
END;
$$ LANGUAGE plpgsql;

-- The WHEN clause carries the whole condition, so a delete of a reapable row
-- never enters plpgsql: the sweep pays nothing for this guard.
--
-- Revoked rows are excluded deliberately. Same-event triggers fire in name order,
-- and 'signing_keys_reap_scope' sorts ahead of 'signing_keys_revocation_terminal',
-- so without the exclusion this trigger would answer first on a revoked row and
-- report a reap-scope violation where the true reason is that revocation is
-- terminal. Excluding them makes the ordering irrelevant rather than merely
-- lucky, and leaves 017 the only guard that speaks for a revoked key.
--
-- NOW() is transaction time, and the sweep's own predicate reads it in the same
-- transaction, so the row the DELETE selected and the row this clause judges are
-- compared against the same instant. The two cannot disagree.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS signing_keys_reap_scope ON auth.signing_keys;
CREATE TRIGGER signing_keys_reap_scope
    BEFORE DELETE ON auth.signing_keys
    FOR EACH ROW WHEN (OLD.status <> 'revoked' AND (OLD.status <> 'retired' OR OLD.expires_at IS NULL OR OLD.expires_at >= NOW()))
    EXECUTE FUNCTION auth.deny_unreapable_signing_key_delete();
