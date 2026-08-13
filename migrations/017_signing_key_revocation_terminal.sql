-- ============================================================================
-- 017: revocation of a signing key is terminal in the database, not just in Go
-- ============================================================================
--
-- A signing key is revoked for exactly one reason: its private material leaked.
-- keystore.Revoke sets status = 'revoked', Refresh's WHERE drops the row from
-- the verification set, and Import refuses to reactivate it. That last guard is
-- the only thing standing between a leaked key and a working token, and it is a
-- WHERE clause inside one application statement:
--
--   ON CONFLICT (kid) DO UPDATE SET ... WHERE signing_keys.status != 'revoked'
--
-- Raw SQL never runs it. 001 line 354 grants vault_app SELECT, INSERT and UPDATE
-- on auth.signing_keys, so a statement reaching the database as the vault's own
-- role puts a leaked key back into JWKS with one UPDATE:
--
--   UPDATE auth.signing_keys SET status = 'retired', expires_at = NULL
--    WHERE kid = '<revoked-leaked-kid>';
--
-- expires_at NULL means never expires, so within one VAULT_KEY_REFRESH_INTERVAL
-- every pod is verifying with the leaked key again, and so is every service
-- polling this issuer.
--
-- This is the half that the application-side fix in the same change cannot
-- reach. That fix refuses to publish any row whose private_key does not decrypt
-- under the master key with kid as AAD, which stops a forged key from being
-- injected. It does nothing here: the row being resurrected is the vault's own,
-- its ciphertext is genuine, and it decrypts. Terminality is a state rule about
-- a row, so it belongs to the database.
--
-- The rule below is wider than "cannot leave revoked", for two reasons.
--
--   * A revoked row is frozen entirely. Renaming its kid frees that identifier
--     for a fresh INSERT, and the attacker already read the ciphertext out of
--     the row, so the resurrected key would decrypt and publish cleanly. Editing
--     public_key or expires_at while leaving status alone changes nothing that
--     is published, so freezing the whole row costs no legitimate operation:
--     Revoke updates only rows whose status is not yet 'revoked', Import's
--     upsert excludes revoked rows in its WHERE, and CleanupExpired deletes only
--     retired ones.
--
--   * DELETE is refused too. The row is the tombstone: while it exists the kid
--     is taken and cannot be re-inserted. Neither vault_app nor vault_admin is
--     granted DELETE on this table today ("no DELETE -- revoke only", 001), so
--     this guards against a future grant rather than a present hole, and the
--     cost is that revoked rows accumulate. They are a few hundred bytes each
--     and one per leak.
--
-- What this does NOT do, in the same spirit as 016 and AR-14. It is not a
-- boundary against SQL running as the table's owner or a superuser: ALTER TABLE
-- ... DISABLE TRIGGER, session_replication_role = replica and TRUNCATE all
-- bypass row triggers, and the migration role holds them. It closes the path
-- available to the two least-privilege roles the services actually connect as,
-- which is the threat model 001 states for auth.signing_keys.
--
-- No audit row is written here, unlike auth.deny_role_escalation. The RAISE
-- aborts the transaction and takes any INSERT made inside it down with it, which
-- is why that trigger's audit row does not survive either: on PostgreSQL 16 a
-- blocked promotion leaves audit.audit_log exactly as it found it. The record of
-- an attempt is the exception, in the PostgreSQL log.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.deny_revoked_signing_key_change() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'signing key revocation is terminal: % cannot be deleted', OLD.kid;
    END IF;
    RAISE EXCEPTION 'signing key revocation is terminal: % cannot be modified (status % -> %)', OLD.kid, OLD.status, NEW.status;
END;
$$ LANGUAGE plpgsql;

-- The WHEN clause carries the whole condition, so every write to a row that is
-- not revoked reaches the table without entering plpgsql at all.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs
-- on any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS signing_keys_revocation_terminal ON auth.signing_keys;
CREATE TRIGGER signing_keys_revocation_terminal
    BEFORE UPDATE OR DELETE ON auth.signing_keys
    FOR EACH ROW WHEN (OLD.status = 'revoked')
    EXECUTE FUNCTION auth.deny_revoked_signing_key_change();
