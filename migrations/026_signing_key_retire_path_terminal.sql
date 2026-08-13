-- ============================================================================
-- 026: a rotated-out signing key cannot return to the verification set, and a
--      reaped kid can never be written again
-- ============================================================================
--
-- 017 froze revoked rows and 020 gave vault_app the reaper's DELETE, bounded to
-- retired keys past their expiry. Between them they leave one lifecycle state
-- unguarded for the two least-privilege roles: the retired row. 001 grants
-- vault_app SELECT, INSERT and UPDATE on auth.signing_keys and 020 adds DELETE,
-- so a statement reaching the database as the vault's own role can still do two
-- things to a key that has been rotated out of service, both of which put its
-- material back where relying parties trust it. Call the pair B2.
--
-- B2a, republish by UPDATE. A retired row is genuine: its private_key decrypts
-- under the master key with kid as AAD and its public_key is the matching half,
-- so the application-side Refresh guard (publish only what opens and matches)
-- waves it through. 017's trigger fires only WHEN OLD.status = 'revoked', so it
-- never sees a retired row. That leaves both of these open to vault_app:
--
--     UPDATE auth.signing_keys SET expires_at = NULL WHERE kid = '<retired-kid>';
--     UPDATE auth.signing_keys SET status = 'active'  WHERE kid = '<retired-kid>';
--
-- Refresh publishes `expires_at IS NULL OR expires_at > NOW()`, so clearing or
-- extending expires_at drags a key that had already left JWKS back into it, and
-- keeps it there. Flipping status to 'active' hands the signer a kid operators
-- believe is dead. Whoever controls a published JWKS key signs any subject, here
-- and in every service polling this issuer.
--
-- B2b, reap-then-reinsert. 020's DELETE lets vault_app remove a retired, expired
-- row, which is the sweep's whole job. But a DELETE frees the kid, and while the
-- row existed the kid was the one thing keeping that identifier from being
-- written afresh. 017 leans on a revoked row surviving as its own tombstone; a
-- reaped row leaves no tombstone at all. So vault_app can reap a kid and then
-- re-INSERT it under material of its choosing, which is the resurrection 017
-- blocks for revoked keys reached one DELETE earlier.
--
-- ----------------------------------------------------------------------------
-- The fix, in two parts, each narrow enough to cost no legitimate write
-- ----------------------------------------------------------------------------
--
-- Part 1, a retire-path guard, closes B2a. On a retired row only, it refuses:
--
--   * clearing expires_at to NULL, or moving it later, while the row is not being
--     re-imported. keystore.Import re-encrypts and re-activates a key with fresh
--     ciphertext and sets status = 'active'; that path is left alone. Every other
--     write that lengthens a retired key's life is refused. Shrinking expires_at
--     stays allowed, which is the back-date the reap test and a manual early
--     expiry both depend on.
--   * moving status to 'active' without new key material. Genuine re-import
--     always supplies a freshly encrypted private_key, so NEW.private_key differs
--     from OLD.private_key on every real reactivation. A bare SET status =
--     'active' leaves private_key untouched, which is exactly what this refuses.
--   * retired -> revoked is untouched, so Revoke still works on a retired key.
--
-- Part 2, a persistent kid tombstone, closes B2b. Every DELETE records the kid in
-- auth.signing_key_tombstones through a SECURITY DEFINER trigger, and every
-- INSERT is refused when its kid is already tombstoned. The reaper's legitimate
-- DELETE is unchanged; what changes is that the kid it frees can never be filled
-- again. A kid is a hash of the public key, so a genuine key never lands on a
-- tombstoned kid: only an attacker reusing an identifier does. vault_app holds no
-- privilege on the tombstone table, so it cannot erase an entry to undo this, and
-- the row that records the reap is written under the migration role's rights.
--
-- ----------------------------------------------------------------------------
-- Trigger ordering
-- ----------------------------------------------------------------------------
--
-- Same-event triggers fire in name order. On BEFORE UPDATE this migration adds
-- signing_keys_retire_path_terminal, which sorts between 020's
-- signing_keys_reap_scope (DELETE only, so never a BEFORE UPDATE peer) and 017's
-- signing_keys_revocation_terminal. Its WHEN clause fires only on
-- OLD.status = 'retired' and 017's only on OLD.status = 'revoked', so the two
-- never judge the same row and their order is moot rather than merely lucky. On
-- BEFORE INSERT only signing_keys_tombstone_guard exists; on AFTER DELETE only
-- signing_keys_tombstone_record. AFTER fires after BEFORE, so a kid is tombstoned
-- only once 017 and 020 have allowed its DELETE: a refused delete records nothing.
--
-- The same limits as 016, 017, 020, 023 and 024 apply and are not papered over.
-- ALTER TABLE ... DISABLE TRIGGER, session_replication_role = replica and
-- TRUNCATE all bypass row triggers, and the migration role holds them. This
-- closes the path available to the two least-privilege roles the services connect
-- as, which is the threat model 001 states for auth.signing_keys.
-- ============================================================================

-- Part 1: retire-path guard --------------------------------------------------

CREATE OR REPLACE FUNCTION auth.deny_retired_signing_key_republish() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'active' THEN
        RAISE EXCEPTION 'signing key % cannot return to active without new key material: a rotated-out key stays retired', OLD.kid;
    END IF;
    RAISE EXCEPTION 'signing key % is retired: its expiry cannot be cleared or extended (expires_at % -> %)', OLD.kid, OLD.expires_at, NEW.expires_at;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the whole condition, so every ordinary write to a
-- retired row (a Revoke, an early expiry, a genuine re-import) reaches the table
-- without entering plpgsql. private_key is BYTEA NOT NULL, so the reactivation
-- comparison never meets a NULL; expires_at may be NULL, which the clause handles
-- explicitly.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS signing_keys_retire_path_terminal ON auth.signing_keys;
CREATE TRIGGER signing_keys_retire_path_terminal
    BEFORE UPDATE ON auth.signing_keys
    FOR EACH ROW WHEN (
        OLD.status = 'retired' AND (
            (NEW.status = 'active' AND NEW.private_key = OLD.private_key)
            OR (NEW.status <> 'active' AND NEW.status <> 'revoked'
                AND OLD.expires_at IS NOT NULL
                AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at))
        )
    )
    EXECUTE FUNCTION auth.deny_retired_signing_key_republish();

-- Part 2: persistent kid tombstone -------------------------------------------

CREATE TABLE IF NOT EXISTS auth.signing_key_tombstones (
    kid           TEXT PRIMARY KEY,
    last_status   TEXT NOT NULL,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No grant to vault_app or vault_admin. The record trigger writes this table with
-- the migration role's rights (SECURITY DEFINER), and nothing the services
-- connect as may read, alter or erase a tombstone. The REVOKE is defensive: a
-- fresh table grants no access to non-owners by default, and this states it.
REVOKE ALL ON auth.signing_key_tombstones FROM PUBLIC;

CREATE OR REPLACE FUNCTION auth.record_signing_key_tombstone() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO auth.signing_key_tombstones (kid, last_status)
    VALUES (OLD.kid, OLD.status)
    ON CONFLICT (kid) DO NOTHING;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION auth.deny_tombstoned_signing_kid_insert() RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM auth.signing_key_tombstones WHERE kid = NEW.kid) THEN
        RAISE EXCEPTION 'signing key kid % is tombstoned: a reaped kid can never be re-inserted', NEW.kid;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

DROP TRIGGER IF EXISTS signing_keys_tombstone_record ON auth.signing_keys;
CREATE TRIGGER signing_keys_tombstone_record
    AFTER DELETE ON auth.signing_keys
    FOR EACH ROW
    EXECUTE FUNCTION auth.record_signing_key_tombstone();

DROP TRIGGER IF EXISTS signing_keys_tombstone_guard ON auth.signing_keys;
CREATE TRIGGER signing_keys_tombstone_guard
    BEFORE INSERT ON auth.signing_keys
    FOR EACH ROW
    EXECUTE FUNCTION auth.deny_tombstoned_signing_kid_insert();
