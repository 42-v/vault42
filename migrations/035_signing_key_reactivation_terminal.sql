-- ============================================================================
-- 035: a rotated-out signing key stays retired even when the writer supplies
--      key material of its own
-- ============================================================================
--
-- 026 made the retired row terminal and stated the invariant as "a rotated-out
-- key stays retired". Its WHEN clause does not assert that. The reactivation
-- disjunct reads
--
--     NEW.status = 'active' AND NEW.private_key = OLD.private_key
--
-- and 026's header explains the exemption: keystore.Import re-encrypts on every
-- call, so a genuine re-import always changes private_key, while a bare
-- SET status = 'active' does not. That is true of the honest caller and says
-- nothing about a hostile one, because the condition is selected by whoever
-- writes the UPDATE. Reproduced as vault_app on PostgreSQL 16.15 with every
-- migration applied verbatim:
--
--     UPDATE auth.signing_keys SET status='active' WHERE kid='<retired>';
--       ERROR:  ... cannot return to active without new key material     -- 026 fires
--
--     UPDATE auth.signing_keys SET status='retired', expires_at=NOW()+INTERVAL '1 hour'
--      WHERE kid='<active>';                                            -- ordinary rotation shape
--     UPDATE auth.signing_keys SET status='active', private_key='\x99', public_key='\x98'
--      WHERE kid='<retired>';
--       UPDATE 1                                                        -- 026 never runs
--
-- One extra column in the SET list and the guard is gone.
--
-- ----------------------------------------------------------------------------
-- What this is and is not
-- ----------------------------------------------------------------------------
--
-- It is not a forgery path, and AR-15's position holds: Refresh publishes a key
-- only if its private_key decrypts under the master key with the kid as AAD and
-- the decrypted public half equals public_key, and an attacker without the
-- master key cannot produce that ciphertext. What is lost is availability and
-- the invariant itself. A corrupt row that says 'active' aborts the whole
-- Refresh rather than being skipped, so running pods keep their loaded key set
-- but a pod that boots afterwards cannot: EnsureKey refuses to start without a
-- successful Refresh, and the deployment cannot scale up or restart while the
-- row stands.
--
-- ----------------------------------------------------------------------------
-- The fix, in two parts, one of which is not a trigger
-- ----------------------------------------------------------------------------
--
-- Part 1 changes what the trigger compares. The kid is the first 16 hex digits
-- of SHA-256 over the public key's PKIX DER (internal/crypto/jwt.go), so under
-- a fixed kid the public_key column can never legitimately change: a re-import
-- of the same key writes the same bytes, and different bytes mean the writer
-- brought a different key. That is the discriminator the guard should have used.
-- The reactivation disjunct becomes
--
--     NEW.status = 'active' AND (NEW.private_key = OLD.private_key
--                                OR NEW.public_key IS DISTINCT FROM OLD.public_key)
--
-- which refuses the bare status flip exactly as 026 did, refuses the reproduction
-- above, and still lets Import's upsert through, since that writes fresh
-- ciphertext under the same public_key. Both columns are BYTEA NOT NULL, so
-- neither comparison meets a NULL; IS DISTINCT FROM is used anyway so a later
-- column change cannot turn the guard into NULL and let a write past.
--
-- Part 2 states the half of this that is a data invariant, as a CHECK. A key
-- carrying a retirement timestamp is not the active key: retired_at IS NULL OR
-- status <> 'active'. This is chosen over a fourth condition on the trigger for
-- the property 027 already leaned on and recorded: session_replication_role =
-- replica and ALTER TABLE ... DISABLE TRIGGER both suspend row triggers, and
-- 016, 017, 020, 023, 024 and 026 all name that as a limit the migration role
-- still holds. A CHECK has no off switch. It also catches the narrower write the
-- trigger provably cannot judge — SET status='active', private_key='<garbage>'
-- with public_key untouched is byte-for-byte what a re-import looks like to a
-- comparison of OLD and NEW, and the database cannot open the ciphertext to tell
-- the difference. What gives it away is that a re-import clears the retirement
-- stamp (keystore.Import sets retired_at = NULL in its ON CONFLICT clause) and
-- an in-place rewrite does not.
--
-- The transition itself stays a trigger because it has to. A CHECK sees one row
-- and has no OLD, so "retired must not become active" is not expressible as one;
-- 027's constraint works precisely because "retired implies an expiry" is a
-- property of a single row. Splitting the guard this way puts each half where it
-- can actually be enforced rather than choosing one mechanism for both.
--
-- Residual, stated rather than papered over: a writer that clears retired_at,
-- leaves public_key alone and supplies new private_key ciphertext is
-- indistinguishable at the database from a genuine re-import, and produces a row
-- Refresh refuses to publish. Closing that needs the reactivation to stop being
-- a raw UPDATE — either Import verifying incoming material against the stored
-- public_key before its upsert, or the upsert moving behind a SECURITY DEFINER
-- function on the house pattern of 015. Both are Go changes and neither belongs
-- in a migration.
--
-- ----------------------------------------------------------------------------
-- Live data and locks
-- ----------------------------------------------------------------------------
--
-- CREATE OR REPLACE FUNCTION and DROP/CREATE TRIGGER take ACCESS EXCLUSIVE on
-- auth.signing_keys for the length of the statement and scan nothing. The table
-- holds one active key plus whatever has not yet been reaped, so this is a
-- catalog update against single-digit rows.
--
-- The constraint is added NOT VALID deliberately. A plain ADD CONSTRAINT
-- validates every existing row inside that same ACCESS EXCLUSIVE lock and aborts
-- the migration if one fails, which on a live deployment is a CrashLoopBackOff
-- rather than a refused write; 021 and 027 already have that shape and a third
-- is not wanted. NOT VALID skips the scan and still enforces the constraint on
-- every INSERT and UPDATE from here on, which is the whole requirement — the
-- only row that could fail validation is one already produced by the defect this
-- closes, and the next legitimate re-import clears its retired_at.
--
-- Trigger ordering is unchanged: signing_keys_retire_path_terminal keeps its
-- name, so it still sorts between 020's DELETE-only signing_keys_reap_scope and
-- 017's signing_keys_revocation_terminal, and 017's WHEN still fires only on
-- OLD.status = 'revoked'. BEFORE ROW triggers run before CHECK constraints, so a
-- write that both refuse reports the trigger's message, which is the specific
-- one.
-- ============================================================================

-- Part 1: the retire-path guard compares the column that cannot lie ------------

CREATE OR REPLACE FUNCTION auth.deny_retired_signing_key_republish() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'active' AND NEW.public_key IS DISTINCT FROM OLD.public_key THEN
        RAISE EXCEPTION 'signing key % is retired: it cannot be reactivated under different key material (a kid is the hash of its public key, so a genuine re-import carries the same public_key)', OLD.kid;
    END IF;
    IF NEW.status = 'active' THEN
        RAISE EXCEPTION 'signing key % cannot return to active without new key material: a rotated-out key stays retired', OLD.kid;
    END IF;
    RAISE EXCEPTION 'signing key % is retired: its expiry cannot be cleared or extended (expires_at % -> %)', OLD.kid, OLD.expires_at, NEW.expires_at;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs
-- on any server old enough to lack the replace form, exactly as 026 does.
DROP TRIGGER IF EXISTS signing_keys_retire_path_terminal ON auth.signing_keys;
CREATE TRIGGER signing_keys_retire_path_terminal
    BEFORE UPDATE ON auth.signing_keys
    FOR EACH ROW WHEN (
        OLD.status = 'retired' AND (
            (NEW.status = 'active'
                AND (NEW.private_key = OLD.private_key
                     OR NEW.public_key IS DISTINCT FROM OLD.public_key))
            OR (NEW.status <> 'active' AND NEW.status <> 'revoked'
                AND OLD.expires_at IS NOT NULL
                AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at))
        )
    )
    EXECUTE FUNCTION auth.deny_retired_signing_key_republish();

-- Part 2: the retirement stamp is a data invariant -----------------------------

-- DROP + ADD rather than a bare ADD so the migration re-runs on a server that
-- already carries the constraint.
ALTER TABLE auth.signing_keys DROP CONSTRAINT IF EXISTS signing_keys_active_is_not_retired;
ALTER TABLE auth.signing_keys
    ADD CONSTRAINT signing_keys_active_is_not_retired
    CHECK (retired_at IS NULL OR status <> 'active') NOT VALID;
