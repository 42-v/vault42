-- ============================================================================
-- 037: a signing key's kid is immutable, and its material stops being writable
--      by a raw statement
-- ============================================================================
--
-- 026 states its tombstone invariant as "the kid it frees can never be filled
-- again". 035 states its own as "a rotated-out key stays retired". Neither
-- holds. Both were enforced against the writes their authors pictured -- an
-- INSERT of a tombstoned kid, a status flip with the material untouched -- and
-- both are reachable by an UPDATE that says something slightly different. All
-- four statements below were run as vault_app on PostgreSQL 16.15, over TCP,
-- with 001..035 applied verbatim.
--
-- ----------------------------------------------------------------------------
-- M-C1: nothing guards the kid
-- ----------------------------------------------------------------------------
--
-- No trigger on this table carries a WHEN clause that mentions kid. 017's fires
-- only on OLD.status = 'revoked' and 026's retire-path clause only on a status
-- move or an expiry that grows; a rename is neither, so a rename is judged by
-- nothing.
--
-- M-C1a, free a kid without leaving a tombstone. The tombstone is written by an
-- AFTER DELETE trigger, so a kid vacated by UPDATE is recorded nowhere and 026's
-- INSERT guard has nothing to refuse:
--
--     UPDATE auth.signing_keys SET kid = 'Kr-old' WHERE kid = 'Kr';   -- UPDATE 1
--     INSERT INTO auth.signing_keys (kid, ...) VALUES ('Kr', ...);    -- INSERT 0 1
--
-- M-C1b, re-fill a kid the reaper legitimately tombstoned one statement earlier.
-- The INSERT guard is the only reader of auth.signing_key_tombstones, so an
-- UPDATE walks a surviving row onto the freed identifier instead:
--
--     DELETE FROM auth.signing_keys WHERE kid = 'Kreap';              -- tombstoned
--     INSERT INTO auth.signing_keys (kid, ...) VALUES ('Kreap', ...);
--       ERROR:  signing key kid Kreap is tombstoned                   -- 026 fires
--     UPDATE auth.signing_keys SET kid = 'Kreap' WHERE kid = 'Kn';    -- UPDATE 1
--
-- The end state that produced is a live signing_keys row with kid 'Kreap' while
-- auth.signing_key_tombstones simultaneously holds 'Kreap'. 026's stated
-- invariant and the table disagree, and the table wins.
--
-- M-C1c, rename the active kid. This one is not a resurrection at all. The kid
-- is the AES-GCM additional authenticated data the private half is wrapped under
-- (internal/keystore/keystore.go, Import), so the identifier is inside the
-- ciphertext's tag. Move it and the row stops opening:
--
--     UPDATE auth.signing_keys SET kid = 'Ka-hijacked' WHERE kid = 'Ka';  -- UPDATE 1
--
-- Refresh treats a decrypt failure on the ACTIVE row as fatal and EnsureKey will
-- not start without a successful Refresh, so no pod boots or scales from that
-- moment on. Running pods keep the key set they already loaded, which is what
-- makes it quiet: the deployment looks healthy until the next rollout.
--
-- ----------------------------------------------------------------------------
-- M-C2: 035's disclosed residual is two ordinary statements
-- ----------------------------------------------------------------------------
--
-- 035 closed the reactivation shapes a trigger can judge and then disclosed the
-- one it cannot: "a writer that clears retired_at, leaves public_key alone and
-- supplies new private_key ciphertext is indistinguishable at the database from
-- a genuine re-import". That is not a corner. It is two statements, and the
-- first of them is the shape a rotation already writes:
--
--     UPDATE auth.signing_keys SET status='retired', retired_at=NOW(),
--            expires_at=NOW()+INTERVAL '1 hour' WHERE kid='Ka';   -- UPDATE 1
--     UPDATE auth.signing_keys SET status='active', private_key='\xdeadbeef',
--            retired_at=NULL, expires_at=NULL WHERE kid='Kr';     -- UPDATE 1
--
-- public_key is untouched, so 035's first disjunct is false; NEW.status is
-- 'active', so its second is false; retired_at is NULL, so 027's and 035's
-- CHECKs both pass. The sole active signing key now carries attacker bytes. One
-- extra column in the SET list, which is the critique 035 levelled at 026,
-- levelled back.
--
-- ----------------------------------------------------------------------------
-- The fix, in two parts, because the two defects want different mechanisms
-- ----------------------------------------------------------------------------
--
-- Part 1, a kid-immutability trigger, settles M-C1.
--
-- No legitimate path renames a kid, and the reason is arithmetic rather than
-- convention: the kid is the first 16 hex digits of SHA-256 over the public
-- key's PKIX DER (internal/crypto/jwt.go), so the identifier is a function of
-- the material. A row whose kid changed is either a different key wearing an old
-- name or the same key wearing a new one, and this schema has no word for
-- either. keystore.Import derives the kid and uses it as the ON CONFLICT target;
-- Revoke, CleanupExpired, the rotation age query and Import's retire step all
-- address rows by kid and never assign one. So freezing the column costs
-- nothing.
--
-- Freezing it settles M-C1b without a second mechanism. A row that cannot change
-- its kid cannot be walked onto a tombstoned one, so 026's tombstone regains the
-- property it claimed: an INSERT is refused by the guard, an UPDATE can no
-- longer arrive by the side door, and DELETE becomes the only way a kid ever
-- leaves a row -- which is the event that records the tombstone in the first
-- place.
--
-- Part 2, the material columns leave the application roles, settles M-C2.
--
-- Compare the two writes a guard would have to separate. A genuine re-import
-- through keystore.Import leaves OLD = (kid, retired, priv P, pub Q, retired_at
-- T) and NEW = (kid, active, priv P'', pub Q, retired_at NULL). The M-C2 write
-- leaves NEW = (kid, active, priv P', pub Q, retired_at NULL). They are the same
-- row shape. The only thing telling P'' from P' is whether it opens under the
-- master key with the kid as AAD, and the database does not hold the master key
-- and never will -- that is AR-15's position and it is the right one. So no WHEN
-- clause, no CHECK and no amount of column comparison can decide this. What has
-- to change is not what the write says but who can express it.
--
-- 035 names two ways to do that. The first, Import verifying incoming material
-- against the stored public_key before its upsert, is not taken, and the reason
-- is the one 017's header gives for not leaving terminality in application SQL:
-- the attacker here is SQL arriving as vault_app, from an injection sink or from
-- the application's own credential, and that attacker does not call Import. A
-- check inside Import constrains the honest caller and says nothing about the
-- hostile one -- which is exactly the reasoning 035 used to reject 026's "a
-- genuine re-import always changes private_key".
--
-- The second is taken. The upsert moves behind a SECURITY DEFINER function on
-- 015's pattern, and the raw privilege that made the statement expressible goes
-- with it. 015's own point is that a column privilege is standing and
-- unconditional, and is not narrowed by the statement that motivated it.
--
-- ----------------------------------------------------------------------------
-- Which columns, and why the split is where it is
-- ----------------------------------------------------------------------------
--
-- auth.signing_keys carries two kinds of column and they want different
-- mechanisms.
--
--   * Identity and material -- kid, private_key, public_key, algorithm,
--     created_at. Exactly one statement in the tree writes these, and it is the
--     upsert in keystore.Import. Nothing else assigns them: Revoke,
--     CleanupExpired, the rotation age query and Import's own retire step all
--     address rows by kid and never set one. Once the upsert is a function,
--     UPDATE on these columns has no remaining caller, so it comes off the two
--     application roles rather than being guarded.
--
--   * Lifecycle -- status, retired_at, expires_at. These have real raw writers:
--     Revoke's UPDATE and the retire step Import runs before the upsert. They
--     stay, and they stay guarded by 017's revocation trigger, 020's reap scope,
--     026 and 035's retire path and 027's and 035's CHECKs -- the mechanisms
--     that can actually judge a lifecycle move, because a lifecycle move is made
--     of values the database can read.
--
-- The kid is in the first group and also carries Part 1's trigger. That is not
-- redundancy for its own sake. The privilege answers for the two roles the
-- services connect as; the trigger answers for every other role including the
-- owner, and keeps the invariant stated if a later migration re-grants the
-- column. 017 makes the same argument for refusing DELETE on a revoked row
-- before any role held DELETE at all.
--
-- ----------------------------------------------------------------------------
-- What the function checks that the raw upsert could not
-- ----------------------------------------------------------------------------
--
-- A definer function that merely wrapped the same INSERT would move the
-- privilege and buy nothing, since vault_app holds EXECUTE on it. What makes it
-- narrower than the statement it replaces is that it can only produce the import
-- shape -- one row, status 'active', retired_at and expires_at cleared, revoked
-- rows excluded -- and that it verifies the one invariant the database is able
-- to verify about key material:
--
--     kid = substr(sha256(public_key)::hex, 1, 8) || '-' ||
--           substr(sha256(public_key)::hex, 9, 8)
--
-- which is internal/crypto/jwt.go's KIDFromPublicKey. A caller can no longer
-- file material under a kid of its choosing; it may only claim the kid that is
-- the digest of the public key it supplied. Changing the derivation in Go
-- without changing it here would refuse every import, which is why
-- tests/integration pins the two against a freshly generated key rather than
-- against a literal.
--
-- ----------------------------------------------------------------------------
-- Residual, stated rather than papered over
-- ----------------------------------------------------------------------------
--
-- Unchanged in kind from AR-15. A caller holding vault_app may still retire the
-- active key through its lifecycle grant and then call this function with a
-- self-consistent (kid, public_key) pair of its own and ciphertext that does not
-- open. The result is a row Refresh refuses to publish and an active key no pod
-- can load: availability, which AR-15 already states is not defended for this
-- table, and not forgery, which needs the master key. The owner role can still
-- rewrite material on a reactivation directly, because that write is
-- indistinguishable from a re-import to anything without the master key;
-- tests/attack pins that limit as a recorded fact.
--
-- What no longer survives is the specific claim 026 and 035 make and could not
-- keep -- that a rotated-out key stays retired -- for the two roles the services
-- connect as, because reaching a retired row's private_key by UPDATE is now a
-- privilege error before any guard is consulted.
--
-- ----------------------------------------------------------------------------
-- Trigger ordering, live data and locks
-- ----------------------------------------------------------------------------
--
-- Same-event triggers fire in name order. On BEFORE UPDATE this table now
-- carries signing_keys_kid_immutable, 026's signing_keys_retire_path_terminal
-- and 017's signing_keys_revocation_terminal, in that order, and the new name
-- sorts first. That matters for exactly one row shape: a revoked row being
-- renamed, which 017 already refuses and which tests/integration pins by 017's
-- message. Rather than lean on a name, the WHEN clause excludes revoked rows
-- outright, the way 020's reap scope excludes them and for the same stated
-- reason -- 017 stays the only guard that speaks for a revoked key, and the
-- ordering becomes irrelevant instead of merely lucky. Coverage is not lost: 017
-- freezes a revoked row entirely, kid included, and names that attack. On a
-- retired or active row the other two triggers do not fire on a bare rename, so
-- the message a rename returns is this one and only this one.
--
-- IS DISTINCT FROM rather than <>: kid is TEXT PRIMARY KEY and cannot be NULL
-- today, and 035 already records why the null-safe form is used anyway -- a
-- later schema change must not be able to turn a guard's condition into NULL and
-- let a write past.
--
-- CREATE OR REPLACE FUNCTION, DROP/CREATE TRIGGER and the GRANT/REVOKE pairs are
-- catalog updates and scan no rows. REVOKE UPDATE followed by GRANT UPDATE
-- (columns) is the only order that works: a table-level UPDATE privilege implies
-- every column and PostgreSQL will not carve one out of it -- REVOKE UPDATE
-- (col) against a table-level holder warns and revokes nothing. Re-running the
-- pair is idempotent. Each GRANT and REVOKE is kept on one line because the
-- integration fixture's stripRoleGrants() drops a line that starts with GRANT or
-- REVOKE and keeps the ones that do not, so a wrapped statement leaves its own
-- tail behind as a syntax error -- the same constraint 015 records.
--
-- The limit 016, 017, 020, 023, 024, 026 and 035 all name applies to Part 1 and
-- is not papered over. ALTER TABLE ... DISABLE TRIGGER, session_replication_role
-- = replica and TRUNCATE bypass row triggers, and the migration role holds them.
-- Part 2 does not share that limit: a privilege has no off switch, which is the
-- property 027 and 035 reached for when they chose a CHECK over a fourth trigger
-- condition.
-- ============================================================================

-- Part 1: the kid is immutable ------------------------------------------------

CREATE OR REPLACE FUNCTION auth.deny_signing_key_kid_change() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'signing key kid is immutable: % cannot be renamed to % (the kid is the AEAD associated data its own private_key is wrapped under, and the identifier a tombstone retires)', OLD.kid, NEW.kid;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the whole condition, so every write that leaves the
-- kid alone reaches the table without entering plpgsql.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs
-- on any server old enough to lack the replace form, exactly as 017, 020, 026
-- and 035 do.
DROP TRIGGER IF EXISTS signing_keys_kid_immutable ON auth.signing_keys;
CREATE TRIGGER signing_keys_kid_immutable
    BEFORE UPDATE ON auth.signing_keys
    FOR EACH ROW WHEN (NEW.kid IS DISTINCT FROM OLD.kid AND OLD.status <> 'revoked')
    EXECUTE FUNCTION auth.deny_signing_key_kid_change();

-- Part 2a: the upsert becomes a function --------------------------------------

CREATE OR REPLACE FUNCTION auth.import_signing_key(
    p_kid         TEXT,
    p_private_key BYTEA,
    p_public_key  BYTEA,
    p_algorithm   TEXT,
    p_created_at  TIMESTAMPTZ
) RETURNS BOOLEAN AS $$
DECLARE
    expected TEXT;
    written  BIGINT;
BEGIN
    IF p_kid IS NULL OR p_private_key IS NULL OR p_public_key IS NULL THEN
        RAISE EXCEPTION 'signing key import needs a kid and both halves of the key'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    expected := encode(sha256(p_public_key), 'hex');
    expected := substr(expected, 1, 8) || '-' || substr(expected, 9, 8);
    IF p_kid <> expected THEN
        RAISE EXCEPTION 'signing key kid % is not the digest of the public key supplied with it (expected %)',
            p_kid, expected
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- The WHERE is 017's guard, which used to live in application SQL where raw
    -- statements never ran it. Here it is on the only write path there is.
    INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at)
    VALUES (p_kid, p_private_key, p_public_key, COALESCE(p_algorithm, 'RS256'), 'active',
            COALESCE(p_created_at, NOW()))
    ON CONFLICT (kid) DO UPDATE SET
        private_key = EXCLUDED.private_key,
        public_key  = EXCLUDED.public_key,
        status      = 'active',
        retired_at  = NULL,
        expires_at  = NULL
    WHERE signing_keys.status <> 'revoked';

    GET DIAGNOSTICS written = ROW_COUNT;
    RETURN written > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- EXECUTE goes to the two roles that import a key and to nobody else. PostgreSQL
-- grants EXECUTE to PUBLIC by default, which would put the only remaining writer
-- of this table's key material within reach of every role in the cluster.
REVOKE ALL ON FUNCTION auth.import_signing_key(TEXT, BYTEA, BYTEA, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.import_signing_key(TEXT, BYTEA, BYTEA, TEXT, TIMESTAMPTZ) TO vault_app;
GRANT EXECUTE ON FUNCTION auth.import_signing_key(TEXT, BYTEA, BYTEA, TEXT, TIMESTAMPTZ) TO vault_admin;

-- Part 2b: the identity and material columns leave the application roles -------

-- vault_app keeps INSERT deliberately. AR-15's finding is that a row vault_app
-- plants is kept out of JWKS by the master key rather than by the grant, and
-- tests/attack pins that. Removing INSERT would retire a test of the control
-- that actually holds, in exchange for nothing: an INSERT cannot reach an
-- existing row's material, which is what this migration is about.
REVOKE UPDATE ON auth.signing_keys FROM vault_app;
GRANT UPDATE (status, retired_at, expires_at) ON auth.signing_keys TO vault_app;

REVOKE UPDATE ON auth.signing_keys FROM vault_admin;
GRANT UPDATE (status, retired_at, expires_at) ON auth.signing_keys TO vault_admin;
