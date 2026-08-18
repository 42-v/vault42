-- ============================================================================
-- 031: the erasure tombstone scrubs the columns auth.users grew after 015
-- ============================================================================
--
-- Erasure keeps the account row. That is deliberate and it is not the problem:
-- eight tables carry a foreign key into auth.users, the account-state gate
-- refuses a deleted row at login, and cmd/recover needs the id to restore an
-- account from escrow. What the row is allowed to still contain is the problem.
--
-- auth.erase_user_identity() (migration 015) writes six columns: email (to the
-- tombstone), display_name, avatar_url, deleted, deleted_at, updated_at. That
-- was the whole of the personal data on auth.users when 015 was written. It is
-- not any more:
--
--   password_hash   (001) the Argon2id hash of the person's password. A
--                   credential, and one people reuse across services. Keeping it
--                   after an Art. 17 request is the worst item here: the account
--                   cannot be logged into, but the hash is still crackable
--                   offline and still tells an attacker what to try elsewhere.
--   roles           (003) what the person was entitled to. "staff", or a paid
--                   tier, is a fact about the person.
--   ban_reason      (004) free text an admin wrote about the person.
--   last_login_at   (004) when they last used the service.
--   imported_from   (006) which system their account came from.
--   legacy_id       (006) their identifier IN that system — an identifier for the
--                   same person in a different controller's database.
--
-- This is the login-country defect in its other form. There the erasure never
-- reached the table; here it reaches the table and stops at a column list that
-- stopped being complete three migrations later. Neither is visible to a reader
-- of the code that added the column, because the erasure story lives somewhere
-- else entirely.
--
-- WHAT IS DELIBERATELY LEFT
--
--   deleted, deleted_at   the tombstone itself.
--   banned, disabled      an erased account must stay refused. Erasure is not a
--                         way out of a ban, and these say nothing about the
--                         person that ban_reason did not carry.
--   email_verified        migration 024's transition trigger raises on TRUE ->
--                         FALSE, so clearing it would abort the erasure of any
--                         verified account. The address is already .invalid.
--   created_at            the escrow record and the audit trail are dated from it.
--   locale                a two-letter language tag with a schema default; not an
--                         identifier, and NOT NULL, so clearing it means writing
--                         a different value rather than removing one.
--   id                    every foreign key above depends on it, and it is what
--                         cmd/recover restores against.
--
-- The signature, the tombstone-address check and the return value are unchanged,
-- so SoftDeleteScrub and every caller are unaffected. This is CREATE OR REPLACE
-- on a function, which takes no table lock at all.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.erase_user_identity(p_user_id UUID, p_tombstone_email TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    scrubbed BIGINT;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'erasure tombstone needs a user id'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_tombstone_email IS NULL OR lower(p_tombstone_email) !~
        ('^deleted-' || lower(p_user_id::text) || '@[a-z0-9.-]+\.invalid$') THEN
        RAISE EXCEPTION 'erasure tombstone for % must be deleted-%@<domain>.invalid, got %',
            p_user_id, lower(p_user_id::text), p_tombstone_email
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    UPDATE auth.users
       SET email         = p_tombstone_email,
           display_name  = NULL,
           avatar_url    = NULL,
           password_hash = NULL,
           roles         = '{}',
           ban_reason    = NULL,
           last_login_at = NULL,
           imported_from = NULL,
           legacy_id     = NULL,
           deleted       = TRUE,
           deleted_at    = NOW(),
           updated_at    = NOW()
     WHERE id = p_user_id;

    GET DIAGNOSTICS scrubbed = ROW_COUNT;
    RETURN scrubbed > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- The EXECUTE grants from 015 survive CREATE OR REPLACE and are restated so this
-- file is self-contained on a database provisioned from it. One statement per
-- line, per 015: the integration fixture drops a line beginning REVOKE or GRANT,
-- and a wrapped statement would leave its tail behind as a syntax error.
REVOKE ALL ON FUNCTION auth.erase_user_identity(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.erase_user_identity(UUID, TEXT) TO vault_app;
GRANT EXECUTE ON FUNCTION auth.erase_user_identity(UUID, TEXT) TO vault_admin;

-- ---------------------------------------------------------------------------
-- Remediation for data already on disk
-- ---------------------------------------------------------------------------
--
-- Accounts erased before this migration still hold every column above. They are
-- a live Art. 17 failure and the erasure that should have cleared them will not
-- be run again.
--
-- Safe on a live database. It is an UPDATE, so ROW EXCLUSIVE and per-row locks,
-- never ACCESS EXCLUSIVE. The WHERE clause restricts it to tombstoned rows — a
-- small subset of any real deployment — and the second half means a re-run, or a
-- deployment that has never erased an account, updates nothing at all. No index
-- is built and none is needed: this runs once.
--
-- updated_at is deliberately not bumped. This is a repair of a past erasure, not
-- a new write to the account, and moving the timestamp would misdate it.
UPDATE auth.users
   SET password_hash = NULL,
       roles         = '{}',
       ban_reason    = NULL,
       last_login_at = NULL,
       imported_from = NULL,
       legacy_id     = NULL
 WHERE deleted
   AND (password_hash IS NOT NULL
     OR roles <> '{}'
     OR ban_reason IS NOT NULL
     OR last_login_at IS NOT NULL
     OR imported_from IS NOT NULL
     OR legacy_id IS NOT NULL);
