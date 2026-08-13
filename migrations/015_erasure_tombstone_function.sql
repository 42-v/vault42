-- ============================================================================
-- 015: the erasure tombstone moves behind a function, and the user identity
--      columns become immutable to the application roles again
-- ============================================================================
--
-- 009 handed both application roles column-level UPDATE on auth.users so the
-- erasure tombstone could run: UPDATE (email) for vault_app, and UPDATE (email,
-- display_name, avatar_url, deleted, deleted_at, updated_at) for vault_admin. It
-- argued the documented "admin cannot modify user identity data" invariant
-- survived because the grants "add erasure, not arbitrary mutation".
--
-- That is not what a GRANT is. A column privilege is standing and
-- unconditional. PostgreSQL does not tie it to the WHERE clause, or to the other
-- columns, of the statement that motivated it. Both roles could run
--
--     UPDATE auth.users SET email = 'attacker@example.com' WHERE id = <victim>
--
-- against a live, non-deleted account, and PostgreSQL accepted it. Nothing about
-- that statement is an erasure.
--
-- It is an account-takeover primitive rather than an untidy grant. Password
-- reset follows the email address, and every admin tier authenticates to
-- PostgreSQL as the same vault_admin login regardless of RBAC rank, so the
-- column grants were the only thing between a viewer-ranked admin session (or
-- any statement that reaches the database as either role) and a user's inbox.
--
-- The fix is the shape audit.cleanup_old_entries() already uses. The one
-- statement that legitimately writes those columns becomes a SECURITY DEFINER
-- function owned by the migration role, and the raw column grants go away. The
-- roles keep the ability to erase an account, which both erasure endpoints
-- already expose, and lose the ability to write anything else into those
-- columns, because the function is now the only writer and the only thing it
-- will write is a tombstone.
--
-- On the tombstone address. The function refuses any address that is not
-- `deleted-<the id of the row being scrubbed>@<something>.invalid`. Both halves
-- matter: `.invalid` is reserved by RFC 2606 and can never resolve or receive
-- mail, which is precisely the property that makes the write useless as a
-- takeover step, and pinning the local part to the row's own id stops one
-- account being aimed at another account's tombstone. The check is on the shape,
-- not on one literal string, so callers that use a different reserved domain
-- still work.
--
-- Callers updated in the same change: UserRepo.SoftDeleteScrub now calls this
-- function instead of issuing the UPDATE, and UserRepo.Update stopped listing
-- `email` in its SET clause. PUT /user/profile never changed the address (the
-- handler merges display_name, avatar_url and locale only), but PostgreSQL
-- checks the privilege on every target column whether or not the value differs,
-- so the column had to leave the statement before the grant could leave the
-- role. That statement is why 009's vault_app grant looked load-bearing.
--
-- The grants below are written bare rather than wrapped in a pg_roles guard, the
-- way 012 writes its grants. 001 creates both roles unconditionally, so the
-- guard buys nothing, and it costs something: the integration fixture's
-- applyRealGrants() re-applies a statement only when its first word is GRANT or
-- REVOKE, so anything nested inside a DO block is skipped there and that suite
-- would go on exercising the pre-015 privilege model.
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
       SET email        = p_tombstone_email,
           display_name = NULL,
           avatar_url   = NULL,
           deleted      = TRUE,
           deleted_at   = NOW(),
           updated_at   = NOW()
     WHERE id = p_user_id;

    GET DIAGNOSTICS scrubbed = ROW_COUNT;
    RETURN scrubbed > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- EXECUTE goes to the two roles that run an erasure and to nobody else.
-- PostgreSQL grants EXECUTE to PUBLIC by default, which would put the tombstone
-- back within reach of every role in the cluster.
REVOKE ALL ON FUNCTION auth.erase_user_identity(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.erase_user_identity(UUID, TEXT) TO vault_app;
GRANT EXECUTE ON FUNCTION auth.erase_user_identity(UUID, TEXT) TO vault_admin;

-- vault_app: email was never its column. 001 lists it under "immutable columns
-- (id, email, created_at)" and 009 granted it anyway. deleted and deleted_at came
-- from 004 for the same tombstone and have no other writer either, and while
-- they cannot take an account over they can retire one: vault_app could mark any
-- account deleted, and the account-state gate refuses deleted rows at login.
REVOKE UPDATE (email, deleted, deleted_at) ON auth.users FROM vault_app;

-- vault_admin: every column 009 opened. What is left from 001 is
-- UPDATE (locked_until, failed_login_count), which is the lock/unlock pair the
-- role is documented to have and the only user-table write the gateway makes
-- outside erasure.
-- Kept on one line: the integration fixture's stripRoleGrants() drops a line
-- that starts with REVOKE and keeps the ones that do not, so a wrapped
-- statement would leave its own tail behind as a syntax error.
REVOKE UPDATE (email, display_name, avatar_url, deleted, deleted_at, updated_at) ON auth.users FROM vault_admin;
