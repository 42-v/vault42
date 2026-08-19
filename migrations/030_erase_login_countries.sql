-- ============================================================================
-- 030: erasure reaches auth.login_countries
-- ============================================================================
--
-- 028 created auth.login_countries with
--
--     user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE
--
-- and concluded from it: "user_id-owned and cascade-deleted, so account erasure
-- (Art. 17) removes a user's countries automatically with no bespoke cascade
-- step." The premise is true and the conclusion does not follow, because this
-- system never deletes the parent row. Erasure is a tombstone: 015's
-- auth.erase_user_identity() scrubs the identity columns of auth.users and sets
-- deleted = TRUE, and the row stays so the foreign keys stay valid. A referential
-- action that only fires on DELETE therefore never fires at all.
--
-- internal/service/erasure.go already says this out loud about the MFA tables
-- ("These hang off user_id with ON DELETE CASCADE, but the user row is scrubbed
-- with an UPDATE and never deleted - the cascade never fires, so they must be
-- removed explicitly"). 028 arrived after that comment was written and repeated
-- the assumption it corrects. The set of countries an account has signed in from
-- is location-revealing personal data, so it outlived an erasure that reported
-- success.
--
-- WHY A FUNCTION AND NOT A GRANT
--
-- The obvious fix is GRANT DELETE ON auth.login_countries TO vault_app, matching
-- what 001 gives the role on auth.devices and the rest of the cascade. 028
-- deliberately withheld exactly that privilege: "vault_app (the API) gets SELECT
-- + INSERT - it records countries and reads the prior count, and must never be
-- able to rewrite or erase them."
--
-- That restriction is load-bearing, not tidiness. This table is the baseline the
-- new-location notice (AR-18) compares against: an actor who can delete rows from
-- it can silence the notice for any account by clearing its history first, then
-- signing in from anywhere as a "first-ever" login. A standing table-level DELETE
-- would put that primitive behind anything that reaches the database as
-- vault_app, which is the whole API surface. 015 makes the same argument about
-- column grants and settles it the same way, so this follows 015.
--
-- auth.erase_login_countries() is SECURITY DEFINER, owned by the migration role,
-- and will only clear the history of an account that is already tombstoned. The
-- roles keep erasure and gain nothing else: for a live account the function
-- refuses, and there is no other writer. Erasure always tombstones before it
-- cascades (internal/service/erasure.go: escrow, then tombstone, THEN purge), and
-- a re-run of an interrupted erasure sees deleted = TRUE from the first attempt,
-- so both paths satisfy the guard.
--
-- A missing user row is not an error. The foreign key means no country row can
-- outlive a hard-deleted user, so there is nothing left to clear and the function
-- returns 0 rather than failing an erasure that has already succeeded.
--
-- The grants are written bare rather than inside a DO block, per 015: the
-- integration fixture's applyRealGrants() only re-applies a statement whose first
-- word is GRANT or REVOKE, so anything nested in a DO block is skipped there and
-- that suite would go on exercising the pre-030 privilege model. Each is kept on
-- one line for stripRoleGrants(), which drops a line starting with GRANT/REVOKE
-- and would otherwise leave a wrapped statement's tail behind as a syntax error.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.erase_login_countries(p_user_id UUID)
RETURNS BIGINT AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'login-country erasure needs a user id'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Refuse a live account. This is the whole reason the function exists: it
    -- must be an erasure step and never a way to clear the new-location baseline
    -- of an account someone is about to sign in to.
    IF EXISTS (SELECT 1 FROM auth.users WHERE id = p_user_id AND NOT deleted) THEN
        RAISE EXCEPTION 'login-country erasure refused for %: the account is not tombstoned', p_user_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    DELETE FROM auth.login_countries WHERE user_id = p_user_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- EXECUTE to the two roles that run an erasure and to nobody else. PostgreSQL
-- grants EXECUTE to PUBLIC by default, which would hand the erasure primitive to
-- every role in the cluster.
REVOKE ALL ON FUNCTION auth.erase_login_countries(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.erase_login_countries(UUID) TO vault_app;
GRANT EXECUTE ON FUNCTION auth.erase_login_countries(UUID) TO vault_admin;

-- ---------------------------------------------------------------------------
-- Remediation for data already on disk
-- ---------------------------------------------------------------------------
--
-- Every account erased between 028 and this migration kept its countries. Those
-- rows are a live Art. 17 failure, not a historical one, so they go now rather
-- than waiting for an erasure that will never be re-run.
--
-- Safe on a live database: a plain DELETE takes ROW EXCLUSIVE, never ACCESS
-- EXCLUSIVE, it touches only rows whose user is already tombstoned, and it
-- cannot abort the migration - a deployment where no account has been erased
-- simply removes nothing. auth.login_countries is a 028 table, so the scan is
-- over at most one release cycle of data.
DELETE FROM auth.login_countries lc
      USING auth.users u
      WHERE u.id = lc.user_id
        AND u.deleted;
