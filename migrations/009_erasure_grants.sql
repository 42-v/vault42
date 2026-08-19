-- ============================================================================
-- 009: privileges the account-erasure cascade actually needs
-- ============================================================================
--
-- Account erasure could not complete under either application role. The feature
-- shipped, the tests passed, and it had never worked outside a superuser session:
-- the integration suite connects to the testcontainer as its owner, so no
-- column-level or table-level grant was ever exercised.
--
-- vault_app (self-service DELETE /user/account)
--   SoftDeleteScrub does `UPDATE auth.users SET email=…, display_name=NULL,
--   avatar_url=NULL, deleted=TRUE, deleted_at=NOW(), updated_at=NOW()`.
--   The column-level UPDATE grant in 001 covers display_name, avatar_url and
--   updated_at; 004 added deleted and deleted_at. `email` was never granted, and
--   Postgres rejects the whole statement if any single target column is denied.
--   So the tombstone step failed with 42501 on every erasure request.
--
-- vault_admin (admin gateway, DELETE /admin/users/{id})
--   Held SELECT on the user tables and nothing else: no DELETE on any of the
--   cascade tables, no INSERT on the recovery escrow, no UPDATE on the columns the
--   tombstone writes. Every admin-initiated erasure failed at the first step.
--
-- On widening vault_admin: 001 notes that the admin role deliberately cannot
-- modify user identity data. The paragraph that stood here argued the invariant
-- survived because the grants below "add erasure (delete + tombstone), not
-- arbitrary mutation". THAT WAS WRONG, and migration 015 undoes it.
--
-- A column privilege is standing and unconditional. PostgreSQL does not tie it
-- to the WHERE clause, or to the other columns, of the statement it was added
-- for, so `GRANT UPDATE (email)` authorises `UPDATE auth.users SET email=$evil
-- WHERE id=$victim` on a live account just as much as it authorises the
-- tombstone. Since password reset follows the email address and every admin tier
-- shares the one vault_admin login, that is an account takeover reachable by
-- anything that reaches the database as either role.
--
-- 015 moves the tombstone into auth.erase_user_identity(), a SECURITY DEFINER
-- function that writes nothing but the scrub, and revokes the identity-column
-- grants made below from both roles. The rest of this migration (the cascade
-- DELETEs, the pseudonym-keyed stores, the append-only escrow) is unaffected
-- and still needed.
-- ============================================================================

-- --- vault_app -------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        -- The one missing column in the tombstone UPDATE. Revoked again by 015:
        -- the tombstone runs inside auth.erase_user_identity() now, and this
        -- grant also authorised rewriting any live account's address.
        GRANT UPDATE (email) ON auth.users TO vault_app;
    END IF;
END $$;

-- --- vault_admin -----------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        -- Tombstone the account row (scrub identity columns + mark deleted).
        -- Revoked again by 015, in full: these six columns are exactly the ones
        -- that let vault_admin rewrite a live user's identity, and the tombstone
        -- no longer needs them.
        GRANT UPDATE (email, display_name, avatar_url, deleted, deleted_at, updated_at)
            ON auth.users TO vault_admin;

        -- The PII cascade.
        GRANT DELETE ON auth.devices             TO vault_admin;
        GRANT DELETE ON auth.social_accounts     TO vault_admin;
        GRANT DELETE ON auth.password_history    TO vault_admin;
        GRANT DELETE ON auth.totp_secrets        TO vault_admin;
        GRANT DELETE ON auth.webauthn_credentials TO vault_admin;
        GRANT DELETE ON auth.backup_codes        TO vault_admin;
        GRANT DELETE ON auth.refresh_tokens      TO vault_admin;

        -- Pseudonym-keyed stores.
        GRANT USAGE ON SCHEMA identity TO vault_admin;
        GRANT USAGE ON SCHEMA objects  TO vault_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON identity.profiles TO vault_admin;
        GRANT SELECT, DELETE                 ON objects.blobs     TO vault_admin;

        -- Recovery escrow: append-only, and 007 revokes UPDATE/DELETE from
        -- vault_app. The same restriction applies here — INSERT and SELECT only,
        -- so an admin can write an escrow record and read it back but never
        -- rewrite or remove one.
        GRANT SELECT, INSERT ON auth.account_recovery TO vault_admin;
        REVOKE UPDATE, DELETE ON auth.account_recovery FROM vault_admin;
    END IF;
END $$;
