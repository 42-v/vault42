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
-- modify user identity data. That invariant is about an admin *editing* a user —
-- changing their email or password behind their back — and it still holds: the
-- grants below add erasure (delete + tombstone), not arbitrary mutation. The
-- gateway already exposes account erasure as an endpoint; it simply could not
-- perform it. It remains loopback-only, mTLS-authenticated and RBAC-gated.
-- ============================================================================

-- --- vault_app -------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        -- The one missing column in the tombstone UPDATE.
        GRANT UPDATE (email) ON auth.users TO vault_app;
    END IF;
END $$;

-- --- vault_admin -----------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        -- Tombstone the account row (scrub identity columns + mark deleted).
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
