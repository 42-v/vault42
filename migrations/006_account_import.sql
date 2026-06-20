-- Account import support (the legacy platform migration).
--
-- Imported accounts are created with password_hash = NULL and import_pending =
-- TRUE: their original credentials use incompatible crypto (the legacy platform = SHA-256+salt)
-- and are NOT migrated. On the first login attempt vault42 ignores the supplied
-- password, emails a magic reset link, and forces the user to set a new Argon2
-- password (which clears import_pending). See internal/service/auth.go.
--
-- Columns:
--   import_pending  TRUE until the user claims the account via the reset link.
--   imported_from   source system tag (e.g. 'legacy'); NULL for native accounts.
--   legacy_id       the source system's user id, for cross-service joins.
-- (imported_from, legacy_id) is unique so re-running an import is idempotent.

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS import_pending BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS imported_from  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS legacy_id      UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_imported_legacy
    ON auth.users (imported_from, legacy_id)
    WHERE imported_from IS NOT NULL AND legacy_id IS NOT NULL;

-- vault_app clears import_pending when the account is claimed (password reset).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT UPDATE (import_pending) ON auth.users TO vault_app;
    END IF;
END $$;
