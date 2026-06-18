-- Add account-level lifecycle flags to auth.users for BeOn3 parity.
--
-- BeOn3's Users table carries Active / Banned / BanReason / LastLogin and a
-- soft-delete. vault42 already had email_verified + locked_until; this adds the
-- remaining account-state columns so an imported BeOn3 account keeps its status,
-- and so the login flow can reject banned/disabled/deleted accounts.
--
-- Constraints:
--   * All additive with safe defaults → existing rows survive without rewrite.
--   * disabled/banned/deleted are NOT NULL DEFAULT FALSE; ban_reason and the
--     *_at timestamps are nullable (only set when the state applies).
--   * Column-level UPDATE grant is extended for vault_app (the table grant in
--     001 is column-scoped on UPDATE); SELECT/INSERT are already table-wide.

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS banned        BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ban_reason    VARCHAR(500),
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS deleted_at    TIMESTAMPTZ;

-- Partial index: the common "list active accounts" / login lookups skip
-- soft-deleted rows. Keeps the email unique index honest while letting the
-- app filter deleted accounts cheaply.
CREATE INDEX IF NOT EXISTS idx_users_active ON auth.users (id) WHERE deleted = FALSE;

-- Extend the column-level UPDATE grant for the least-privilege app role.
-- Guarded so the migration also applies on databases provisioned without the
-- vault_app role (e.g. some test fixtures).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT UPDATE (disabled, banned, ban_reason, last_login_at, deleted, deleted_at)
            ON auth.users TO vault_app;
    END IF;
END $$;
