-- Custom roles catalog.
--
-- Until now user.roles was a free-form TEXT[] validated only against the
-- admin-reserved deny-list (internal/seed). Consumers like BeOn3 need their own
-- roles (moderator, premium_user, …) governed by a catalog so the set of valid
-- roles is explicit and admin-manageable, while admin-tier names stay forbidden.
--
-- Design:
--   * name is the PK (role string used in JWT claims).
--   * reserved = catalog-protected: the admin API may not delete these.
--   * namespace groups roles by owning app (metadata only).
--   * admin/super_admin are intentionally NOT seeded here — those remain
--     AdminUser-only and are rejected for regular users by FilterUserRoles.
--   * vault_app gets SELECT only (it reads the catalog to validate user.roles
--     at JWT issuance). Catalog writes go through the admin gateway role.

CREATE TABLE IF NOT EXISTS auth.app_roles (
    name        VARCHAR(64) PRIMARY KEY,
    namespace   VARCHAR(64) NOT NULL DEFAULT 'app',
    description VARCHAR(255) NOT NULL DEFAULT '',
    reserved    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_roles_namespace ON auth.app_roles (namespace);

-- Baseline roles (reserved — cannot be deleted via the admin API).
INSERT INTO auth.app_roles (name, namespace, description, reserved) VALUES
    ('user',     'core', 'Standard authenticated user', TRUE),
    ('viewer',   'core', 'Read-only application access', TRUE),
    ('operator', 'core', 'Elevated application operator', TRUE)
ON CONFLICT (name) DO NOTHING;

-- BeOn3 application roles (deletable/manageable by super_admin).
INSERT INTO auth.app_roles (name, namespace, description, reserved) VALUES
    ('moderator',    'beon3', 'Forum moderator', FALSE),
    ('premium_user', 'beon3', 'Premium subscription user', FALSE),
    ('business',     'beon3', 'Business account', FALSE),
    ('creator',      'beon3', 'Content creator (dedicated forum subcategory)', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Least-privilege app role reads the catalog to validate user.roles at login.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT SELECT ON auth.app_roles TO vault_app;
    END IF;
END $$;
