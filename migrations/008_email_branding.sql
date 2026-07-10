-- Per-app email branding and template overrides (white-label auth emails).
--
-- vault42 acts as the auth authority for multiple applications. Each app should
-- see auth emails (verification, password reset, MFA code, lockout) that look
-- native to it — its own name, logo, accent colour, and optionally its own
-- From line and fully custom HTML — rather than the single global brand.
--
-- An "app" is a loose slug (e.g. 'acme', 'store'), consistent with how the
-- codebase already uses app identifiers (auth.app_roles.namespace,
-- auth.users.imported_from). It is intentionally NOT a foreign key to
-- auth.clients: branding must not require OAuth-client registration, and an
-- unknown slug simply falls back to the global defaults.
--
-- Two layers, both optional and independently useful:
--   * auth.email_branding  — per-app name/logo/colour/From. Setting just this
--     re-skins ALL existing templates for that app with zero template authoring.
--   * auth.email_templates — per-app, per-type full HTML override for apps that
--     need a completely custom email body. (app, template_name) is unique.
--
-- Roles: vault_app (the auth send path) gets SELECT only — it reads branding at
-- send time. The admin gateway runs as vault_admin and is granted full DML
-- explicitly below. Migrations run as the vault_mig DDL role, so vault_mig (not
-- vault_admin) owns these tables; write access for vault_admin therefore comes
-- from explicit grants, exactly as migration 001 grants the auth.admin_* and
-- auth.clients tables. updated_at is maintained by the repository UPDATE
-- statements (no trigger), matching the codebase convention.

-- Slug shared by both tables: lowercase, starts alphanumeric, <= 64 chars.
CREATE TABLE IF NOT EXISTS auth.email_branding (
    app           TEXT PRIMARY KEY
        CHECK (app ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    app_name      VARCHAR(255),
    logo_url      VARCHAR(1024),
    primary_color VARCHAR(7),
    from_name     VARCHAR(255),
    from_address  VARCHAR(254),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by    VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS auth.email_templates (
    id            UUID PRIMARY KEY,
    app           TEXT NOT NULL
        CHECK (app ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    template_name VARCHAR(64) NOT NULL,
    subject       VARCHAR(255) NOT NULL,
    html_content  TEXT NOT NULL,
    text_content  TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    VARCHAR(255),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by    VARCHAR(255)
);

-- One template per (app, type). Replacing means UPDATE, not a second row. This
-- unique index also serves app-prefix lookups (ListByApp), so no separate index
-- on (app) is needed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_templates_app_name
    ON auth.email_templates (app, template_name);

-- Least-privilege: the auth send path (vault_app) reads branding + templates;
-- the admin gateway (vault_admin) reads and writes them. Both grants are
-- explicit because vault_mig owns the tables (see the role note above).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT SELECT ON auth.email_branding  TO vault_app;
        GRANT SELECT ON auth.email_templates TO vault_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.email_branding  TO vault_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.email_templates TO vault_admin;
    END IF;
END $$;
