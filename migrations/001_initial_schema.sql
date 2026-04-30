-- Vault initial schema (merged from 001-008, pre-alpha reset)
-- No production database exists — single migration for clean bootstrap.

-- ============================================================================
-- Schemas
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS objects;

-- ============================================================================
-- Tables: auth schema
-- ============================================================================

CREATE TABLE auth.users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash VARCHAR(512),
    display_name VARCHAR(255),
    avatar_url VARCHAR(1024),
    locale VARCHAR(10) NOT NULL DEFAULT 'en',
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    locked_until TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.password_history (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    password_hash VARCHAR(512) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.social_accounts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    access_token_enc VARCHAR(2048),
    refresh_token_enc VARCHAR(2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE TABLE auth.clients (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    secret_hash VARCHAR(512) NOT NULL,
    role VARCHAR(50) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    redirect_uris TEXT[] DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES auth.clients(id),
    token_hash VARCHAR(128) NOT NULL,
    family_id UUID NOT NULL,
    device_id UUID,
    fingerprint_hash VARCHAR(128),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(128) NOT NULL,
    friendly_name VARCHAR(255),
    trusted BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_until TIMESTAMPTZ,
    ip VARCHAR(45),
    user_agent VARCHAR(1024),
    last_seen_at TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.totp_secrets (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    secret_enc VARCHAR(512) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    friendly_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.backup_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash VARCHAR(512) NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.rate_limits (
    key VARCHAR(512) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (key, window_start)
);

CREATE TABLE auth.admin_config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE TABLE auth.signing_keys (
    kid         TEXT PRIMARY KEY,
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    algorithm   TEXT NOT NULL DEFAULT 'RS256',
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'retired', 'revoked')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);

-- ============================================================================
-- Tables: audit schema
-- ============================================================================

CREATE TABLE audit.audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID,
    client_id UUID,
    ip VARCHAR(45),
    user_agent VARCHAR(1024),
    fingerprint_hash VARCHAR(128),
    device_id UUID,
    metadata JSONB,
    risk_score INTEGER NOT NULL DEFAULT 0
);

-- Append-only: prevent UPDATE and DELETE
CREATE OR REPLACE FUNCTION audit.deny_modify() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.deny_modify();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.deny_modify();

-- ============================================================================
-- Tables: identity schema
-- ============================================================================

CREATE TABLE identity.profiles (
    pseudonym_id  VARCHAR(128) PRIMARY KEY,
    data_enc      BYTEA NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Tables: objects schema
-- ============================================================================

CREATE TABLE objects.blobs (
    id            UUID PRIMARY KEY,
    pseudonym_id  VARCHAR(128) NOT NULL,
    ref_hash      VARCHAR(128),
    label_enc     BYTEA,
    data_enc      BYTEA NOT NULL,
    size_bytes    INTEGER NOT NULL,
    stored_bytes  INTEGER NOT NULL,
    checksum      VARCHAR(128) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Named blobs: at most one blob per (user, name).
-- ref_hash is HMAC(name, secret) so the plaintext name never hits the DB.
CREATE UNIQUE INDEX blobs_ref_unique ON objects.blobs (pseudonym_id, ref_hash) WHERE ref_hash IS NOT NULL;

-- Immutability: blobs cannot be updated, only created and deleted
CREATE OR REPLACE FUNCTION objects.deny_update() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'blobs are immutable: UPDATE not allowed';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blobs_no_update
    BEFORE UPDATE ON objects.blobs
    FOR EACH ROW EXECUTE FUNCTION objects.deny_update();

-- ============================================================================
-- Tables: RBAC admin (admin gateway)
-- ============================================================================

CREATE TABLE auth.admin_roles (
    role        VARCHAR(32) PRIMARY KEY,
    description VARCHAR(128) NOT NULL,
    rank        INTEGER NOT NULL UNIQUE
);

INSERT INTO auth.admin_roles (role, description, rank) VALUES
    ('viewer',      'Read-only access to keys, audit, users, sessions, config, metrics', 1),
    ('operator',    'Viewer + rotate keys, lock/unlock users, revoke sessions, list clients', 2),
    ('super_admin', 'Full access: revoke keys, delete users, manage clients/config/admins', 3);

CREATE TABLE auth.admin_users (
    id                UUID PRIMARY KEY,
    username          VARCHAR(64) UNIQUE NOT NULL,
    password_hash     VARCHAR(512) NOT NULL,
    role              VARCHAR(32) NOT NULL REFERENCES auth.admin_roles(role),
    totp_secret_enc   VARCHAR(512),
    totp_verified     BOOLEAN NOT NULL DEFAULT FALSE,
    last_totp_counter BIGINT NOT NULL DEFAULT 0,
    locked_until      TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    last_login_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by        UUID REFERENCES auth.admin_users(id)
);

CREATE TABLE auth.admin_sessions (
    id          UUID PRIMARY KEY,
    admin_id    UUID NOT NULL REFERENCES auth.admin_users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(128) NOT NULL,
    ip          VARCHAR(45) NOT NULL,
    user_agent  VARCHAR(1024),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX idx_password_history_user ON auth.password_history(user_id);
CREATE INDEX idx_social_accounts_user ON auth.social_accounts(user_id);
CREATE UNIQUE INDEX idx_totp_secrets_user ON auth.totp_secrets(user_id);
CREATE INDEX idx_webauthn_credentials_user ON auth.webauthn_credentials(user_id);
CREATE INDEX idx_backup_codes_user ON auth.backup_codes(user_id);
CREATE INDEX idx_refresh_tokens_user ON auth.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family ON auth.refresh_tokens(family_id);
CREATE UNIQUE INDEX idx_refresh_tokens_hash_unique ON auth.refresh_tokens(token_hash);
CREATE INDEX idx_devices_user ON auth.devices(user_id);
CREATE INDEX idx_devices_fingerprint ON auth.devices(fingerprint_hash);
CREATE UNIQUE INDEX idx_devices_user_fingerprint_unique ON auth.devices(user_id, fingerprint_hash);
CREATE UNIQUE INDEX idx_clients_name_unique ON auth.clients(name);
CREATE INDEX idx_signing_keys_status ON auth.signing_keys(status);
CREATE UNIQUE INDEX idx_signing_keys_active ON auth.signing_keys(status) WHERE status = 'active';
CREATE INDEX idx_blobs_pseudonym ON objects.blobs(pseudonym_id);
CREATE INDEX idx_admin_sessions_admin ON auth.admin_sessions(admin_id);
CREATE INDEX idx_admin_sessions_hash ON auth.admin_sessions(token_hash);
CREATE INDEX idx_admin_sessions_expires ON auth.admin_sessions(expires_at);
CREATE INDEX idx_audit_log_user ON audit.audit_log(user_id);
CREATE INDEX idx_audit_log_timestamp ON audit.audit_log(timestamp);
CREATE INDEX idx_audit_log_event_type ON audit.audit_log(event_type);
CREATE INDEX idx_users_email ON auth.users(email);
CREATE INDEX idx_rate_limits_key ON auth.rate_limits(key);
CREATE INDEX idx_cache_expires ON auth.cache(expires_at);

-- ============================================================================
-- Role grants: vault_app (main API, least privilege)
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        CREATE ROLE vault_app LOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA auth TO vault_app;
GRANT USAGE ON SCHEMA audit TO vault_app;
GRANT USAGE ON SCHEMA identity TO vault_app;
GRANT USAGE ON SCHEMA objects TO vault_app;

-- auth.users: full CRUD, column-level UPDATE restriction
-- Immutable columns (id, email, created_at) cannot be updated by vault_app
GRANT SELECT, INSERT, DELETE ON auth.users TO vault_app;
GRANT UPDATE (password_hash, display_name, avatar_url, locale, mfa_required, email_verified, locked_until, failed_login_count, updated_at) ON auth.users TO vault_app;

-- auth.password_history: full CRUD (managed by password change flow)
GRANT SELECT, INSERT, DELETE ON auth.password_history TO vault_app;

-- auth.social_accounts: full CRUD (managed by OAuth2 flows)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.social_accounts TO vault_app;

-- auth.clients: SELECT + INSERT for vault_app (seeding creates clients at startup)
-- UPDATE/DELETE restricted to admin gateway
GRANT SELECT, INSERT ON auth.clients TO vault_app;

-- auth.refresh_tokens: full CRUD (token lifecycle)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.refresh_tokens TO vault_app;

-- auth.devices: full CRUD (device management)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.devices TO vault_app;

-- auth.totp_secrets: full CRUD (2FA setup/teardown)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.totp_secrets TO vault_app;

-- auth.webauthn_credentials: full CRUD (passkey management)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.webauthn_credentials TO vault_app;

-- auth.backup_codes: full CRUD (2FA backup codes)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.backup_codes TO vault_app;

-- auth.rate_limits: full CRUD (rate limit counters)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.rate_limits TO vault_app;

-- auth.admin_config: SELECT + INSERT + UPDATE for vault_app (InitAdminToken writes at startup)
-- DELETE restricted to admin gateway
GRANT SELECT, INSERT, UPDATE ON auth.admin_config TO vault_app;

-- auth.cache: full CRUD (cache entries)
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.cache TO vault_app;

-- Signing keys: SELECT, INSERT, UPDATE (no DELETE — revoke only)
GRANT SELECT, INSERT, UPDATE ON auth.signing_keys TO vault_app;

-- Audit schema: INSERT, SELECT only (append-only)
GRANT SELECT, INSERT ON audit.audit_log TO vault_app;
REVOKE UPDATE, DELETE ON audit.audit_log FROM vault_app;

-- Identity schema: full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.profiles TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA identity GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_app;

-- Objects schema: SELECT, INSERT, DELETE (no UPDATE — trigger enforces immutability)
GRANT SELECT, INSERT, DELETE ON objects.blobs TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA objects GRANT SELECT, INSERT, DELETE ON TABLES TO vault_app;

-- vault_app: restricted access to admin tables (read-only)
GRANT SELECT ON auth.admin_roles TO vault_app;
GRANT SELECT ON auth.admin_users TO vault_app;
GRANT SELECT ON auth.admin_sessions TO vault_app;
REVOKE INSERT, UPDATE, DELETE ON auth.admin_users FROM vault_app;
REVOKE INSERT, UPDATE, DELETE ON auth.admin_sessions FROM vault_app;

-- ============================================================================
-- Trigger: prevent admin role escalation via direct SQL
-- Belt-and-suspenders with Go RBAC — even if SQL injection reaches the DB,
-- a lower-ranked admin cannot promote themselves to a higher rank.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.deny_role_escalation() RETURNS TRIGGER AS $$
DECLARE
    old_rank INTEGER;
    new_rank INTEGER;
BEGIN
    IF NEW.role IS DISTINCT FROM OLD.role THEN
        SELECT rank INTO old_rank FROM auth.admin_roles WHERE role = OLD.role;
        SELECT rank INTO new_rank FROM auth.admin_roles WHERE role = NEW.role;
        IF new_rank > old_rank THEN
            -- Log to audit before raising (best-effort, ignore failure)
            BEGIN
                INSERT INTO audit.audit_log (id, event_type, metadata)
                VALUES (
                    gen_random_uuid(),
                    'admin:role_escalation_blocked',
                    jsonb_build_object(
                        'admin_id', OLD.id,
                        'username', OLD.username,
                        'old_role', OLD.role,
                        'new_role', NEW.role
                    )
                );
            EXCEPTION WHEN OTHERS THEN
                NULL; -- audit failure must not mask the escalation block
            END;
            RAISE EXCEPTION 'role escalation denied: cannot promote % → %', OLD.role, NEW.role;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_users_no_escalation
    BEFORE UPDATE ON auth.admin_users
    FOR EACH ROW EXECUTE FUNCTION auth.deny_role_escalation();

-- ============================================================================
-- Role grants: vault_admin (admin gateway only)
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        CREATE ROLE vault_admin LOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA auth TO vault_admin;
GRANT USAGE ON SCHEMA audit TO vault_admin;

-- vault_admin: full access to admin tables
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.admin_users TO vault_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.admin_sessions TO vault_admin;
GRANT SELECT ON auth.admin_roles TO vault_admin;

-- vault_admin: read + column-level update on user tables (lock/unlock only)
-- Admin cannot modify user identity data (password, email, display_name, avatar)
GRANT SELECT ON auth.users TO vault_admin;
GRANT UPDATE (locked_until, failed_login_count) ON auth.users TO vault_admin;
GRANT SELECT ON auth.refresh_tokens TO vault_admin;
GRANT SELECT ON auth.devices TO vault_admin;
GRANT SELECT, INSERT, UPDATE ON auth.clients TO vault_admin;
GRANT SELECT, INSERT, UPDATE ON auth.admin_config TO vault_admin;

-- vault_admin: signing key management (rotate, list, revoke)
GRANT SELECT, INSERT, UPDATE ON auth.signing_keys TO vault_admin;

-- vault_admin: audit log access (read + append)
GRANT SELECT, INSERT ON audit.audit_log TO vault_admin;

-- ============================================================================
-- Audit log retention cleanup function (SECURITY DEFINER)
-- ============================================================================
-- The audit log is append-only (deny_modify triggers block DELETE/UPDATE).
-- This function temporarily disables the delete trigger, removes old entries,
-- then re-enables it. Only callable via CLI with admin token.
CREATE OR REPLACE FUNCTION audit.cleanup_old_entries(retention_interval INTERVAL)
RETURNS BIGINT AS $$
DECLARE deleted BIGINT;
BEGIN
    ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_no_delete;
    DELETE FROM audit.audit_log WHERE timestamp < NOW() - retention_interval;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_no_delete;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
