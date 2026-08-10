-- ============================================================================
-- 014: service-scoped JSON document store (objects.service_documents)
-- ============================================================================
--
-- Services registered in auth.clients need somewhere to keep small structured
-- records about a subject without owning a schema migration for every new
-- per-user boolean. vault42 already has a namespaced arbitrary-JSON store,
-- IdentityData.Dynamic, with the right semantics (opaque, encrypted, validated
-- for size and shape only) and the wrong access control: it is one ciphertext,
-- written by the user's own token, with no per-service isolation. This table is
-- that store with an ownership axis.
--
-- It is deliberately NOT a column added to objects.blobs. Blob ownership is a
-- single pseudonym with no client dimension, the blob routes authenticate a
-- user JWT and their DELETE requires a password re-confirmation no service can
-- satisfy, and the blob prefix carries an exemption from the global body cap
-- sized for 10 MiB uploads.
--
-- Roles: vault_app performs the whole request path, including replacement and
-- deletion, so it needs UPDATE and DELETE as well as SELECT and INSERT. Note
-- that migration 001 sets ALTER DEFAULT PRIVILEGES IN SCHEMA objects granting
-- only SELECT, INSERT, DELETE, so an inherited default would leave replacement
-- failing with 42501 at runtime and invisible to the integration suite, which
-- connects as the container owner. The grant below is therefore explicit.
-- vault_admin gets SELECT and DELETE for the admin-gateway erasure cascade,
-- matching what migration 009 grants it on objects.blobs.
-- ============================================================================

CREATE TABLE IF NOT EXISTS objects.service_documents (
    id            UUID PRIMARY KEY,
    client_id     UUID NOT NULL REFERENCES auth.clients(id),
    subject_hash  VARCHAR(128) NOT NULL,
    doc_key       VARCHAR(128) NOT NULL,
    visibility    SMALLINT NOT NULL DEFAULT 0,
    data_enc      BYTEA NOT NULL,
    size_bytes    INTEGER NOT NULL,
    stored_bytes  INTEGER NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Lowercase segments joined by '.', '_' or '-'. Mirrors the identity store's
    -- dynamic-namespace shape (internal/service/identity.go dynamicKeyRe) so a
    -- key that is legal in one store is legal in the other.
    CONSTRAINT service_documents_key_chk
        CHECK (doc_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),

    -- 0 = private, 1 = shared. A CHECK rather than a boolean column: adding a
    -- third tier (an explicit grantee allow-list) is then a constraint widening
    -- plus a new table, not a column type change and a wire break.
    CONSTRAINT service_documents_visibility_chk
        CHECK (visibility IN (0, 1)),

    CONSTRAINT service_documents_size_chk
        CHECK (size_bytes >= 0 AND stored_bytes >= 0)
);

-- One document per (owning client, subject, key). Replacing a document is an
-- UPDATE through this index, never a second row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_svcdoc_owner_key
    ON objects.service_documents (client_id, subject_hash, doc_key);

-- The erasure cascade and the per-subject byte quota both span every owning
-- client for one subject, so they cannot use the index above.
CREATE INDEX IF NOT EXISTS idx_svcdoc_subject
    ON objects.service_documents (subject_hash);

-- Cross-service reads only ever look at shared rows; the partial index keeps
-- that lookup off the private majority.
CREATE INDEX IF NOT EXISTS idx_svcdoc_shared
    ON objects.service_documents (subject_hash, doc_key)
    WHERE visibility = 1;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON objects.service_documents TO vault_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        GRANT USAGE ON SCHEMA objects TO vault_admin;
        GRANT SELECT, DELETE ON objects.service_documents TO vault_admin;
    END IF;
END $$;
