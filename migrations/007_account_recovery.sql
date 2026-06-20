-- Account-deletion recovery escrow log.
--
-- Every account erasure (GDPR right-to-be-forgotten) appends one row here so an
-- operator can restore a deleted user from backup after an accidental or
-- malicious deletion. The recoverable material (the user's real email and a
-- minimal profile) is held ONLY in the encrypted `payload` column.
--
-- Asymmetric escrow: the server holds only a recovery PUBLIC key. It can WRITE
-- (encrypt) records but cannot READ them back — decryption needs the matching
-- PRIVATE key, which is kept offline by the operator. A compromised server or
-- database therefore cannot recover the erased emails, but the operator still
-- can, using the offline key (see cmd/recover).
--
-- `pseudonym` is an HMAC-SHA256 of the user id. It lets an operator correlate a
-- recovery record back to a (now soft-deleted) user row without storing the
-- plaintext identity in this table.
--
-- Append-only: like audit.audit_log, UPDATE and DELETE are blocked by triggers
-- and vault_app is granted INSERT + SELECT only. An attacker who can write rows
-- still cannot rewrite or erase escrow history.

CREATE TABLE IF NOT EXISTS auth.account_recovery (
    id          UUID PRIMARY KEY,
    pseudonym   TEXT NOT NULL,
    payload     BYTEA NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_by  TEXT,
    reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_account_recovery_pseudonym  ON auth.account_recovery (pseudonym);
CREATE INDEX IF NOT EXISTS idx_account_recovery_deleted_at ON auth.account_recovery (deleted_at);

-- Append-only: reuse the audit.deny_modify() trigger function (migration 001).
CREATE TRIGGER account_recovery_no_update
    BEFORE UPDATE ON auth.account_recovery
    FOR EACH ROW EXECUTE FUNCTION audit.deny_modify();

CREATE TRIGGER account_recovery_no_delete
    BEFORE DELETE ON auth.account_recovery
    FOR EACH ROW EXECUTE FUNCTION audit.deny_modify();

-- Least-privilege app role: append + read-back of metadata only. No UPDATE/DELETE
-- (mirrors the audit_log grant pattern in migration 001). Guarded so the
-- migration also applies on databases provisioned without the vault_app role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT SELECT, INSERT ON auth.account_recovery TO vault_app;
        REVOKE UPDATE, DELETE ON auth.account_recovery FROM vault_app;
    END IF;
END $$;
