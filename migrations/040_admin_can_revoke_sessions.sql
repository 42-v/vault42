-- ============================================================================
-- 040: the admin plane can actually revoke the sessions it says it revokes
-- ============================================================================
--
-- POST /admin/users/{id}/lock ends with RevokeAllForUser, and the comment above
-- that call says the revocation is "what makes containment immediate": locking
-- an account stops it signing in again, and revoking its refresh families stops
-- the sessions it already holds. Only the first half has ever worked.
--
-- RevokeAllForUser is an UPDATE:
--
--   UPDATE auth.refresh_tokens SET revoked = TRUE
--    WHERE user_id = $1 AND revoked = FALSE
--
-- and vault_admin holds SELECT (001) and DELETE (009) on that table and no
-- UPDATE at all. So in any deployment running as the real role the statement
-- fails with 42501 and the operator is told the account is contained while every
-- issued session keeps rotating until its own expiry. It was invisible because
-- the admin-plane tests drive the owner pool, where the grant is irrelevant.
--
-- The grant is scoped to the one column the revocation writes. That is narrower
-- than the DELETE vault_admin already holds -- erasure hard-deletes these rows --
-- so this widens nothing: it lets the admin plane do the gentler of the two
-- things it is already permitted to do. Revoking leaves the row, and its family
-- and device linkage, for the audit trail; deleting does not, which is why the
-- lock path revokes rather than deletes.
--
-- Column-scoped rather than table-wide on purpose. 037 records that a
-- column-level REVOKE is a silent no-op when a table-level grant exists; the
-- converse is what makes this safe, because there is no table-level UPDATE here
-- for a column grant to be swallowed by. vault_admin cannot touch token_hash,
-- family_id, expires_at or used through this.
--
-- Idempotent: GRANT is idempotent by definition, and the DO block only guards
-- against the role being absent, which is the shape 009 and 015 already use.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        GRANT UPDATE (revoked) ON auth.refresh_tokens TO vault_admin;
    END IF;
END
$$;
