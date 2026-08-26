-- ============================================================================
-- 041: the admin plane can set a user's roles
-- ============================================================================
--
-- Roles reach auth.users at exactly one place today: POST /admin/users/import,
-- which writes them in the INSERT. After that they are frozen. There is no
-- route, no repository method and no grant that can change a live user's roles,
-- so an operator who imports a user with the wrong roles, or a platform that
-- promotes somebody after the import, has nowhere to go but SQL.
--
-- GET/POST/DELETE /admin/roles is the *catalog* -- the set of names that exist.
-- It has never been the assignment.
--
-- vault_admin holds SELECT on auth.users (001:455) and UPDATE on exactly three
-- columns: locked_until and failed_login_count (001:456) and must_reset_password
-- (039:141). 009 granted six more; 015:112 revoked all six and 015:105-108
-- records that what remains is the two from 001. PostgreSQL checks the column
-- privilege on every target an UPDATE names, so without this grant a
-- roles-writing statement fails with 42501 in any deployment running as the
-- real role -- and passes in the admin-plane tests, which drive the owner pool
-- where the grant is irrelevant. That is the shape 040 was written to fix for
-- refresh_tokens, one table over.
--
-- Column-scoped, like 039 and 040, and for the reason 037 records: a
-- column-level REVOKE is a silent no-op when a table-level grant exists, so the
-- absence of a table-level UPDATE here is what makes the narrow grant mean
-- something. vault_admin cannot reach email, password_hash, deleted or
-- mfa_required through this.
--
-- Not granted to vault_app. The main binary reads roles at token issuance and
-- has never written them; nothing on that side should start.
--
-- What this deliberately does not do is constrain the values. Migration 003
-- states there is no DB-level CHECK on role strings, and 005 keeps the catalog
-- in its own table rather than as an enum, so the invariants -- name shape,
-- catalog membership, admin-tier names refused -- live in Go where the error
-- messages are. A CHECK here would answer 23514 to a caller that deserves a
-- 400 naming the role.
--
-- Idempotent: GRANT is idempotent by definition, and the DO block only guards
-- against the role being absent, which is the shape 009, 015 and 040 use.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        GRANT UPDATE (roles) ON auth.users TO vault_admin;
    END IF;
END
$$;
