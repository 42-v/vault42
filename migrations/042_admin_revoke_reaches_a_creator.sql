-- ============================================================================
-- 042: an admin who created another admin can still be revoked
-- ============================================================================
--
-- POST /admin/admins/{id}/revoke could not revoke any admin who had created
-- another admin. 001:252 declares
--
--     created_by UUID REFERENCES auth.admin_users(id)
--
-- with no ON DELETE clause, so the default NO ACTION applies, and
-- AdminUserRepo.Revoke is a bare DELETE. Deleting a row that another row still
-- names raises 23503 and the whole statement fails: the account stays, and so
-- do its live sessions -- admin_sessions.admin_id cascades (001:257), but only
-- if the parent delete succeeds, and it does not.
--
-- created_by is never null in practice. adminapi/handler.go sets it on every
-- create and 016:84-88 raises when it is null once any admin exists, so the
-- admin graph is a tree. The bootstrap super_admin becomes unrevokable the
-- moment it creates one other admin, which is the first thing an operator does.
--
-- That matters more than an ordinary 500 because revoke is the only containment
-- lever there is. adminapi/router.go:125-128 is the entire admin-management
-- surface: list, create, revoke. There is no admin update, no admin lock and no
-- per-admin-session revoke, so an admin whose credentials are known to be
-- compromised cannot be stopped at all.
--
-- The existing coverage passes because it only ever revokes a leaf:
-- tests/integration/postgres_admin_test.go sets target.CreatedBy = admin.ID and
-- revokes the target, never the creator.
--
-- SET NULL rather than CASCADE, deliberately. CASCADE would delete the revoked
-- admin's entire created subtree -- revoking one compromised account would
-- silently remove every account it had ever created, which is a far worse
-- outcome than the bug. SET NULL costs provenance on the children instead, and
-- RevokeAdmin now writes the old created_by into the audit metadata so the
-- answer to "who authorized this account" survives in the trail.
--
-- Neither role-escalation trigger fires on this. deny_role_escalation_on_insert
-- is BEFORE INSERT only (016:129-132) and deny_role_escalation short-circuits
-- unless the role changes (001:394-428); an FK-driven SET NULL touches neither.
--
-- Idempotent: the DROP is conditional and the ADD follows it, so re-running
-- lands on the same constraint.

ALTER TABLE auth.admin_users DROP CONSTRAINT IF EXISTS admin_users_created_by_fkey;

ALTER TABLE auth.admin_users
    ADD CONSTRAINT admin_users_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES auth.admin_users(id) ON DELETE SET NULL;
