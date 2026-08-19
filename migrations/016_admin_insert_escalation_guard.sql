-- ============================================================================
-- 016: the admin role-escalation guard covers INSERT
-- ============================================================================
--
-- 001 installs auth.deny_role_escalation as a BEFORE UPDATE trigger on
-- auth.admin_users. It reads OLD.role, compares ranks, and refuses a promotion.
-- The three ways to end up with a super_admin row are:
--
--   * UPDATE an existing row's role upward       -> the trigger fires, refused.
--   * INSERT ... ON CONFLICT DO UPDATE, role up  -> fires the UPDATE trigger, refused.
--   * INSERT a brand-new super_admin row         -> no trigger at all. Accepted.
--
-- The gateway connects as vault_admin, which 001 grants full INSERT on
-- auth.admin_users, so the third path needs no privilege the role does not
-- already hold. Nobody has to promote the row the trigger is watching. They
-- write a new one next to it, with a password hash they picked, and log in as
-- it. DELETE-then-INSERT of one's own row is the same gap reached differently.
--
-- The guard below closes it with a rule the database can check on its own: an
-- admin row may not outrank its own creator.
--
-- Go does not check that rule, and being exact about it matters, because the
-- natural reading is that the trigger duplicates a handler check. POST
-- /admin/admins is gated on the admins:create permission, validates the
-- requested role with rbac.IsValidRole, and records the acting admin in
-- created_by. adminapi.CreateAdmin compares no ranks, and no other Go path does
-- either. What holds the invariant above the database is narrower than a check:
-- admins:create belongs to super_admin alone, so a creator is always the top
-- tier and cannot be outranked by whatever role it asks for.
--
-- The distinction decides what moving that grant would mean. Giving
-- admins:create to operator reads as widening what operator may create. With no
-- rank comparison in Go it is not a widening: an operator holding it could
-- create a super_admin and log in as it, which is escalation to the top tier,
-- and this trigger is the only thing that would refuse it.
--
-- Stated as a data invariant the rule is checkable and has no exceptions to
-- argue about:
--
--   * created_by set    -> the creator must exist and must rank at or above the
--                          role being created.
--   * created_by NULL   -> only while auth.admin_users is empty. That is
--                          EnsureFirstAdmin on first boot, the one admin in a
--                          deployment that genuinely has no creator to name.
--                          Afterwards an unattributed admin row is refused, so
--                          the rule cannot be sidestepped by simply omitting the
--                          column.
--
-- seed.RunAdmins used to insert with created_by NULL and now records the
-- highest-ranked existing admin, because a seed file names a role but no actor
-- and the deployment owner who applies it is exactly that admin.
--
-- What this does NOT do, stated plainly because 001 claimed otherwise. 001
-- introduces the UPDATE trigger as "even if SQL injection reaches the DB, a
-- lower-ranked admin cannot promote themselves to a higher rank". That holds for
-- UPDATE, where the ceiling is OLD.role and comes from the row rather than from
-- the statement. It cannot hold for INSERT, where every value is supplied by the
-- statement: vault_admin holds SELECT on auth.admin_users, so anything that can
-- write the table can first read a real super_admin's id and name it in
-- created_by. This trigger raises the cost of that from one INSERT to a SELECT
-- and an INSERT. It is not a boundary, and it does not make the database safe to
-- reach. The control that actually holds is that every admin-plane query is
-- parameterised. A hard boundary would need one database login per admin rank,
-- which the single shared vault_admin login rules out by construction. The claim
-- has been corrected in 001, docs/admin-gateway.md and docs/security.md (AR-14).
--
-- Where it does earn its keep is the failure this release cannot otherwise
-- detect: an RBAC regression in Go that lets a viewer-ranked session create a
-- super_admin now fails at the database instead of shipping quietly, and every
-- admin row in an existing deployment can be audited against the invariant.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.deny_role_escalation_on_insert() RETURNS TRIGGER AS $$
DECLARE
    new_rank     INTEGER;
    creator_rank INTEGER;
    creator_role TEXT;
BEGIN
    SELECT rank INTO new_rank FROM auth.admin_roles WHERE role = NEW.role;
    IF new_rank IS NULL THEN
        RAISE EXCEPTION 'role escalation denied: % is not a known admin role', NEW.role;
    END IF;

    IF NEW.created_by IS NULL THEN
        IF EXISTS (SELECT 1 FROM auth.admin_users) THEN
            RAISE EXCEPTION 'role escalation denied: admin % cannot be created without a creator once an admin exists', NEW.username;
        END IF;
        RETURN NEW; -- first boot: nobody exists who could have authorised this
    END IF;

    SELECT r.role, r.rank INTO creator_role, creator_rank
      FROM auth.admin_users a
      JOIN auth.admin_roles r ON r.role = a.role
     WHERE a.id = NEW.created_by;

    IF creator_rank IS NULL THEN
        RAISE EXCEPTION 'role escalation denied: creator % does not exist', NEW.created_by;
    END IF;

    IF new_rank > creator_rank THEN
        -- Same best-effort shape as the UPDATE trigger: the record of the attempt
        -- is worth having, and a failure to write it must not swallow the block.
        BEGIN
            INSERT INTO audit.audit_log (id, event_type, metadata)
            VALUES (
                gen_random_uuid(),
                'admin:role_escalation_blocked',
                jsonb_build_object(
                    'admin_id', NEW.id,
                    'username', NEW.username,
                    'old_role', creator_role,
                    'new_role', NEW.role,
                    'created_by', NEW.created_by,
                    'path', 'insert'
                )
            );
        EXCEPTION WHEN OTHERS THEN
            NULL;
        END;
        RAISE EXCEPTION 'role escalation denied: cannot create % above creator %', NEW.role, creator_role;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs
-- on any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS admin_users_no_escalation_insert ON auth.admin_users;
CREATE TRIGGER admin_users_no_escalation_insert
    BEFORE INSERT ON auth.admin_users
    FOR EACH ROW EXECUTE FUNCTION auth.deny_role_escalation_on_insert();
