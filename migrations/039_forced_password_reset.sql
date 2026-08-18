-- ============================================================================
-- 039: an account can be told to reset its password before it signs in again
-- ============================================================================
--
-- A migration from a legacy platform arrives with password hashes vault42 cannot
-- verify: a bcrypt, an MD5, a scheme with a pepper nobody kept. VerifyPassword
-- parses Argon2id and nothing else, so those accounts answer every correct
-- password with invalid_credentials and no explanation, forever. 006 solved the
-- narrower case where the import carries no credential at all -- import_pending
-- means "there is no password here yet, claim the account" -- and it is one-way
-- by construction: an account is claimed once.
--
-- must_reset_password is the general form of the same idea: this account's stored
-- password must not be used again, whatever the reason, and the account holder is
-- to be sent a reset link. The legacy hash is the motivating case and not the only
-- one -- an operator with evidence that a credential is compromised wants the same
-- state -- so unlike import_pending this one moves in both directions, and an
-- account may enter it more than once.
--
-- ----------------------------------------------------------------------------
-- Why the column is not simply granted to vault_app
-- ----------------------------------------------------------------------------
--
-- Two roles touch it, in opposite directions, and the direction is what decides
-- who may write:
--
--   * Clearing it is the application role's own work. The password-reset confirm
--     handler (internal/handler/password.go) runs in the web server under
--     vault_app, and clearing the flag is part of the same event that writes the
--     new password_hash. Without the privilege a completed reset could never lift
--     the flag, and the account would be refused password login permanently --
--     the exact failure this feature exists to end.
--
--   * Setting it is an administrative act with the blast radius of a ban. One
--     UPDATE with no WHERE refuses the password login of every account in the
--     deployment and puts a reset mail in front of all of them, which is 024's
--     argument for taking banned and disabled off vault_app, restated. No
--     vault_app code path sets this column; the login branch that reads it only
--     reads it.
--
-- So the rule is a transition rule keyed on the role, and it needs a trigger. A
-- column-level REVOKE cannot express it: the privilege is checked against the
-- columns a statement names, not the values it writes, so revoking UPDATE would
-- take the clear with it. This is the same shape as 023, which is the other
-- guard in the tree that has to ask who is writing, and for the same reason: the
-- row alone does not separate the legitimate write from the escalation.
--
-- 024's guard is left alone rather than extended. Its function refuses two
-- one-way regressions -- a confirmed address cannot be un-confirmed, a claimed
-- import cannot be re-armed -- and both hold for whoever asks, which is why 024
-- deliberately does not look at the role. This column is not one-way and the
-- rule is not about direction alone, so folding it into that WHEN clause would
-- either forbid the operator's legitimate write or force 024's role-blind
-- function to grow a role test it was written to avoid.
--
-- ----------------------------------------------------------------------------
-- The admin plane's grant, and its writer
-- ----------------------------------------------------------------------------
--
-- vault_admin gains UPDATE (must_reset_password), joining the
-- UPDATE (locked_until, failed_login_count) 001 gave it. That is the pairing 024
-- named for locked_until and 029 completed: an account-state flag that contains
-- an account belongs to the plane that runs behind mTLS on loopback, authorizes
-- on a permission, and writes an audit row naming the acting admin.
--
-- The gateway's own INSERT path already carries the flag: POST /admin/users/import
-- writes it with the row (UserRepo.CreateImported), which is the migration case
-- and needs no UPDATE at all. The operator verb that flips it on an account that
-- already exists is a new admin route, and it lands with the change that
-- documents it -- the route inventories in docs/ are machine-checked against the
-- registered routes, so the handler and its documentation are one commit and not
-- this one. The privilege is granted here because it belongs to the column
-- rather than to that route: without it the guard below has no path to allow and
-- the operator half of the feature would need a second migration to become
-- reachable.
--
-- ----------------------------------------------------------------------------
-- What is deliberately left open
-- ----------------------------------------------------------------------------
--
-- vault_app can clear the flag whenever it likes, not only after a password was
-- actually rewritten. Nothing in SQL can tie the two: both writes are ordinary
-- UPDATEs from the same role, and a statement that sets password_hash and clears
-- the flag together is indistinguishable from one that only clears it.
--
-- The exposure is bounded and worth stating rather than papering over. Clearing
-- the flag restores the ordinary password gate, it does not open it: the account
-- still has to present a password that verifies against the stored hash, and for
-- the legacy-import case there is no such password, so the account stays shut.
-- What it does cost is the operator's forced reset on an account whose current
-- password is believed compromised -- a vault_app that can clear the flag can
-- keep that password usable. The containment lever for exactly that case is
-- POST /admin/users/{id}/lock, which vault_app has not been able to write since
-- 029, and which refuses the login before any credential is read.
--
-- The same limits as 016, 017, 020, 023, 024 and 026 apply and are not papered
-- over. ALTER TABLE ... DISABLE TRIGGER, session_replication_role = replica and
-- TRUNCATE all bypass row triggers, and the migration role holds them. No audit
-- row is written, for 019's reason: the RAISE aborts the transaction and would
-- take the write with it, so the trace is a RAISE WARNING in the PostgreSQL log.
--
-- ----------------------------------------------------------------------------
-- login:status joins the capability scopes
-- ----------------------------------------------------------------------------
--
-- The refusal this flag produces is not visible to the caller. An unauthenticated
-- login on a flagged account answers 401 invalid_credentials, byte for byte what
-- a wrong password answers, because a distinct status would tell whoever asked
-- that the address is registered and what state it is in (ASVS V2.1.1, and the
-- lesson 006's claim branch already learned). The distinct status exists for a
-- first-party client that has authenticated with client credentials, and vault42
-- authorizes that kind of trust on scopes: login:status is the new one.
--
-- It is a vault42 capability rather than an application's own vocabulary, so it
-- joins the set auth.capability_scopes() names and Go refuses to mint. A client
-- row carrying it can distinguish a registered flagged account from an unknown
-- address, so it reaches the estate through POST /admin/clients, under
-- vault_admin, with an audit row naming the admin -- and not through a seed file
-- that names a capability and no authority for it. The function is redefined
-- rather than the trigger changed: 023's WHEN clause calls it, so the guard picks
-- the new name up with no second copy of the list.
--
-- ----------------------------------------------------------------------------
-- Live data and locks
-- ----------------------------------------------------------------------------
--
-- ADD COLUMN ... NOT NULL DEFAULT FALSE stores the default in the catalog on
-- PostgreSQL 11 and later, so it takes ACCESS EXCLUSIVE for the length of a
-- catalog update and rewrites no rows. Every existing account reads FALSE, which
-- is the state they are in: nobody has asked any of them to reset.
-- ============================================================================

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS must_reset_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Written bare rather than inside a pg_roles guard, the way 015, 024 and 029
-- argue: 001 creates both roles unconditionally, and a statement nested in a DO
-- block is skipped by the integration fixture's applyRealGrants(), which would
-- leave that suite exercising a privilege model this migration never wrote.
GRANT UPDATE (must_reset_password) ON auth.users TO vault_app;
GRANT UPDATE (must_reset_password) ON auth.users TO vault_admin;

CREATE OR REPLACE FUNCTION auth.deny_forced_password_reset_set() RETURNS TRIGGER AS $$
DECLARE
    admin_plane BOOLEAN;
BEGIN
    -- Membership rather than a name comparison, so a deployment that reaches the
    -- gateway through a role granted vault_admin is judged the same as one
    -- connecting as vault_admin itself. The lookup goes through pg_roles rather
    -- than pg_has_role(current_user, 'vault_admin', 'USAGE') directly because that
    -- form raises when the role does not exist, and an error here would be
    -- indistinguishable from the refusal. A missing role yields NULL, which
    -- COALESCE turns into a refusal: fail closed. This is 023's test, verbatim,
    -- because it is the same question.
    SELECT pg_has_role(current_user, r.oid, 'USAGE') INTO admin_plane
      FROM pg_roles r
     WHERE r.rolname = 'vault_admin';

    IF COALESCE(admin_plane, FALSE) THEN
        RETURN NEW;
    END IF;

    RAISE WARNING 'user:forced_password_reset_blocked user_id=% role=%', OLD.id, current_user;
    RAISE EXCEPTION 'forced password reset denied: % may not set must_reset_password on user % (admin plane only)',
        current_user, OLD.id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the direction, so clearing the flag and every other
-- write to auth.users reaches the table without entering plpgsql, and only the
-- one transition that needs a role test pays for one. The column is NOT NULL, so
-- there is no third state for the comparison to fall through.
--
-- The name sorts after 024's users_account_state_transitions, which is the only
-- other row trigger on this table. Same-event triggers fire in name order; both
-- of these raise, so the order decides only which message a write refused by both
-- reports, and 024's is the more specific of the two in that case. The name
-- follows the <table>_<purpose> shape 017 and 020 established.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS users_forced_password_reset_scope ON auth.users;
CREATE TRIGGER users_forced_password_reset_scope
    BEFORE UPDATE ON auth.users
    FOR EACH ROW WHEN (NOT OLD.must_reset_password AND NEW.must_reset_password)
    EXECUTE FUNCTION auth.deny_forced_password_reset_set();

-- The capability list gains login:status. Redefining the function is the whole
-- change: 023's trigger calls it from its WHEN clause, and
-- tests/spec/capability_scope_parity_test.go pins this list against
-- service.mintDeniedScopes, which gains the same name in the same commit.
CREATE OR REPLACE FUNCTION auth.capability_scopes() RETURNS TEXT[] AS $$
    SELECT ARRAY[
        'mint:token',
        'kms:unwrap',
        'svcdoc:read',
        'svcdoc:write',
        'login:status',
        'admin',
        'admin:read',
        'admin:write'
    ]::TEXT[];
$$ LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp;
