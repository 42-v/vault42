-- ============================================================================
-- 024: the privileged account-state columns of auth.users move one way, and two
--      of them stop moving for the application role at all
-- ============================================================================
--
-- 015 closed the tombstone columns (email, deleted, deleted_at) for vault_app and
-- said what was left. This is the rest of the set: banned, ban_reason, disabled,
-- email_verified and import_pending. Every one of them decides whether an account
-- may authenticate, and Login reads all five (internal/service/auth.go): banned
-- and disabled before the password is checked, import_pending instead of checking
-- it, email_verified after.
--
-- They arrived by accident rather than by decision. 004 added the account-state
-- columns for legacy-platform parity and granted vault_app UPDATE on all of them
-- in one line, and 006 added import_pending and granted it because one statement
-- clears it. Nobody asked which of those writes the running server actually makes.
--
-- A blanket REVOKE is wrong, which is why this is not one line. Two of the five
-- have a real writer in vault_app and would break with the grant:
--
--   * import_pending: UserRepo.ClearImportPending (user.go:73), reached from the
--     password-reset handler and the OAuth callback when an imported account is
--     claimed.
--   * email_verified: UserRepo.VerifyEmail (user.go:202), the whole of email
--     confirmation.
--
-- Both move in one direction only, and nothing anywhere moves either back. So the
-- rule is a transition rule, not a privilege rule, and it needs a trigger.
--
-- ----------------------------------------------------------------------------
-- Each column, and the direction it is allowed to move in
-- ----------------------------------------------------------------------------
--
-- banned, ban_reason, disabled -- no direction. The privilege comes off.
--
--     Nothing in the tree writes these by UPDATE. They are set once, at INSERT,
--     by UserRepo.CreateImported carrying the source system's account state, and
--     that runs on the admin gateway under vault_admin, which 012 granted INSERT
--     on auth.users. There is no ban endpoint and no unban endpoint. So 004's
--     grant is surplus, and surplus is exactly what a REVOKE is for: a guard on a
--     privilege nothing uses is a guard that has to be got right, where the
--     absence of the privilege cannot be got wrong.
--
--     What it costs the attacker is worth being precise about, because vault_app
--     keeps UPDATE (password_hash) and always will -- password change and reset
--     are its job -- so account takeover through this role is not what is being
--     closed here and cannot be. Two things that password_hash does not reach are:
--
--       * Lifting a ban. The account-state gate refuses a banned row before any
--         credential is read, so no amount of control over the hash opens it.
--       * Mass denial of service. One UPDATE with no WHERE bans or disables every
--         account in the deployment, and no code path can perform that write at
--         all, so nothing legitimate is measured against it.
--
--     ban_reason goes with them. It has no writer either, and leaving it behind
--     would let the recorded reason for a ban be rewritten while the ban stands,
--     which is evidence tampering on the one field that says why.
--
-- email_verified -- FALSE to TRUE only.
--
--     Confirming an address is vault_app's own work. The reverse has no writer,
--     and it is not merely untidy: an unverified row cannot log in (the gate
--     returns the same error as a wrong password, deliberately), and
--     linkableToExistingAccount refuses to attach a social identity to an
--     unverified account. Clearing the flag is therefore a per-account lockout
--     that also strips a working OAuth login, arriving from a role no operator
--     asked to do it.
--
-- import_pending -- TRUE to FALSE only.
--
--     An imported account is claimed once. Setting the flag on a claimed account
--     puts Login back on the import branch, where it ignores the password,
--     answers every attempt with invalid_credentials, and mails a claim link. The
--     account holder cannot clear that state from the outside, and the row looks
--     ordinary in every listing.
--
-- locked_until -- both directions. This was the gap 024 left open; migration 029
-- has since closed it.
--
--     The rule that fits is that locked_until belongs to the admin plane:
--     vault_admin sets a lock and clears one, and vault_app does not write the
--     column at all. At 024 that did not survive contact with the tree.
--     `vault lock-user` and `vault unlock-user` (internal/cli/cli.go,
--     lockUser/unlockUser) called UserRepo.LockUntil and UserRepo.Unlock, they
--     lived in cmd/vault, and cmd/vault opens its pool with cfg.DatabaseURL("app").
--     Clearing a live lock was therefore a path the vault_app role genuinely took,
--     on an operator's command, and a REVOKE here would have broken it.
--
--     That Go change has since landed. Both CLI subcommands are retired: they
--     print an error and issue no database write. Account containment runs on the
--     admin gateway via POST /admin/users/{id}/lock and /unlock, under vault_admin,
--     which holds UPDATE (locked_until, failed_login_count) from 001, is gated on
--     users:lock / users:unlock, audits the action and revokes the target's
--     sessions. With no vault_app writer left, migration 029 revokes
--     UPDATE (locked_until) from vault_app, narrowing this column the way the other
--     four above are narrowed. vault_app keeps UPDATE (failed_login_count).
--
-- ----------------------------------------------------------------------------
-- Why the trigger is not keyed on the role, when 023's is
-- ----------------------------------------------------------------------------
--
-- 023 has to ask who is writing, because a client row carrying mint:token is
-- legitimate from the admin plane and an escalation from the application role.
-- Here there is no such split. vault_admin holds no UPDATE privilege on
-- email_verified or import_pending at all, so it never reaches this trigger;
-- PostgreSQL refuses it with 42501 first. The rule left over is a plain statement
-- about the row -- a confirmed address stays confirmed, a claimed account stays
-- claimed -- which holds for whoever asks, including a role that does not exist
-- yet. Keying it on a role name would make it stop holding the moment somebody
-- adds one.
--
-- The same limits as 016, 017, 020, 023 and AR-14 apply. ALTER TABLE ... DISABLE
-- TRIGGER, session_replication_role = replica and TRUNCATE all bypass row
-- triggers, and the migration role holds them.
--
-- No audit row is written, for the reason 019 sets out: the RAISE aborts the
-- transaction and would take the INSERT with it. The trace is a RAISE WARNING in
-- the PostgreSQL log.
-- ============================================================================

-- Written bare rather than inside a pg_roles guard, the way 015 argues: 001
-- creates both roles unconditionally, and a statement nested in a DO block is
-- skipped by the integration fixture's applyRealGrants(), which would leave that
-- suite exercising the pre-024 privilege model.
REVOKE UPDATE (banned, ban_reason, disabled) ON auth.users FROM vault_app;

CREATE OR REPLACE FUNCTION auth.deny_account_state_regression() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.email_verified AND NOT NEW.email_verified THEN
        RAISE WARNING 'user:account_state_blocked column=email_verified user_id=% role=%',
            OLD.id, current_user;
        RAISE EXCEPTION 'account state transition denied: user % cannot have a confirmed email address un-confirmed', OLD.id;
    END IF;

    RAISE WARNING 'user:account_state_blocked column=import_pending user_id=% role=%',
        OLD.id, current_user;
    RAISE EXCEPTION 'account state transition denied: user % cannot be returned to import_pending once claimed', OLD.id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the whole condition, so every ordinary write to
-- auth.users reaches the table without entering plpgsql. Both columns are NOT
-- NULL, so there is no third state for the comparison to fall through.
--
-- auth.users carries no other row trigger, in 001 through 023, so this name
-- cannot reorder anything. Same-event triggers fire in name order, which 020
-- depends on for auth.signing_keys; nothing on this table does. The name follows
-- the <table>_<purpose> shape 017 and 020 established.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS users_account_state_transitions ON auth.users;
CREATE TRIGGER users_account_state_transitions
    BEFORE UPDATE ON auth.users
    FOR EACH ROW WHEN ((OLD.email_verified AND NOT NEW.email_verified)
                    OR (NOT OLD.import_pending AND NEW.import_pending))
    EXECUTE FUNCTION auth.deny_account_state_regression();
