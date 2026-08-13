-- ============================================================================
-- Migration 019: make a blocked role escalation actually leave a trace
--
-- auth.deny_role_escalation (001) and auth.deny_role_escalation_on_insert (016)
-- both tried to record the attempt before refusing it:
--
--     BEGIN
--         INSERT INTO audit.audit_log (...);
--     EXCEPTION WHEN OTHERS THEN
--         NULL;
--     END;
--     RAISE EXCEPTION 'role escalation denied: ...';
--
-- The INSERT never survives. The subtransaction commits it, and then the RAISE
-- aborts the statement that fired the trigger, which rolls the INSERT back with
-- everything else. A row cannot be persisted by a transaction that is about to
-- abort, so no arrangement of BEGIN and EXCEPTION around the INSERT can work.
--
-- The comment said the record of the attempt is worth having, which is right.
-- The mechanism could not deliver it, and the EXCEPTION WHEN OTHERS THEN NULL
-- guaranteed the failure was invisible: the audit write was already being
-- discarded on purpose, so nothing distinguished "never wrote a row" from
-- "wrote a row that was rolled back".
--
-- The effect was that an attempt to promote an admin above its creator was
-- blocked, correctly, and left nothing anywhere. The block is the loud part, but
-- the attempt is the interesting part, and it was the part that vanished.
--
-- RAISE WARNING carries the same fields and is not a row, so the abort does not
-- take it. It reaches the server log and the client immediately, which makes the
-- Postgres log the durable record rather than audit.audit_log.
--
-- That is a real reduction in where the evidence lands, and it is stated here
-- rather than papered over: the audit table cannot hold this event, because the
-- only transaction that knows about it is the one being aborted. Putting the row
-- in the audit table would need the application to catch the error and write it
-- from a transaction that commits, or an out-of-transaction channel such as
-- dblink. The first is the right answer and is a change to the Go layer, not to
-- this trigger.
--
-- The exception messages are unchanged. tests/attack matches on the text
-- 'role escalation denied', and no production code matches on either message or
-- SQLSTATE, so the text stays as the stable part of the contract.
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
            RAISE WARNING 'admin:role_escalation_blocked path=update admin_id=% username=% old_role=% new_role=%',
                OLD.id, OLD.username, OLD.role, NEW.role;
            RAISE EXCEPTION 'role escalation denied: cannot promote % → %', OLD.role, NEW.role;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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
        RAISE WARNING 'admin:role_escalation_blocked path=insert admin_id=% username=% old_role=% new_role=% created_by=%',
            NEW.id, NEW.username, creator_role, NEW.role, NEW.created_by;
        RAISE EXCEPTION 'role escalation denied: cannot create % above creator %', NEW.role, creator_role;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
