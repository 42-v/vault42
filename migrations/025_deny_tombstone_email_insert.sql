-- ============================================================================
-- 025: the erasure tombstone address becomes terminal against INSERT, not only
--      against UPDATE
-- ============================================================================
--
-- 015 established the invariant that auth.users.email in the erasure tombstone
-- domain has exactly one legitimate writer, auth.erase_user_identity(), and that
-- no application role may point an account at that address by any other route. It
-- enforced the invariant against UPDATE: it revoked UPDATE (email) from vault_app
-- and vault_admin and moved the one legitimate write behind a SECURITY DEFINER
-- function. It did not enforce it against INSERT, and INSERT is the other half.
--
-- 001 grants vault_app SELECT, INSERT, DELETE on auth.users so registration can
-- create rows, and email is a UNIQUE column. That is a squat primitive. A holder
-- of the vault_app role -- a SQL injection that reaches an INSERT on auth.users,
-- or a compromised application node -- can pre-occupy a victim's future tombstone
-- address before the victim is ever erased:
--
--     INSERT INTO auth.users (id, email)
--     VALUES (<attacker row>, 'deleted-<victim id>@deleted.invalid')
--
-- When the victim is later erased, auth.erase_user_identity() runs
--
--     UPDATE auth.users SET email = 'deleted-<victim id>@deleted.invalid'
--      WHERE id = <victim id>
--
-- which now collides on the unique email index and raises 23505. The erasure
-- fails, the Art. 17 request cannot complete, and the victim's personal data is
-- retained. It is the exact denial of service 015 argued the tombstone must be
-- immune to, reached through the one grant 015 left standing.
--
-- The application layer already refuses this domain: sanitize.Email turns away
-- the deleted.invalid domain at Register, at the OAuth callback and at import. But
-- sanitize runs in Go, and the write above reaches PostgreSQL as vault_app without
-- passing through it. 015's own reasoning is why that matters: every tier reaches
-- the database as the same login, so a check that lives only above the database is
-- not a check the database enforces. This migration makes the database enforce the
-- same rule the application already states, which is where the tombstone invariant
-- belongs.
--
-- Shape of the guard. A BEFORE INSERT trigger on auth.users that refuses any row
-- whose email lies in the deleted.invalid domain -- the domain the running server
-- actually tombstones into (internal/service/erasure.go builds
-- "deleted-<id>@deleted.invalid") and the exact domain sanitize.Email refuses. The
-- domain is matched on the substring after the last '@', case-insensitively, the
-- same way sanitize.Email reads it, so the local part is irrelevant: nothing may
-- be inserted into that domain, which is a strict superset of the victim-targeted
-- address and blocks the squat whatever local part it carries.
--
-- Why this breaks nothing legitimate:
--
--   * .invalid is RFC 2606 reserved and can never be a deliverable address, so no
--     genuine registration, import or OAuth link ever carries one. sanitize.Email
--     already refuses it above; this only closes the path that bypasses sanitize.
--   * Erasure writes the tombstone with UPDATE, through auth.erase_user_identity().
--     A BEFORE INSERT trigger never sees an UPDATE, so the one write that is
--     supposed to reach this domain is untouched. The account row is scrubbed in
--     place and never deleted and re-inserted, so no legitimate INSERT ever needs
--     this domain.
--
-- The trigger is not keyed on the role, for the reason 024 gives for its own: the
-- rule is a plain statement about the row -- this domain is reserved to the
-- erasure function -- that holds for whoever asks, including the migration role
-- and a role that does not exist yet. Keying it on a role name would make it stop
-- holding the moment somebody adds one. The migration role's bypasses are the same
-- as every other row trigger in this tree (016, 017, 020, 023, 024): ALTER TABLE
-- ... DISABLE TRIGGER, session_replication_role = replica and TRUNCATE. None of
-- them is a path the application role can take.
--
-- No EXECUTE grant is written. PostgreSQL runs a trigger function regardless of
-- the invoking role's privileges on it, and this one touches no table, so it needs
-- none. That also keeps it out of the integration fixture's applyRealGrants()
-- entirely: there is nothing here for stripRoleGrants() to strip.
--
-- No audit row is written, for the reason 019 and 024 set out: the RAISE aborts
-- the transaction and would take any audit INSERT with it. The trace is a
-- RAISE WARNING in the PostgreSQL log.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.deny_tombstone_email_insert() RETURNS TRIGGER AS $$
BEGIN
    RAISE WARNING 'user:tombstone_insert_blocked email=% role=%', NEW.email, current_user;
    RAISE EXCEPTION 'insert into auth.users refused: % is in the erasure tombstone domain, which only auth.erase_user_identity() may write',
        NEW.email
        USING ERRCODE = 'invalid_parameter_value';
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the whole condition, so every ordinary registration
-- reaches the table without entering plpgsql. email is NOT NULL (001), so there is
-- no third state for the comparison to fall through. The substring pattern takes
-- the run of non-'@' characters at the end of the address, which is the domain
-- after the last '@', matching sanitize.Email's LastIndexByte read.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form. auth.users carries one other row
-- trigger, 024's BEFORE UPDATE; this one is BEFORE INSERT, so the two never share
-- an event and their firing order is not a question.
DROP TRIGGER IF EXISTS users_no_tombstone_email_insert ON auth.users;
CREATE TRIGGER users_no_tombstone_email_insert
    BEFORE INSERT ON auth.users
    FOR EACH ROW WHEN (lower(substring(NEW.email FROM '[^@]*$')) = 'deleted.invalid')
    EXECUTE FUNCTION auth.deny_tombstone_email_insert();
