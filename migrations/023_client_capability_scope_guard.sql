-- ============================================================================
-- 023: a capability scope reaches a client row through the admin plane only
-- ============================================================================
--
-- 001 line 326 grants vault_app SELECT and INSERT on auth.clients, commented
-- "seeding creates clients at startup". auth.clients.scopes is a plain TEXT[]
-- with no constraint, no catalog and no check. So the grant is not "may register
-- an application", it is "may write any authorization this service recognizes":
--
--   INSERT INTO auth.clients (id, name, secret_hash, role, scopes, active, ...)
--   VALUES (gen_random_uuid(), 'not-a-backdoor', '<hash of a secret I chose>',
--           'service', ARRAY['mint:token','kms:unwrap'], TRUE, ...);
--
-- and then POST /client/token with that secret. ClientHandler.Token reads active,
-- verifies the secret against the hash in the row, and issues a token carrying
-- the row's scopes verbatim. RequireScope compares those strings exactly, so the
-- token opens POST /mint and POST /kms/unwrap.
--
-- That is the largest single step available to anything holding this role. It
-- turns "can write application tables" into "can assert any subject to every
-- relying party in the estate, and can open every envelope the KMS oracle will
-- decrypt". It is also the step that converts a defect with no network reach, a
-- SQL injection sink, into a bearer credential usable from outside the database.
--
-- ----------------------------------------------------------------------------
-- What MintAllowedScopes does, and why it is not this
-- ----------------------------------------------------------------------------
--
-- VAULT_MINT_SCOPES and the service.mintDeniedScopes list behind it are read
-- inside MintService, on the way OUT of POST /mint: they bound what a minted
-- token may carry. Nothing reads them on the way IN to a client row, and the two
-- questions are not the same one. mintDeniedScopes stops a mint holder from
-- pivoting onto the privileged endpoints; it has no opinion about how the mint
-- holder came to hold mint:token, which is the question here.
--
-- ----------------------------------------------------------------------------
-- Which scopes are privileged
-- ----------------------------------------------------------------------------
--
-- auth.capability_scopes() below names them, and it is exactly the set Go
-- refuses to mint, because both answer one question: which scope names are
-- vault42's own capabilities rather than an application's.
--
--   * mint:token   -- POST /mint. Signs an assertion about a subject vault42
--                     never authenticated. AR-16 is the whole exposure.
--   * kms:unwrap   -- POST /kms/unwrap. Opens envelopes under the master key.
--   * svcdoc:read  -- the service document store, reachable over the network.
--   * svcdoc:write
--   * admin, admin:read, admin:write -- no route gates on these today. They are
--                     in the Go list as reserved names and are here for the same
--                     reason: if a route ever claims one, the database is already
--                     refusing to hand it out, rather than acquiring the guard a
--                     release later.
--
-- The set is duplicated between Go and SQL, which is a drift risk, so it is
-- pinned: tests/spec/capability_scope_parity_test.go fails the build when
-- mintDeniedScopes and auth.capability_scopes() stop agreeing. Deriving one from
-- the other is not available -- the trigger cannot call into the process, and the
-- process would have to query the database before it could refuse anything.
--
-- Matching is exact membership, not prefix. That mirrors RequireScope, which
-- compares whole strings: "kms:unwrap:readonly" does not open kms:unwrap, and a
-- guard that treated it as privileged would refuse a name the endpoints ignore.
--
-- ----------------------------------------------------------------------------
-- Why this is a trigger and not a REVOKE
-- ----------------------------------------------------------------------------
--
-- PostgreSQL does have column-level INSERT, so REVOKE INSERT (scopes) ON
-- auth.clients FROM vault_app looks like the whole answer. It is not, for the
-- same reason 015 had to move a statement before it could move a grant: the
-- privilege is checked against the columns a statement NAMES, not the values it
-- writes. ClientRepo.Create lists scopes in every INSERT, including the ones
-- carrying nothing but user:read, so the column REVOKE would refuse ordinary
-- seeding too and take declarative seeding out with it. 015 could fix that by
-- dropping email from the SET clause; here the column is the point of the
-- statement and cannot leave it.
--
-- The trigger is therefore keyed on the value, and on who is writing it. That
-- second half is unusual in this tree and is deliberate: the row is legitimate
-- when the admin plane writes it and an escalation when the application role
-- does, so there is nothing about the row alone that separates the two.
--
-- ----------------------------------------------------------------------------
-- The seed path, and why it does not need a carve-out
-- ----------------------------------------------------------------------------
--
-- cmd/vault calls seed.Run under vault_app, so a VAULT_SEED_FILE listing
-- mint:token on a client now fails at startup, loudly, naming the scope. That is
-- the intended outcome rather than a casualty of it.
--
-- A privileged client has a complete alternative writer, and it has had one since
-- 001: POST /admin/clients runs under vault_admin, which keeps INSERT and UPDATE
-- here (001 line 459). It is gated on the clients:create permission, which
-- belongs to super_admin alone, and it writes an admin:client_create audit row
-- naming the acting admin. Creating a mint or KMS credential is exactly the kind
-- of act that should carry an actor and an audit row, and the seed file carries
-- neither: it names a capability and no authority for it, and the process that
-- reads it is the one the threat model treats as semi-hostile.
--
-- So the answer to "does the seed path need to create privileged clients" is no,
-- and the loss is one convenience: a deployment that wants a mint client from a
-- file now creates it through the gateway instead. Ordinary seeding is untouched,
-- which is what the 001 grant was actually for.
--
-- `vault add-client --scopes` is affected the same way and for the same reason:
-- the CLI subcommands live in cmd/vault and share its pool, so add-client is
-- vault_app writing a client row. Its siblings show where this was already
-- heading. `vault revoke-client` calls ClientRepo.Deactivate and
-- `vault rotate-client-secret` calls ClientRepo.Update, both of which are UPDATE
-- statements on a table vault_app has never held UPDATE on, so both have failed
-- with 42501 in every deployment since 001. Client mutation from cmd/vault was
-- never wired to a role that could carry it out; this migration takes the one
-- privileged case of the one command that still worked and points it at the plane
-- the working paths already use.
--
-- A first-boot carve-out on the model of 016 was considered and rejected, and the
-- difference is worth stating because the two situations look alike. 016 lets an
-- admin row through with created_by NULL while auth.admin_users is empty, and
-- that carve-out is safe because it closes by itself: EnsureFirstAdmin runs at
-- every gateway boot, so the table becomes non-empty on the first start and the
-- window never reopens. auth.clients has no equivalent. A deployment that seeds
-- no clients leaves the table empty forever, so "empty means first boot" would
-- leave the escalation permanently available on exactly the deployments that
-- never registered a client -- and an attacker holding vault_app can read the
-- table and knows when the window is open. A carve-out that never closes is not a
-- carve-out.
--
-- ----------------------------------------------------------------------------
-- Scope of the guard
-- ----------------------------------------------------------------------------
--
-- UPDATE is covered as well as INSERT, though vault_app holds no UPDATE on this
-- table today and cannot reach it: PostgreSQL refuses the statement with 42501
-- before any trigger runs, and ON CONFLICT DO UPDATE needs the same privilege.
-- 017 covered DELETE on the same reasoning, that it guards a future grant rather
-- than a present hole, and the cost here is likewise nothing.
--
-- The same limits as 016, 017, 020 and AR-14 apply and are not papered over.
-- ALTER TABLE ... DISABLE TRIGGER, session_replication_role = replica and TRUNCATE
-- all bypass row triggers, and the migration role holds them. This closes the path
-- available to the two least-privilege roles the services connect as.
--
-- No audit row is written. 019 established why: the RAISE aborts the transaction
-- and takes any INSERT in it down too, so the record of an attempt is a RAISE
-- WARNING in the PostgreSQL log.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.capability_scopes() RETURNS TEXT[] AS $$
    SELECT ARRAY[
        'mint:token',
        'kms:unwrap',
        'svcdoc:read',
        'svcdoc:write',
        'admin',
        'admin:read',
        'admin:write'
    ]::TEXT[];
$$ LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp;

-- EXECUTE stays with PUBLIC, which is the one place this migration does not
-- follow 015. The trigger below runs with the privileges of whoever issues the
-- INSERT, and its WHEN clause calls this function, so a role without EXECUTE
-- would be refused with 42501 on every write to auth.clients including the
-- ordinary ones. The function returns a constant list of scope names already
-- published in docs/api.md, so there is nothing to withhold.

CREATE OR REPLACE FUNCTION auth.deny_client_capability_scope() RETURNS TRIGGER AS $$
DECLARE
    admin_plane BOOLEAN;
    requested   TEXT[];
BEGIN
    -- Membership rather than a name comparison, so a deployment that reaches the
    -- gateway through a role granted vault_admin is judged the same as one
    -- connecting as vault_admin itself. The lookup goes through pg_roles rather
    -- than pg_has_role(current_user, 'vault_admin', 'USAGE') directly because
    -- that form raises when the role does not exist, and an error here would be
    -- indistinguishable from the refusal. A missing role yields NULL, which
    -- COALESCE turns into a refusal: fail closed.
    SELECT pg_has_role(current_user, r.oid, 'USAGE') INTO admin_plane
      FROM pg_roles r
     WHERE r.rolname = 'vault_admin';

    IF COALESCE(admin_plane, FALSE) THEN
        RETURN NEW;
    END IF;

    SELECT array_agg(s ORDER BY s) INTO requested
      FROM unnest(NEW.scopes) AS s
     WHERE s = ANY (auth.capability_scopes());

    RAISE WARNING 'client:capability_scope_blocked role=% client_id=% name=% scopes=%',
        current_user, NEW.id, NEW.name, requested;
    RAISE EXCEPTION 'capability scope denied: % may not grant % to client % (admin plane only)',
        current_user, requested, NEW.name;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The WHEN clause carries the structural half of the condition, so an ordinary
-- client row never enters plpgsql and seeding pays nothing for this guard. The
-- role test cannot live there: it needs the pg_roles lookup above, and a WHEN
-- clause may not contain a subquery.
--
-- auth.clients carries no other row trigger, in 001 through 022, so this name
-- cannot reorder anything. Same-event triggers fire in name order, which 020
-- depends on for auth.signing_keys; nothing on this table does. The name follows
-- the <table>_<purpose> shape 017 and 020 established, so a later trigger on
-- auth.clients has a predictable neighbour to sort against.
--
-- DROP + CREATE rather than CREATE OR REPLACE TRIGGER so the migration re-runs on
-- any server old enough to lack the replace form.
DROP TRIGGER IF EXISTS clients_capability_scope_guard ON auth.clients;
CREATE TRIGGER clients_capability_scope_guard
    BEFORE INSERT OR UPDATE ON auth.clients
    FOR EACH ROW WHEN (NEW.scopes && auth.capability_scopes())
    EXECUTE FUNCTION auth.deny_client_capability_scope();
