-- ============================================================================
-- Migration 021: one credential id belongs to one credential
--
-- WebAuthn level 2, 7.1 step 17 requires a relying party to refuse a credential
-- id it has already registered. vault42 did not check, and the column carried no
-- unique constraint: auth.webauthn_credentials had only idx_webauthn_credentials
-- _user on user_id, so two rows could hold the same credential_id.
--
-- Attestation conveyance is 'none', so the credential id inside the attested
-- credential data is chosen by whoever builds the authenticator, and a soft
-- authenticator emits whatever 32 bytes it likes. The victim's ids are not
-- secret either: POST /auth/2fa/webauthn/verify/begin returns them in
-- allowCredentials. So the collision is selected, not stumbled into.
--
-- Nothing authenticates by credential id alone today. Every production lookup
-- goes through ListByUser and then checks ownership, which is why this is a trap
-- rather than a live bypass. It springs the moment a discoverable or passkey
-- login path is added, because that path looks a credential up by id with no
-- user in hand, and a duplicate decides which public key answers.
--
-- The handler now refuses a duplicate at registration. That check reads and then
-- writes, so two concurrent registrations can both read "no duplicate" and both
-- insert. Only the index closes that window, which is the whole reason this
-- migration exists alongside the handler change rather than instead of it.
--
-- CONCURRENTLY is not used. internal/migrate runs each file inside a single
-- transaction, and CREATE INDEX CONCURRENTLY cannot run in a transaction block.
-- The table is small (one row per enrolled authenticator) so the ACCESS
-- EXCLUSIVE lock a plain CREATE INDEX takes is brief.
--
-- The duplicate check runs first and by hand. A bare CREATE UNIQUE INDEX on a
-- table that already holds duplicates fails with Postgres naming one key value,
-- which aborts the migration and, because migrations run at startup, stops the
-- server with an error an operator has to reverse-engineer. Deciding which of
-- two colliding credentials to delete is a security decision about someone's
-- second factor, so this refuses and reports rather than choosing. It lists the
-- offending ids so the operator can look at both rows before removing either.
-- ============================================================================

DO $$
DECLARE
    dupes TEXT;
BEGIN
    SELECT string_agg(encode(credential_id, 'hex'), ', ')
      INTO dupes
      FROM (
            SELECT credential_id
              FROM auth.webauthn_credentials
             GROUP BY credential_id
            HAVING COUNT(*) > 1
           ) d;

    IF dupes IS NOT NULL THEN
        RAISE EXCEPTION
            'auth.webauthn_credentials holds duplicate credential_id values and cannot take a unique index: %',
            dupes
            USING HINT = 'Inspect both rows for each id and delete the one that is not the credential the user still holds. Deleting the wrong one removes a working second factor, so this migration will not choose.';
    END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
    ON auth.webauthn_credentials (credential_id);
