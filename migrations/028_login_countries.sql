-- ============================================================================
-- Migration 028: seen login countries — the new-location (AR-18) notice
-- ============================================================================
--
-- The new-location notice tells a user when their account is accessed from a
-- country it has not been seen signing in from before. That requires one fact
-- this schema never stored: the set of countries a user has already logged in
-- from. This table is that set, at COUNTRY GRANULARITY ONLY — never an IP.
--
-- The country is derived locally from coarse IP-registration data (the ipintel
-- table, no third-party lookup), reduced to an ISO 3166-1 alpha-2 code, and only
-- that code is stored. There is deliberately no timestamp finer than first-seen,
-- no IP column, and no per-login history: a login-history log is not the point,
-- and the less this holds the less an erasure has to reach. See docs/PRIVACY.md
-- P4 (security monitoring / abuse prevention) and the data-minimisation note.
--
-- Modeled on auth.devices (migration 001): user_id-owned and cascade-deleted,
-- so account erasure (Art. 17) removes a user's countries automatically with no
-- bespoke cascade step. The PRIMARY KEY (user_id, country_code) is also the
-- uniqueness the upsert relies on: INSERT ... ON CONFLICT DO NOTHING makes
-- "record this country" idempotent, and whether a row was actually inserted is
-- exactly the "is this a new country?" signal the notice needs.
--
-- Grants: vault_app (the API) gets SELECT + INSERT — it records countries and
-- reads the prior count, and must never be able to rewrite or erase them.
-- vault_admin gets SELECT + DELETE for erasure/administration. Neither gets
-- UPDATE: a country is either present or not; there is nothing to mutate.
-- ============================================================================

CREATE TABLE auth.login_countries (
    user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    country_code  CHAR(2) NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, country_code)
);

GRANT SELECT, INSERT ON auth.login_countries TO vault_app;
GRANT SELECT, DELETE ON auth.login_countries TO vault_admin;
