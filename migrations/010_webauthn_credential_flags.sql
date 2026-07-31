-- ============================================================================
-- 010: persist the WebAuthn credential flags
-- ============================================================================
--
-- Every backup-eligible (synced) passkey was permanently unusable the moment it
-- was enrolled, and enrolling one could lock the account out entirely.
--
-- A credential record carries the authenticator flags observed during
-- registration. go-webauthn compares the stored BackupEligible flag against the
-- one in every subsequent assertion and rejects the login unconditionally when
-- they disagree ("Backup Eligible flag inconsistency detected during login
-- validation"). Nothing here stored the flags, so the rehydrated credential
-- always claimed BE=0. A platform passkey from iCloud Keychain, Google Password
-- Manager or Windows Hello asserts BE=1, so every verification failed with 401.
-- Registration itself was never blocked, so the user ended up with
-- WebAuthnEnabled=true, RequiresMFA=true and no way to satisfy the challenge.
--
-- The value is the raw authenticator flags byte (UP/UV/BE/BS and the structural
-- bits), which is what go-webauthn serialises and reconstructs. SMALLINT is the
-- narrowest integer type Postgres offers and holds it comfortably.
--
-- Existing rows default to 0, which no genuine ceremony can produce: user
-- presence is mandatory for both registration and assertion, so bit 0 is always
-- set. 0 therefore means "never recorded" rather than "recorded as none", and
-- the handler adopts the flags from the first assertion it successfully
-- verifies instead of rejecting the credential. See adoptUnknownCredentialFlags
-- in internal/handler/webauthn.go for why that is not a downgrade.
-- ============================================================================

ALTER TABLE auth.webauthn_credentials
    ADD COLUMN IF NOT EXISTS flags SMALLINT NOT NULL DEFAULT 0;

-- vault_app performs the sign-count UPDATE after a successful assertion and now
-- writes the flags alongside it. 001 grants UPDATE at table level, which already
-- covers columns added later; the explicit column grant states the requirement
-- so a future narrowing of that grant cannot silently reinstate the lockout.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        GRANT UPDATE (flags) ON auth.webauthn_credentials TO vault_app;
    END IF;
END $$;
