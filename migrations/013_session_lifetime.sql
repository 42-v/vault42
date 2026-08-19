-- ============================================================================
-- 013: absolute session lifetime — give the rotation family a birth date
-- ============================================================================
--
-- auth.refresh_tokens (migration 001) records created_at per token and groups
-- rotations under family_id, but it records nothing about when the family began.
-- Every rotation issues a token with a full, fresh refresh TTL, so the 7-day
-- VAULT_REFRESH_TOKEN_TTL is a sliding window rather than a bound: a client that
-- refreshes inside every window keeps one session alive forever, and no query in
-- the system can even tell how old that session is.
--
-- NIST SP 800-63B-4 §2.2.3 requires reauthentication at an absolute interval
-- regardless of activity. That control needs one fact this schema never stored:
-- the instant the family was created.
--
-- family_created_at is that fact. It is written once by the first token of a
-- family and copied verbatim onto every rotation (see
-- internal/repository/postgres/refresh_token.go, Create), so:
--
--   * rotation cannot advance it — the INSERT reads the family's existing value
--     and only falls back to its own created_at when the family has no rows yet;
--   * pruning cannot reset it — DeleteExpired removes spent rows, and every
--     surviving row still carries the family's original value, which is why this
--     is a stored column and not MIN(created_at) computed at read time.
--
-- Backfill uses MIN(created_at) per family, which is exact for every family whose
-- first token has not been pruned and conservative (never older than the truth)
-- otherwise. A pre-existing session therefore gets at most one extra absolute
-- window before it is forced to reauthenticate.
--
-- Grants: 001 grants vault_app SELECT/INSERT/UPDATE/DELETE and vault_admin SELECT
-- at table level, so both roles pick the new column up without further grants.
-- ============================================================================

ALTER TABLE auth.refresh_tokens ADD COLUMN family_created_at TIMESTAMPTZ;

UPDATE auth.refresh_tokens t
SET family_created_at = o.origin
FROM (
    SELECT family_id, MIN(created_at) AS origin
    FROM auth.refresh_tokens
    GROUP BY family_id
) o
WHERE t.family_id = o.family_id
  AND t.family_created_at IS NULL;

-- The default covers any writer that does not name the column; the application
-- always names it, and NOT NULL is what makes the bound impossible to bypass by
-- inserting a row with no origin.
ALTER TABLE auth.refresh_tokens ALTER COLUMN family_created_at SET DEFAULT NOW();
ALTER TABLE auth.refresh_tokens ALTER COLUMN family_created_at SET NOT NULL;

COMMENT ON COLUMN auth.refresh_tokens.family_created_at IS
    'Instant the rotation family was created. Inherited unchanged by every rotation; enforces the absolute session lifetime (NIST SP 800-63B-4 §2.2.3).';
