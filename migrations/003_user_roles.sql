-- Add per-user roles support to auth.users.
--
-- Until this migration, every user's JWT carried a hardcoded ["user"] roles
-- claim regardless of how they were seeded. Downstream RBAC (Hermod) wanted
-- distinct viewer/operator roles per user, which needs the user record to
-- carry its own role set.
--
-- Constraints:
--   * NOT NULL with empty-array default → existing rows survive the column
--     add without rewrite. Login flow falls back to ["user"] when the array
--     is empty (preserves the pre-migration default).
--   * No CHECK constraint on which strings are allowed at the DB layer;
--     application-side validation in internal/seed/seed.go rejects the
--     admin-reserved set ("admin", "super_admin") so the user table can
--     never grant the admin gateway.
--   * pg_trgm GIN index on roles only if you actually filter by role at
--     scale; not added here because the current login lookup is by email
--     and the array is loaded into the JWT once per session.
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS roles TEXT[] NOT NULL DEFAULT '{}';
