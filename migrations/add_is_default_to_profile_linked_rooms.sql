-- Adds a single "default" Profile Room marker to the profile_linked_rooms relation.
-- Phase 1 (backend only). This is a public-profile presentation preference ONLY:
-- it does NOT affect Room membership, joins, roles, invites, or permissions.
-- Run this file manually in the Supabase SQL Editor before deploying the Worker.
--
-- Backward-compatible & non-destructive:
--   - Existing rows receive is_default=false via the column DEFAULT.
--   - No existing profile therefore has a default after migration.
--   - The first linked Room is NEVER auto-selected as default.
--   - No rows are deleted, no Room order changes, no membership rows are touched.
--   - Idempotent: safe to re-run (IF NOT EXISTS on both statements).

BEGIN;

-- 1) The default marker. NOT NULL with a false default keeps every existing row valid.
ALTER TABLE profile_linked_rooms
  ADD COLUMN IF NOT EXISTS is_default boolean NOT NULL DEFAULT false;

-- 2) Database-level guarantee of at most one default per profile owner.
--    Scope column is owner_user_id — the active persona author_id used
--    everywhere in the /api/profile-rooms handlers. A PARTIAL unique index
--    (WHERE is_default = true) allows any number of non-default rows and
--    keeps "zero defaults" valid, while forbidding two defaults per owner.
CREATE UNIQUE INDEX IF NOT EXISTS profile_linked_rooms_one_default_per_owner_idx
  ON profile_linked_rooms (owner_user_id)
  WHERE is_default = true;

COMMIT;

-- 3) Force PostgREST (the Supabase REST layer the Worker uses) to reload its
--    schema cache so `is_default` is recognized immediately after migration.
NOTIFY pgrst, 'reload schema';
