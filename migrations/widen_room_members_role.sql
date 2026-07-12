-- Widen room_members.role CHECK constraint to allow 'registered' role.
-- 'registered': a Room registrant who may comment but may not publish root posts.
-- Existing 'owner' and 'member' rows remain valid and unchanged.
-- Application behavior (normal Join writing 'registered') will be updated in a later Worker phase.
-- Run this in the Supabase SQL Editor.

ALTER TABLE room_members DROP CONSTRAINT IF EXISTS room_members_role_check;

ALTER TABLE room_members
  ADD CONSTRAINT room_members_role_check
  CHECK (role IN ('owner', 'member', 'registered'));
