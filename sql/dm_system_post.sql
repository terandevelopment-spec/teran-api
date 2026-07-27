-- DM-as-a-Room — Phase 2: canonical system-post uniqueness
-- Run in Supabase SQL Editor (service role). Idempotent.
--
-- Each DM Room (rooms.room_type = 'dm') hosts EXACTLY ONE internal system post
-- that exists only as the host/root for the existing comment stream (Phase 3).
-- The system post is identified by a dedicated posts.post_type = 'dm_system'.
--
-- Why a dedicated post_type (not a new column):
--   * posts.post_type has NO CHECK constraint, so introducing an internal type
--     adds nothing to — and weakens nothing in — normal post validation. Normal
--     posts remain 'status' | 'thread' | 'share' as enforced by the API layer.
--   * Every feed/discovery query already filters post_type to the normal set
--     (e.g. post_type = 'status'), so 'dm_system' rows are naturally excluded in
--     addition to the room_id exclusion already applied to DM Rooms (Phase 1).
--
-- Why this index is REQUIRED:
--   The happy path (the DM-Room-creation winner also creates the system post;
--   losers reselect) already avoids duplicates. This partial unique index closes
--   the remaining narrow window — a Room created whose system-post insert failed,
--   then two simultaneous retries — by making a second 'dm_system' post per Room
--   impossible at the database level. POST /api/dm/open handles the resulting
--   unique violation (23505) by reselecting the surviving canonical post.
--
-- Scope: this index constrains ONLY rows with post_type = 'dm_system'. It has no
-- effect on any normal post, so a Room may still have many ordinary root posts.

CREATE UNIQUE INDEX IF NOT EXISTS posts_dm_system_uidx
  ON public.posts (room_id)
  WHERE post_type = 'dm_system';
