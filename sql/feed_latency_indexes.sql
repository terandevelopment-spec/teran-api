-- ============================================================
-- Targeted indexes for feed latency reduction
-- ============================================================
--
-- Run each statement ONE AT A TIME in Supabase SQL Editor.
-- All idempotent (IF NOT EXISTS).
--
-- Context: /api/posts feed MISS queries cost ~380ms.
-- Postgres itself runs in ~2ms; the ~350ms is Supabase/PostgREST
-- round-trip overhead. These indexes ensure the Postgres execution
-- stays minimal even as data grows.
-- ============================================================


-- ── 1. Global status feed ──────────────────────────────────
-- For: ?post_type=status&root_only=1&room_scope=global&light=1
-- Query: WHERE post_type='status' AND parent_post_id IS NULL
--         AND deleted_at IS NULL AND (room_id IS NULL OR room_id='global')
-- ORDER BY created_at DESC, id DESC LIMIT 60
--
-- Partial index: only root status posts in global scope.
-- Avoids scanning all posts; directly serves the most-hit feed.

CREATE INDEX IF NOT EXISTS idx_posts_global_status_feed
  ON public.posts (created_at DESC, id DESC)
  WHERE post_type = 'status'
    AND parent_post_id IS NULL
    AND deleted_at IS NULL
    AND (room_id IS NULL OR room_id = 'global');


-- ── 2. Rooms feed ──────────────────────────────────────────
-- For: ?root_only=1&room_scope=rooms&light=1
-- Query: WHERE parent_post_id IS NULL AND deleted_at IS NULL
--         AND room_id IS NOT NULL AND room_id != 'global'
-- ORDER BY created_at DESC, id DESC LIMIT 60

CREATE INDEX IF NOT EXISTS idx_posts_rooms_feed
  ON public.posts (created_at DESC, id DESC)
  WHERE parent_post_id IS NULL
    AND deleted_at IS NULL
    AND room_id IS NOT NULL
    AND room_id != 'global';


-- ── 3. Blocks composite covering indexes ───────────────────
-- For: GET /api/blocks/relations
-- Query 1: WHERE blocker_user_id = $me AND blocked_user_id IN (...)
-- Query 2: WHERE blocked_user_id = $me AND blocker_user_id IN (...)
--
-- NOTE: performance_indexes.sql already defines these.
-- Check first:
--   SELECT indexname, indexdef FROM pg_indexes
--   WHERE schemaname = 'public' AND tablename = 'blocks';
--
-- If idx_blocks_blocker and idx_blocks_blocked already exist, skip.

CREATE INDEX IF NOT EXISTS idx_blocks_blocker_blocked_covering
  ON public.blocks (blocker_user_id, blocked_user_id);

CREATE INDEX IF NOT EXISTS idx_blocks_blocked_blocker_covering
  ON public.blocks (blocked_user_id, blocker_user_id);


-- ============================================================
-- Validation: confirm all new indexes exist
-- ============================================================
-- SELECT indexname, indexdef
-- FROM pg_indexes
-- WHERE schemaname = 'public'
--   AND indexname IN (
--     'idx_posts_global_status_feed',
--     'idx_posts_rooms_feed',
--     'idx_blocks_blocker_blocked_covering',
--     'idx_blocks_blocked_blocker_covering'
--   )
-- ORDER BY indexname;
