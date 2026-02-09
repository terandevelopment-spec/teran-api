-- ============================================================
-- Postgres indexes for teran-api performance
-- ============================================================
--
-- IMPORTANT: Run each statement ONE AT A TIME in Supabase SQL Editor.
-- Do NOT use CONCURRENTLY — Supabase SQL Editor wraps in a transaction.
-- If you need CONCURRENTLY, use psql directly (not the Editor).
--
-- These are all idempotent (IF NOT EXISTS).
-- ============================================================


-- ── Step 0: Verify post_likes columns ──────────────────────
-- Run this FIRST to confirm column names:
--
-- SELECT column_name, data_type
-- FROM information_schema.columns
-- WHERE table_schema='public' AND table_name='post_likes'
-- ORDER BY ordinal_position;
--
-- Expected columns: post_id, actor_id, actor_name, actor_avatar, ...
-- The user column is "actor_id" (NOT "user_id")


-- ── Step 1: Posts feed ordering ────────────────────────────
-- Used by: GET /api/posts?limit=50
-- Query:   SELECT ... FROM posts ORDER BY created_at DESC, id DESC LIMIT 50
CREATE INDEX IF NOT EXISTS idx_posts_created_at_desc_id_desc
  ON posts (created_at DESC, id DESC);


-- ── Step 2: Blocks lookup ─────────────────────────────────
-- Used by: GET /api/blocks
-- Query:   SELECT ... FROM blocks WHERE blocker_user_id = $1 ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_blocks_blocker_user_id
  ON blocks (blocker_user_id);


-- ── Step 3: Blocks reverse lookup ─────────────────────────
-- Used by: GET /api/blocks/relations
-- Query:   SELECT ... FROM blocks WHERE blocked_user_id = $1
CREATE INDEX IF NOT EXISTS idx_blocks_blocked_user_id
  ON blocks (blocked_user_id);


-- ── Step 4: Echoes list ───────────────────────────────────
-- Used by: GET /api/echoes
-- Query:   SELECT ... FROM echoes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200
CREATE INDEX IF NOT EXISTS idx_echoes_user_id_created_at
  ON echoes (user_id, created_at DESC);


-- ── Step 5: Echoes relations ──────────────────────────────
-- Used by: GET /api/echoes/relations
-- Query:   SELECT ... FROM echoes WHERE user_id = $1 AND echoed_user_id IN (...)
CREATE INDEX IF NOT EXISTS idx_echoes_user_id_echoed_user_id
  ON echoes (user_id, echoed_user_id);


-- ── Step 6: Like counts (most important for feed perf) ────
-- Used by: GET /api/posts parallel_queries → likes batch
-- Query:   SELECT post_id FROM post_likes WHERE post_id IN (...)
CREATE INDEX IF NOT EXISTS idx_post_likes_post_id
  ON post_likes (post_id);


-- ── Step 7: "Liked by me" lookup ──────────────────────────
-- Used by: GET /api/posts parallel_queries → likedByMe
-- Query:   SELECT post_id FROM post_likes WHERE post_id IN (...) AND actor_id = $1
-- NOTE: Column is "actor_id", NOT "user_id"
CREATE INDEX IF NOT EXISTS idx_post_likes_actor_id_post_id
  ON post_likes (actor_id, post_id);


-- ── Step 8: Media by post ─────────────────────────────────
-- Used by: GET /api/posts parallel_queries → media batch
-- Query:   SELECT ... FROM media WHERE post_id IN (...)
CREATE INDEX IF NOT EXISTS idx_media_post_id
  ON media (post_id);


-- ── Step 9: Notifications unread count ────────────────────
-- Used by: GET /api/notifications/unread_count
-- Query:   SELECT count FROM notifications WHERE recipient_user_id = $1 AND is_read = false
CREATE INDEX IF NOT EXISTS idx_notifications_recipient_unread
  ON notifications (recipient_user_id)
  WHERE is_read = false;


-- ============================================================
-- Validation: Run this after all indexes are created
-- ============================================================
-- SELECT tablename, indexname, indexdef
-- FROM pg_indexes
-- WHERE schemaname = 'public'
--   AND tablename IN ('posts','blocks','echoes','post_likes','media','notifications')
-- ORDER BY tablename, indexname;


-- ============================================================
-- EXPLAIN ANALYZE templates (uncomment and run to verify)
-- Replace $1 with a real user_id UUID
-- ============================================================

-- Posts feed:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT id,user_id,created_at,title,content,author_id,author_name,author_avatar,
--        room_id,parent_post_id,post_type,shared_post_id
-- FROM posts ORDER BY created_at DESC, id DESC LIMIT 50;

-- Blocks:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT blocked_user_id, created_at FROM blocks
-- WHERE blocker_user_id = '$1' ORDER BY created_at DESC;

-- Echoes:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT echoed_user_id, created_at FROM echoes
-- WHERE user_id = '$1' ORDER BY created_at DESC LIMIT 200;

-- Like counts:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT post_id FROM post_likes WHERE post_id IN (1, 2, 3);
