-- ============================================================
-- Recommended indexes for API performance
-- Run in Supabase SQL Editor (Dashboard > SQL Editor)
-- Use CONCURRENTLY to avoid locking tables during creation
-- ============================================================

-- ── Posts feed: ORDER BY created_at DESC, id DESC LIMIT 50 ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_posts_created_at_desc_id_desc
  ON posts (created_at DESC, id DESC);

-- ── Media: fetched via .in("post_id", postIds) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_media_post_id
  ON media (post_id);

-- ── Post likes: fetched via .in("post_id", postIds) for count ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_post_likes_post_id
  ON post_likes (post_id);

-- ── Post likes: liked_by_me check via .eq("post_id", pid).eq("actor_id", ...) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_post_likes_post_id_actor_id
  ON post_likes (post_id, actor_id);

-- ── Notifications: unread count via .eq("recipient_user_id", uid).eq("is_read", false) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_recipient_unread
  ON notifications (recipient_user_id)
  WHERE is_read = false;

-- ── Blocks: GET /api/blocks via .eq("blocker_user_id", ...) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_blocks_blocker_user_id
  ON blocks (blocker_user_id);

-- ── Blocks: blocks/relations via .eq("blocked_user_id", ...) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_blocks_blocked_user_id
  ON blocks (blocked_user_id);

-- ── Echoes: GET /api/echoes via .eq("user_id", ...) ORDER BY created_at DESC ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_echoes_user_id_created_at
  ON echoes (user_id, created_at DESC);

-- ── Echoes: blocks check in echoes handler via .or(blocker=me, blocked=me) ──
-- Covered by idx_blocks_blocker_user_id + idx_blocks_blocked_user_id above

-- ── Echoes relations: .eq("user_id", ...).in("echoed_user_id", [...]) ──
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_echoes_user_id_echoed_user_id
  ON echoes (user_id, echoed_user_id);

-- ============================================================
-- EXPLAIN ANALYZE: Run these to verify index usage
-- Replace $1 with your actual user_id for testing
-- ============================================================

-- Posts feed query:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT id,user_id,created_at,title,content,author_id,author_name,author_avatar,room_id,parent_post_id,post_type,shared_post_id
-- FROM posts
-- ORDER BY created_at DESC, id DESC
-- LIMIT 50;

-- Blocks query:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT blocked_user_id, created_at
-- FROM blocks
-- WHERE blocker_user_id = '$1'
-- ORDER BY created_at DESC;

-- Echoes query:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT echoed_user_id, created_at
-- FROM echoes
-- WHERE user_id = '$1'
-- ORDER BY created_at DESC
-- LIMIT 200;

-- Like counts query:
-- EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
-- SELECT post_id
-- FROM post_likes
-- WHERE post_id IN (1, 2, 3);  -- replace with real post IDs
