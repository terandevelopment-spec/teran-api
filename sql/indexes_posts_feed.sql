-- Recommended indexes for GET /api/posts feed performance
-- Run these in Supabase SQL Editor (Dashboard > SQL Editor)

-- 1. Posts: feed query uses ORDER BY created_at DESC, id DESC LIMIT 50
--    This composite index lets Postgres do an index-only backward scan
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_posts_created_at_desc_id_desc
  ON posts (created_at DESC, id DESC);

-- 2. Media: fetched via .in("post_id", postIds) — needs index on post_id  
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_media_post_id
  ON media (post_id);

-- 3. Post likes: fetched via .eq("post_id", pid) for count
--    Also used for liked_by_me via .eq("post_id", pid).eq("actor_id", ...)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_post_likes_post_id
  ON post_likes (post_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_post_likes_post_id_actor_id
  ON post_likes (post_id, actor_id);

-- 4. Notifications: unread_count uses .eq("recipient_user_id", uid).eq("is_read", false)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_recipient_unread
  ON notifications (recipient_user_id, is_read)
  WHERE is_read = false;

-- 5. Blocks: used in blocks/relations via .eq("blocker_user_id", ...) and .eq("blocked_user_id", ...)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_blocks_blocker_user_id
  ON blocks (blocker_user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_blocks_blocked_user_id
  ON blocks (blocked_user_id);
