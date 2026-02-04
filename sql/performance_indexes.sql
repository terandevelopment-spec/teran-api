-- Performance indexes for slow endpoints
-- Run these in Supabase SQL Editor (safe, non-destructive)

-- Index for /api/comments?post_id=X (filter by post_id, order by created_at desc)
CREATE INDEX IF NOT EXISTS idx_comments_post_created
ON public.comments (post_id, created_at DESC);

-- Unique constraint for comment_likes (required for upsert with ignoreDuplicates)
-- This enables idempotent like/unlike in single DB calls
ALTER TABLE public.comment_likes
ADD CONSTRAINT IF NOT EXISTS comment_likes_user_comment_unique 
UNIQUE (user_id, comment_id);

-- Index for comment_likes lookup by comment_id (bulk IN queries)
CREATE INDEX IF NOT EXISTS idx_comment_likes_comment_id
ON public.comment_likes (comment_id);

-- Index for comment_likes lookup by user_id + comment_id (liked_by_me check)
CREATE INDEX IF NOT EXISTS idx_comment_likes_user_comment
ON public.comment_likes (user_id, comment_id);

-- Index for media lookup by comment_id
CREATE INDEX IF NOT EXISTS idx_media_comment
ON public.media (comment_id) WHERE comment_id IS NOT NULL;

-- Index for media lookup by post_id
CREATE INDEX IF NOT EXISTS idx_media_post
ON public.media (post_id) WHERE post_id IS NOT NULL;

-- Index for /api/echoes (filter by user_id, order by created_at desc)
CREATE INDEX IF NOT EXISTS idx_echoes_user_created
ON public.echoes (user_id, created_at DESC);

-- Unique constraint for echoes (required for upsert with ignoreDuplicates)
-- This enables idempotent echo/un-echo in single DB calls
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'echoes_user_target_unique'
  ) THEN
    ALTER TABLE public.echoes
    ADD CONSTRAINT echoes_user_target_unique UNIQUE (user_id, echoed_user_id);
  END IF;
END $$;

-- Index for blocks lookup (both directions)
CREATE INDEX IF NOT EXISTS idx_blocks_blocker
ON public.blocks (blocker_user_id, blocked_user_id);

CREATE INDEX IF NOT EXISTS idx_blocks_blocked
ON public.blocks (blocked_user_id, blocker_user_id);

-- Unique constraint for saves (required for upsert with ignoreDuplicates)
-- This enables idempotent save/unsave in single DB calls
ALTER TABLE public.saves
ADD CONSTRAINT IF NOT EXISTS saves_user_post_unique 
UNIQUE (user_id, post_id);

-- Index for saves lookup by user_id (list saved posts)
CREATE INDEX IF NOT EXISTS idx_saves_user
ON public.saves (user_id, created_at DESC);

-- Index for saves lookup by post_id (count saves per post)
CREATE INDEX IF NOT EXISTS idx_saves_post
ON public.saves (post_id);
