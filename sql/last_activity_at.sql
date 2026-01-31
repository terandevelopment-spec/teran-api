-- Add last_activity_at column to posts for "bump on new comment" behavior

-- 1) Add column (nullable, default null)
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMPTZ;

-- 2) Initialize existing rows with created_at value
UPDATE public.posts
SET last_activity_at = created_at
WHERE last_activity_at IS NULL;

-- 3) Add index for efficient ordering
CREATE INDEX IF NOT EXISTS posts_last_activity_at_idx ON public.posts (last_activity_at DESC);
