-- Saves (bookmarks) table
-- Allows users to save/bookmark posts for later

CREATE TABLE IF NOT EXISTS public.saves (
  id SERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  post_id INTEGER NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Prevent duplicate saves
  CONSTRAINT saves_user_post_unique UNIQUE (user_id, post_id)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_saves_user_id ON public.saves(user_id);
CREATE INDEX IF NOT EXISTS idx_saves_post_id ON public.saves(post_id);
CREATE INDEX IF NOT EXISTS idx_saves_created_at ON public.saves(created_at DESC);

-- Grant permissions (adjust as needed for your RLS setup)
-- ALTER TABLE public.saves ENABLE ROW LEVEL SECURITY;
