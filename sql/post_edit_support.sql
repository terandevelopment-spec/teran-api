-- Add canonical edit support to posts table
-- Run this in Supabase SQL Editor

-- 1) Add edited_at column — NULL means never edited
ALTER TABLE posts
  ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ NULL DEFAULT NULL;

-- 2) Index for efficient "edited" queries (partial — only non-null rows)
CREATE INDEX IF NOT EXISTS posts_edited_at_idx
  ON posts (edited_at)
  WHERE edited_at IS NOT NULL;
