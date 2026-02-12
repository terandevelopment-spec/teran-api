-- Add genre column to posts for AI auto-classification
-- Run this in Supabase SQL Editor

-- 1) Add nullable text column
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS genre text;

-- 2) Index for filtering by genre
CREATE INDEX IF NOT EXISTS posts_genre_idx ON public.posts (genre);
