-- Add mode + moods columns to posts table for 2-step thread creation
-- Run this in Supabase SQL Editor

-- 1) mode: single-select thread purpose (Ask / Discuss / Share / Fun)
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS mode text;

-- 2) moods: 1–2 emotional tags as text array
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS moods text[]
  DEFAULT '{}'::text[];

-- 3) Indexes for future filtering
CREATE INDEX IF NOT EXISTS posts_mode_idx ON public.posts (mode);
CREATE INDEX IF NOT EXISTS posts_moods_idx ON public.posts USING GIN (moods);
