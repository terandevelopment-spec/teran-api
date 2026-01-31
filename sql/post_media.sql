-- Supabase SQL: post_media table
-- Run this in Supabase SQL Editor

CREATE TABLE IF NOT EXISTS post_media (
  id bigserial PRIMARY KEY,
  post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  type text NOT NULL CHECK (type IN ('image', 'video')),
  key text NOT NULL,
  thumb_key text NULL,
  width int NULL,
  height int NULL,
  bytes int NULL,
  duration_ms int NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Index for fast lookups by post
CREATE INDEX IF NOT EXISTS idx_post_media_post_id ON post_media(post_id);

-- Optional: unique constraint on key to prevent duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_post_media_key ON post_media(key);

-- RLS: enable and allow select for all (writes via service role only)
ALTER TABLE post_media ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read media (public posts)
CREATE POLICY "Allow public read on post_media"
  ON post_media
  FOR SELECT
  USING (true);

-- Writes are done via service role (no user policy needed)
