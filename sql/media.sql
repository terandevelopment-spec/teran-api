-- Unified media table for posts and comments
-- Run this in Supabase SQL Editor

-- 1) Create unified media table
CREATE TABLE IF NOT EXISTS media (
  id bigserial PRIMARY KEY,
  post_id bigint NULL REFERENCES posts(id) ON DELETE CASCADE,
  comment_id bigint NULL REFERENCES comments(id) ON DELETE CASCADE,

  type text NOT NULL CHECK (type IN ('image','video')),
  key text NOT NULL,
  thumb_key text NULL,

  width int NULL,
  height int NULL,
  bytes int NULL,
  duration_ms int NULL,

  created_at timestamptz NOT NULL DEFAULT now(),

  -- Exactly one of post_id or comment_id must be set
  CONSTRAINT media_one_owner CHECK (
    (post_id IS NOT NULL AND comment_id IS NULL) OR
    (post_id IS NULL AND comment_id IS NOT NULL)
  )
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS media_post_id_idx ON media(post_id);
CREATE INDEX IF NOT EXISTS media_comment_id_idx ON media(comment_id);

-- RLS: enable and allow select for all, writes via service role
ALTER TABLE media ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read media
CREATE POLICY "Allow public read on media"
  ON media
  FOR SELECT
  USING (true);

-- Allow service_role to insert media (Worker uses service_role key)
CREATE POLICY "Allow service_role insert on media"
  ON media
  FOR INSERT
  TO service_role
  WITH CHECK (true);

-- Allow service_role to update media
CREATE POLICY "Allow service_role update on media"
  ON media
  FOR UPDATE
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Allow service_role to delete media
CREATE POLICY "Allow service_role delete on media"
  ON media
  FOR DELETE
  TO service_role
  USING (true);

-- OPTIONAL: migrate existing post_media rows to media table
-- (uncomment if you have existing data to migrate)
-- INSERT INTO media (post_id, type, key, thumb_key, width, height, bytes, duration_ms, created_at)
-- SELECT post_id, type, key, thumb_key, width, height, bytes, duration_ms, created_at
-- FROM post_media
-- WHERE post_id IS NOT NULL
-- ON CONFLICT DO NOTHING;

-- OPTIONAL: drop old table after verifying migration
-- DROP TABLE IF EXISTS post_media;
