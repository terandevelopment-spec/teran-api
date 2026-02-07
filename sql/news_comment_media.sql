-- Extend media table to support news comment attachments
-- Run this in Supabase SQL Editor AFTER the existing media.sql migration

-- 1) Add news_comment_id FK column
ALTER TABLE media
  ADD COLUMN IF NOT EXISTS news_comment_id bigint NULL
    REFERENCES news_comments(id) ON DELETE CASCADE;

-- 2) Drop old 2-way CHECK and recreate as 3-way XOR
--    Exactly one of {post_id, comment_id, news_comment_id} must be non-null
ALTER TABLE media DROP CONSTRAINT IF EXISTS media_one_owner;

ALTER TABLE media ADD CONSTRAINT media_one_owner CHECK (
  (
    (post_id IS NOT NULL)::int +
    (comment_id IS NOT NULL)::int +
    (news_comment_id IS NOT NULL)::int
  ) = 1
);

-- 3) Index for fast lookups by news_comment_id
CREATE INDEX IF NOT EXISTS media_news_comment_id_idx ON media(news_comment_id);
