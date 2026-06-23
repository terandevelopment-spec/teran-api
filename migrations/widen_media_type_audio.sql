-- Widen media.type CHECK constraint to allow 'audio'
-- Short-media policy: image, video, audio (gif-like media is stored as type='video' for now)
-- Run this in the Supabase SQL Editor.
--
-- NOTE: The legacy `post_media` table is NOT used by the Worker (all reads/writes
-- target the unified `media` table), so its constraint is intentionally left unchanged.

ALTER TABLE media DROP CONSTRAINT IF EXISTS media_type_check;

ALTER TABLE media
  ADD CONSTRAINT media_type_check CHECK (type IN ('image', 'video', 'audio'));
