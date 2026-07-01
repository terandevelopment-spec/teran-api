-- Add video trim/crop metadata to the unified media table
-- Run this in the Supabase SQL Editor.
--
-- All columns are nullable so existing media rows remain valid:
--   trim_start_ms  NULL -> play from 0
--   trim_end_ms    NULL -> no trim end (play to natural end)
--   object_pos_x   NULL -> centered horizontally (treated as 0.5 at render time)
--   object_pos_y   NULL -> centered vertically   (treated as 0.5 at render time)

ALTER TABLE media
  ADD COLUMN IF NOT EXISTS trim_start_ms int NULL,
  ADD COLUMN IF NOT EXISTS trim_end_ms int NULL,
  ADD COLUMN IF NOT EXISTS object_pos_x float NULL,
  ADD COLUMN IF NOT EXISTS object_pos_y float NULL;
