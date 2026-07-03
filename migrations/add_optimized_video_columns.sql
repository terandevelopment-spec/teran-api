-- Add optimized video support columns to the unified media table.
-- Run this in the Supabase SQL Editor.
--
-- All columns are nullable so existing media rows remain valid:
--   optimized_key          NULL → no optimized version exists (use original key)
--   processing_status      NULL → no processing requested
--   optimized_bytes        NULL → unknown / not yet processed
--   optimized_duration_ms  NULL → unknown / not yet processed
--
-- processing_status values:
--   NULL        → legacy / no processing pipeline
--   'pending'   → queued for transcoding
--   'processing'→ transcoding in progress
--   'ready'     → optimized video available at optimized_key
--   'failed'    → transcoding failed; fall back to original key

ALTER TABLE media
  ADD COLUMN IF NOT EXISTS optimized_key text NULL,
  ADD COLUMN IF NOT EXISTS processing_status text NULL,
  ADD COLUMN IF NOT EXISTS optimized_bytes int NULL,
  ADD COLUMN IF NOT EXISTS optimized_duration_ms int NULL;

-- Safe constraint: use DO block to avoid error on re-run
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'media_processing_status_check'
  ) THEN
    ALTER TABLE media
      ADD CONSTRAINT media_processing_status_check
      CHECK (
        processing_status IS NULL
        OR processing_status IN ('pending', 'processing', 'ready', 'failed')
      );
  END IF;
END
$$;
