-- ============================================================
-- Add icon_thumb_key to rooms table for small-icon rendering
-- ============================================================
-- Room icons are uploaded full-size (image_original/) but rendered at
-- 44×44px on room list cards. Without a thumb, browsers must download
-- and decode the full original (potentially hundreds of KB) for every
-- card. This column stores a 128px JPEG companion uploaded alongside
-- the original via kind="image_thumb".
--
-- Backward compat: existing rooms are left with icon_thumb_key = NULL.
-- RoomCard preferentially uses the thumb; falls back to icon_key.
-- ============================================================

ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS icon_thumb_key text NULL;

-- Validation (run after migration to confirm):
-- SELECT id, name, icon_key, icon_thumb_key
-- FROM public.rooms
-- WHERE icon_key IS NOT NULL
-- LIMIT 10;
