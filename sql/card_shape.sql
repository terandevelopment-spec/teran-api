-- Migration: add card_shape column to rooms table
-- Date: 2026-04-15
-- Purpose: Store the card layout choice for Social-mode rooms.
--          'flat'    = current divider-based list (default, backward-compatible)
--          'rounded' = isolated rounded-corner card per post (Main-card geometry)
--
-- Old rows: column defaults to NULL, treated as 'flat' by all frontend/backend
--           fallback logic. No data migration needed.

ALTER TABLE rooms
  ADD COLUMN IF NOT EXISTS card_shape TEXT DEFAULT NULL
  CHECK (card_shape IS NULL OR card_shape IN ('flat', 'rounded'));
