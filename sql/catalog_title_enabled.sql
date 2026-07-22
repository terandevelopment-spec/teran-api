-- Migration: add catalog_title_enabled to rooms (Catalog Mode)
-- Date: 2026-07-22
-- Purpose: Controls whether root Catalog posts use a title. Applies to both
--          Catalog + Teran and Catalog + Standard card styles. Behaviorally
--          relevant ONLY when room_type = 'catalog'; it is persisted for every
--          room so the client/API can read it uniformly, but has no effect for
--          non-catalog rooms.
--
-- Notes:
--   * Default TRUE so existing Catalog Rooms behave as title-enabled after the
--     migration (no title data is lost or cleared).
--   * Existing non-catalog rooms are unaffected (the flag is ignored for them).
--   * Does NOT touch posts.title. No second post-title column is introduced.

ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS catalog_title_enabled boolean NOT NULL DEFAULT true;
