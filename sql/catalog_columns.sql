-- Migration: add catalog_columns to rooms (Catalog Mode — Phase 1)
-- Date: 2026-07-22
-- Purpose: Number of columns the Teran card layout uses for Catalog Rooms.
--          Behaviorally relevant ONLY when room_type = 'catalog' AND
--          thread_card_style = 'teran'. It is persisted for every room so the
--          client can read it uniformly, but has no visual effect for
--          non-catalog rooms or the 'standard' card style.
--
-- Notes:
--   * room_type itself has no CHECK constraint (see room_design.sql), so the
--     new 'catalog' room type requires no schema change — only this column.
--   * Old rows: filled with the default 3 (matches the frontend default).
--     Existing 'post'/'thread' rooms are unaffected and are NOT reinterpreted
--     as Catalog Rooms.

ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS catalog_columns smallint NOT NULL DEFAULT 3
  CHECK (catalog_columns IN (2, 3));
