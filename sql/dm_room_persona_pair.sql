-- DM-as-a-Room — Phase 1: canonical two-Persona pair fields on rooms
-- Run in Supabase SQL Editor (service role). Idempotent.
--
-- A DM Room is a normal `rooms` row with room_type = 'dm' that is shared by
-- exactly two Personas. The canonical pair is stored as the ordered pair of
-- Persona author_ids (dm_persona_lo < dm_persona_hi) so that
--   (Persona A, Persona B) and (Persona B, Persona A)
-- always resolve to the SAME row and can never create two DM Rooms.
--
-- These columns store PERSONA author_ids only (user_profiles.user_id / the same
-- identity used by the echoes table). They intentionally do NOT store account
-- IDs, device IDs, or room_members identities. No foreign key is added: the
-- Persona author_id key is TEXT and is already referenced without an FK by the
-- echoes table, so we keep the same (safe, stable) convention here.

-- 1) Canonical Persona-pair columns (nullable; only populated for DM Rooms).
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS dm_persona_lo text NULL;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS dm_persona_hi text NULL;

-- 2) Integrity constraint:
--    - DM Rooms (room_type = 'dm') MUST have both pair fields, ordered lo < hi.
--    - All other Rooms (including legacy NULL room_type) MUST have both NULL.
--    Existing rows all satisfy the second branch (both columns are NULL after
--    the ADD COLUMN above and room_type is never 'dm' yet), so adding the
--    constraint validates cleanly against current data.
ALTER TABLE public.rooms DROP CONSTRAINT IF EXISTS rooms_dm_pair_chk;
ALTER TABLE public.rooms
  ADD CONSTRAINT rooms_dm_pair_chk CHECK (
    (
      room_type = 'dm'
      AND dm_persona_lo IS NOT NULL
      AND dm_persona_hi IS NOT NULL
      AND dm_persona_lo < dm_persona_hi
    )
    OR
    (
      room_type IS DISTINCT FROM 'dm'
      AND dm_persona_lo IS NULL
      AND dm_persona_hi IS NULL
    )
  );

-- 3) Uniqueness: at most ONE DM Room per canonical Persona pair.
--    Partial index scoped to DM Rooms so it never affects normal Rooms.
--    Combined with the lo < hi ordering above, this guarantees A+B == B+A.
CREATE UNIQUE INDEX IF NOT EXISTS rooms_dm_pair_uidx
  ON public.rooms (dm_persona_lo, dm_persona_hi)
  WHERE room_type = 'dm';
