-- DM-as-a-Room — Phase 4: Persona-scoped unread read-state
-- Run in Supabase SQL Editor (service role). Idempotent: safe to re-run.
--
-- Adds the ONLY storage backing Persona-scoped DM unread counts. It is fully
-- additive: no existing DM table, post, comment, Echo, or block rule changes.
--
-- Identity model (mirrors dm_room_persona_pair.sql conventions):
--   * room_id                  → rooms.id (text; canonical DM Room, unique per pair)
--   * reader_persona_author_id → Persona author_id (text; SAME identity as
--                                echoes.echoer_author_id / user_profiles.user_id).
--   Each of the two participants in one DM Room owns an INDEPENDENT row, so a
--   read position is per-(Room, reader Persona). Sibling Personas of the same
--   account are distinct readers. A MISSING row means this reader Persona has
--   read NONE of the currently available incoming messages (no backfill needed).
--
-- Foreign keys (consistent with the existing DM schema):
--   * room_id  → REFERENCES rooms(id) ON DELETE CASCADE. This exactly matches
--     every other room-scoped table (room_members, room_avatar_options,
--     room_links, sql/rooms.sql), so deleting a DM Room cleans up its cursors.
--   * reader_persona_author_id → NO foreign key. Persona author_ids are stored
--     FK-less throughout (echoes, dm_persona_lo/hi); we keep that convention.
--   * last_read_message_id → NO foreign key. It is a pure cursor POSITION. DM
--     messages are never physically deleted (only hidden by the 24h window), so
--     a dormant cursor pointing at an expired message is harmless and must never
--     be resurrected. Avoiding the FK also keeps mark-read from being coupled to
--     comment lifecycle.

-- ── 1) Table ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.dm_read_states (
  room_id                  text        NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  reader_persona_author_id text        NOT NULL,
  last_read_message_id     bigint      NOT NULL,   -- matches comments.id (bigint)
  last_read_created_at     timestamptz NOT NULL,   -- server-derived; never a client clock
  updated_at               timestamptz NOT NULL DEFAULT now(),
  -- Unique read-state identity. Declared as the PRIMARY KEY so it doubles as the
  -- lookup/uniqueness index (no separate UNIQUE index needed → no duplicates).
  CONSTRAINT dm_read_states_pkey PRIMARY KEY (room_id, reader_persona_author_id)
);

-- ── 2) Indexes ───────────────────────────────────────────────────────────
-- The (room_id, reader_persona_author_id) unique/lookup index is provided by the
-- PRIMARY KEY above. No additional index on this table is required.
--
-- Comments range/count support: the existing index
--   idx_comments_post_created ON public.comments (post_id, created_at DESC)
-- (sql/performance_indexes.sql) already serves the 24h range filter
-- (post_id = X AND created_at > cutoff) used by unread counting. A
-- (post_id, created_at, id) variant would be a near-duplicate whose only extra
-- benefit is the id tiebreak on the single boundary row, so it is intentionally
-- NOT added here (avoids a redundant duplicate index).

-- ── 3) RLS: fully private (service-role only) ────────────────────────────
-- Same pattern as public.echoes (sql/rls_public_tables.sql): enable RLS with NO
-- policies. The Worker uses the service role (bypasses RLS) for all reads/writes;
-- direct anon / PostgREST access is denied. No public SELECT/INSERT/UPDATE.
ALTER TABLE public.dm_read_states ENABLE ROW LEVEL SECURITY;

-- ── 4) Grouped unread-count function ─────────────────────────────────────
-- Calculates per-conversation unread INCOMING counts entirely in SQL (no bulk
-- comment download into the Worker). The Worker first authorizes and resolves the
-- eligible DM conversations (mutual Echo + not blocked + canonical Room + its
-- dm_system post) using the existing Inbox pipeline, then passes the validated
-- tuples here. This function performs NO authorization of its own and must only
-- ever be called with an already-authorized batch (it is not a public bypass —
-- RLS on dm_read_states + the EXECUTE grants below restrict it to the service
-- role, and it only reads rows the caller already proved access to).
--
-- p_convos: jsonb array of { "room_id": text, "post_id": bigint, "other": text }.
-- A comment is unread iff ALL hold:
--   * c.post_id = the conversation's canonical dm_system post
--   * c.created_at > p_cutoff            (authoritative 24h window)
--   * c.author_id = the OTHER Persona    (incoming only; never reader-authored)
--   * (c.created_at, c.id) is lexicographically AFTER the reader's stored cursor,
--     or no cursor row exists (→ every available incoming message is unread).
-- Returns one row per input conversation, including those with unread_count = 0
-- (LEFT JOIN + count(non-null) yields 0 when nothing matches).
CREATE OR REPLACE FUNCTION public.get_dm_unread_counts(
  p_reader text,
  p_cutoff timestamptz,
  p_convos jsonb
)
RETURNS TABLE (room_id text, unread_count bigint)
LANGUAGE sql
STABLE
AS $$
  WITH convos AS (
    SELECT
      (elem->>'room_id')::text   AS room_id,
      (elem->>'post_id')::bigint AS post_id,
      (elem->>'other')::text     AS other
    FROM jsonb_array_elements(p_convos) AS elem
  )
  SELECT
    cv.room_id,
    count(c.id)::bigint AS unread_count
  FROM convos cv
  LEFT JOIN public.dm_read_states rs
         ON rs.room_id = cv.room_id
        AND rs.reader_persona_author_id = p_reader
  LEFT JOIN public.comments c
         ON c.post_id    = cv.post_id
        AND c.author_id  = cv.other
        AND c.created_at > p_cutoff
        AND (
              rs.last_read_created_at IS NULL
              OR c.created_at > rs.last_read_created_at
              OR (c.created_at = rs.last_read_created_at
                  AND c.id > rs.last_read_message_id)
            )
  GROUP BY cv.room_id
$$;

-- ── 5) Monotonic mark-read function ──────────────────────────────────────
-- Advances the reader's cursor for one DM Room atomically. The cursor may ONLY
-- move forward: the ON CONFLICT ... WHERE guard makes an older-or-equal request
-- a successful no-op (idempotent; duplicate / retried / out-of-order / two-device
-- requests can never regress the cursor). All values are validated by the Worker
-- (verifyDmRoomCommentAccess + comment ownership/timestamp) BEFORE this is called.
CREATE OR REPLACE FUNCTION public.dm_advance_read_cursor(
  p_room       text,
  p_reader     text,
  p_msg_id     bigint,
  p_created_at timestamptz
)
RETURNS void
LANGUAGE sql
AS $$
  INSERT INTO public.dm_read_states AS s (
    room_id, reader_persona_author_id, last_read_message_id, last_read_created_at, updated_at
  )
  VALUES (p_room, p_reader, p_msg_id, p_created_at, now())
  ON CONFLICT (room_id, reader_persona_author_id) DO UPDATE
    SET last_read_message_id = EXCLUDED.last_read_message_id,
        last_read_created_at = EXCLUDED.last_read_created_at,
        updated_at           = now()
    WHERE EXCLUDED.last_read_created_at > s.last_read_created_at
       OR (EXCLUDED.last_read_created_at = s.last_read_created_at
           AND EXCLUDED.last_read_message_id > s.last_read_message_id);
$$;

-- ── 6) Execute grants: service role only ─────────────────────────────────
-- Defense-in-depth so neither function is callable via the anon/authenticated
-- PostgREST roles. The Worker (service role) retains EXECUTE.
REVOKE ALL ON FUNCTION public.get_dm_unread_counts(text, timestamptz, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_dm_unread_counts(text, timestamptz, jsonb) TO service_role;

REVOKE ALL ON FUNCTION public.dm_advance_read_cursor(text, text, bigint, timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dm_advance_read_cursor(text, text, bigint, timestamptz) TO service_role;

-- ── Rollback (manual; do NOT run as part of forward migration) ───────────
--   DROP FUNCTION IF EXISTS public.dm_advance_read_cursor(text, text, bigint, timestamptz);
--   DROP FUNCTION IF EXISTS public.get_dm_unread_counts(text, timestamptz, jsonb);
--   DROP TABLE    IF EXISTS public.dm_read_states;
-- Dropping the table degrades unread counts gracefully to "all incoming unread"
-- (the Worker treats a missing row / absent count as zero-cursor) and never
-- affects messages, Rooms, Echoes, or blocks.
