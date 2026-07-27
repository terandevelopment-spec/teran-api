-- ============================================================
-- Lightweight Persona-to-Persona DM — database foundation
-- Migration: create_persona_dm_tables
-- ============================================================
-- Phase 2 of 5. Creates ONLY the private database schema for
-- one-to-one Persona DM. No Worker endpoints, no frontend, no
-- conversation prepopulation, no scheduled cleanup.
--
-- Identity model:
--   Every participant is a Persona author_id (TEXT), matching
--   echoes.echoer_author_id / echoes.echoed_user_id / user_profiles.user_id.
--   NEVER a JWT subject, device ID, account ID, email, or Teran ID.
--
-- Access model (mirrors public.echoes in sql/rls_public_tables.sql):
--   RLS is ENABLED with NO policies -> fully locked to direct
--   anon/authenticated PostgREST access. Only the teran-api service
--   role (which bypasses RLS) can read/write. Explicit REVOKEs added
--   as defense-in-depth.
--
-- Persona foreign keys: intentionally OMITTED. The existing schema
--   (echoes) does NOT use DB-level foreign keys to user_profiles for
--   Persona identity, and cascading a profile deletion into another
--   participant's message history would be unsafe. Persona validity is
--   enforced by Worker authorization + profile-existence checks (phase 3).
--
-- Run in the Supabase SQL Editor. Idempotent and safe to re-run.
-- ============================================================

BEGIN;

-- ────────────────────────────────────────────────────────────
-- 1. dm_conversations
-- Canonical one-to-one Persona pair, lazily created on first message.
-- persona_lo < persona_hi guarantees A→B and B→A resolve to one row.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.dm_conversations (
    id BIGSERIAL PRIMARY KEY,

    persona_lo TEXT NOT NULL,
    persona_hi TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_message_at TIMESTAMPTZ,

    CONSTRAINT dm_conversations_distinct_personas
        CHECK (persona_lo < persona_hi),

    CONSTRAINT dm_conversations_unique_pair
        UNIQUE (persona_lo, persona_hi)
);

-- ────────────────────────────────────────────────────────────
-- 2. dm_messages
-- Private text messages that become inaccessible 24h after creation.
-- expires_at is ALWAYS server-controlled by a trigger (see §5).
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.dm_messages (
    id BIGSERIAL PRIMARY KEY,

    conversation_id BIGINT NOT NULL
        REFERENCES public.dm_conversations(id)
        ON DELETE CASCADE,

    sender_author_id TEXT NOT NULL,
    recipient_author_id TEXT NOT NULL,

    body TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),

    CONSTRAINT dm_messages_distinct_participants
        CHECK (sender_author_id <> recipient_author_id),

    CONSTRAINT dm_messages_body_not_blank
        CHECK (length(btrim(body)) > 0),

    CONSTRAINT dm_messages_body_length
        CHECK (char_length(body) <= 1000),

    CONSTRAINT dm_messages_valid_expiry
        CHECK (expires_at > created_at)
);

-- ────────────────────────────────────────────────────────────
-- 3. dm_reads
-- Recipient-only internal open-state used to compute unread counts.
-- NEVER exposed to the other participant (no public read receipts).
-- One row per (conversation, participant) — never one row per message.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.dm_reads (
    conversation_id BIGINT NOT NULL
        REFERENCES public.dm_conversations(id)
        ON DELETE CASCADE,

    persona_author_id TEXT NOT NULL,

    last_opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (conversation_id, persona_author_id)
);

-- ────────────────────────────────────────────────────────────
-- 4. Server-controlled 24-hour expiration (defense-in-depth)
-- expires_at is ALWAYS created_at + 24h, regardless of any value the
-- Worker/caller supplies. Recomputed if created_at/expires_at change,
-- so message lifetime can never be extended. Opening a message does
-- not touch created_at, so it never extends expiration.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.set_dm_message_expiry()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.created_at IS NULL THEN
        NEW.created_at := NOW();
    END IF;

    NEW.expires_at := NEW.created_at + INTERVAL '24 hours';

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_dm_message_expiry ON public.dm_messages;

CREATE TRIGGER trg_set_dm_message_expiry
BEFORE INSERT OR UPDATE OF created_at, expires_at
ON public.dm_messages
FOR EACH ROW
EXECUTE FUNCTION public.set_dm_message_expiry();

-- ────────────────────────────────────────────────────────────
-- 5. Validate message participants against the conversation
-- sender/recipient must be exactly the conversation's two Personas.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.validate_dm_message_participants()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row public.dm_conversations%ROWTYPE;
BEGIN
    SELECT *
    INTO conversation_row
    FROM public.dm_conversations
    WHERE id = NEW.conversation_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'DM conversation does not exist';
    END IF;

    IF NOT (
        (
            NEW.sender_author_id = conversation_row.persona_lo
            AND NEW.recipient_author_id = conversation_row.persona_hi
        )
        OR
        (
            NEW.sender_author_id = conversation_row.persona_hi
            AND NEW.recipient_author_id = conversation_row.persona_lo
        )
    ) THEN
        RAISE EXCEPTION 'DM message participants do not match conversation';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_dm_message_participants ON public.dm_messages;

CREATE TRIGGER trg_validate_dm_message_participants
BEFORE INSERT OR UPDATE OF conversation_id, sender_author_id, recipient_author_id
ON public.dm_messages
FOR EACH ROW
EXECUTE FUNCTION public.validate_dm_message_participants();

-- ────────────────────────────────────────────────────────────
-- 6. Update conversation activity on message insert
-- Advances last_message_at monotonically. NOTE: this stored field is
-- NOT proof an unexpired message still exists — list queries in phase 3
-- must validate the newest UNEXPIRED message (expires_at > NOW()).
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.update_dm_conversation_activity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public.dm_conversations
    SET last_message_at = NEW.created_at
    WHERE id = NEW.conversation_id
      AND (
          last_message_at IS NULL
          OR last_message_at < NEW.created_at
      );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_update_dm_conversation_activity ON public.dm_messages;

CREATE TRIGGER trg_update_dm_conversation_activity
AFTER INSERT
ON public.dm_messages
FOR EACH ROW
EXECUTE FUNCTION public.update_dm_conversation_activity();

-- ────────────────────────────────────────────────────────────
-- 7. Validate dm_reads participant against the conversation
-- (defense-in-depth)
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.validate_dm_read_participant()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row public.dm_conversations%ROWTYPE;
BEGIN
    SELECT *
    INTO conversation_row
    FROM public.dm_conversations
    WHERE id = NEW.conversation_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'DM conversation does not exist';
    END IF;

    IF NEW.persona_author_id <> conversation_row.persona_lo
       AND NEW.persona_author_id <> conversation_row.persona_hi THEN
        RAISE EXCEPTION 'DM read participant does not match conversation';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_dm_read_participant ON public.dm_reads;

CREATE TRIGGER trg_validate_dm_read_participant
BEFORE INSERT OR UPDATE OF conversation_id, persona_author_id
ON public.dm_reads
FOR EACH ROW
EXECUTE FUNCTION public.validate_dm_read_participant();

-- ────────────────────────────────────────────────────────────
-- 8. Indexes matching future query patterns.
-- (persona_lo, persona_hi) is already indexed by dm_conversations_unique_pair.
-- ────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS dm_conversations_persona_lo_idx
    ON public.dm_conversations (persona_lo);

CREATE INDEX IF NOT EXISTS dm_conversations_persona_hi_idx
    ON public.dm_conversations (persona_hi);

CREATE INDEX IF NOT EXISTS dm_conversations_last_message_at_idx
    ON public.dm_conversations (last_message_at DESC);

CREATE INDEX IF NOT EXISTS dm_messages_conversation_created_idx
    ON public.dm_messages (conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS dm_messages_recipient_created_idx
    ON public.dm_messages (recipient_author_id, created_at DESC);

CREATE INDEX IF NOT EXISTS dm_messages_conversation_recipient_created_idx
    ON public.dm_messages (conversation_id, recipient_author_id, created_at DESC);

CREATE INDEX IF NOT EXISTS dm_messages_expires_at_idx
    ON public.dm_messages (expires_at);

CREATE INDEX IF NOT EXISTS dm_reads_persona_idx
    ON public.dm_reads (persona_author_id);

-- ────────────────────────────────────────────────────────────
-- 9. Row-Level Security: enabled with NO policies => fully locked
-- to direct anon/authenticated access. Service role bypasses RLS.
-- Mirrors public.echoes.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.dm_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dm_messages      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dm_reads         ENABLE ROW LEVEL SECURITY;
-- No SELECT/INSERT/UPDATE/DELETE policies: private by design.

-- ────────────────────────────────────────────────────────────
-- 10. Grants: revoke all direct access from anon + authenticated
-- (defense-in-depth alongside RLS). Does NOT affect the service role.
-- ────────────────────────────────────────────────────────────
REVOKE ALL ON TABLE public.dm_conversations FROM anon, authenticated;
REVOKE ALL ON TABLE public.dm_messages      FROM anon, authenticated;
REVOKE ALL ON TABLE public.dm_reads         FROM anon, authenticated;

REVOKE ALL ON SEQUENCE public.dm_conversations_id_seq FROM anon, authenticated;
REVOKE ALL ON SEQUENCE public.dm_messages_id_seq      FROM anon, authenticated;

-- ────────────────────────────────────────────────────────────
-- 11. Comments (identity semantics)
-- ────────────────────────────────────────────────────────────
COMMENT ON TABLE public.dm_conversations IS
'Private one-to-one Persona DM conversations. Persona pair is stored in canonical lexicographic order.';

COMMENT ON COLUMN public.dm_conversations.persona_lo IS
'Lexicographically smaller Persona author_id.';

COMMENT ON COLUMN public.dm_conversations.persona_hi IS
'Lexicographically larger Persona author_id.';

COMMENT ON TABLE public.dm_messages IS
'Private text DM messages that become inaccessible 24 hours after creation.';

COMMENT ON COLUMN public.dm_messages.sender_author_id IS
'Source Persona author_id. Never an account or device ID.';

COMMENT ON COLUMN public.dm_messages.recipient_author_id IS
'Recipient Persona author_id. Never an account or device ID.';

COMMENT ON TABLE public.dm_reads IS
'Recipient-only internal conversation-open state used to calculate unread counts. Never exposed as public read receipts.';

COMMIT;

-- ────────────────────────────────────────────────────────────
-- 12. Force PostgREST to reload its schema cache so the Worker (via the
-- Supabase REST layer) recognizes the new tables immediately.
-- ────────────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';
