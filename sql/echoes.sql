-- Echoes table for private follow-like feature (Persona-to-Persona)
-- No public visibility, no counts, no notifications.
-- See migrations/echoes_persona_to_persona.sql for the upgrade from the original
-- account-level schema.

CREATE TABLE IF NOT EXISTS public.echoes (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,              -- authenticated account/device identity (JWT sub) that owns the source Persona
  echoer_author_id TEXT NOT NULL,     -- source Persona author_id (who performed the Echo)
  echoed_user_id TEXT NOT NULL,       -- target Persona author_id (who is being echoed)
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT echoes_persona_unique UNIQUE (echoer_author_id, echoed_user_id),
  CONSTRAINT echoes_no_self_persona CHECK (echoer_author_id <> echoed_user_id)
);

-- Indexes for outgoing, incoming, and newest-first pagination.
CREATE INDEX IF NOT EXISTS echoes_user_id_idx ON public.echoes (user_id);
CREATE INDEX IF NOT EXISTS echoes_echoer_author_id_idx ON public.echoes (echoer_author_id);
CREATE INDEX IF NOT EXISTS echoes_echoed_user_id_idx ON public.echoes (echoed_user_id);
CREATE INDEX IF NOT EXISTS echoes_incoming_idx ON public.echoes (echoed_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS echoes_outgoing_idx ON public.echoes (echoer_author_id, created_at DESC);
