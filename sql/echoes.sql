-- Echoes table for private follow-like feature
-- No public visibility, no counts, no notifications

CREATE TABLE IF NOT EXISTS public.echoes (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,              -- the echoing user (JWT sub)
  echoed_user_id TEXT NOT NULL,       -- the target user being echoed
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT echoes_unique UNIQUE (user_id, echoed_user_id),
  CONSTRAINT echoes_no_self CHECK (user_id <> echoed_user_id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS echoes_user_id_idx ON public.echoes (user_id);
CREATE INDEX IF NOT EXISTS echoes_echoed_user_id_idx ON public.echoes (echoed_user_id);
