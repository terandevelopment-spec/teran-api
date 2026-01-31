-- Blocks table for user blocking (mutual visibility enforced client-side)

CREATE TABLE IF NOT EXISTS public.blocks (
  id BIGSERIAL PRIMARY KEY,
  blocker_user_id TEXT NOT NULL,
  blocked_user_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT blocks_unique UNIQUE (blocker_user_id, blocked_user_id),
  CONSTRAINT blocks_no_self CHECK (blocker_user_id <> blocked_user_id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS blocks_blocker_idx ON public.blocks (blocker_user_id);
CREATE INDEX IF NOT EXISTS blocks_blocked_idx ON public.blocks (blocked_user_id);
