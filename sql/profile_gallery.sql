-- Profile gallery table for storing up to 6 media keys per user
-- No auth required; client sends user_id

CREATE TABLE IF NOT EXISTS public.profile_gallery (
  user_id TEXT PRIMARY KEY,
  slots TEXT[] NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
