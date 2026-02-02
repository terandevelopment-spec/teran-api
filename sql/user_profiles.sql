-- User profiles table for storing profile header data (display name, bio, avatar)
-- Stage 1: READ path - used by GET /api/profile?user_id=...

CREATE TABLE IF NOT EXISTS public.user_profiles (
  user_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT 'Anonymous',
  bio TEXT,
  avatar TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
