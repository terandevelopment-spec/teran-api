-- Post Appearance Overrides
-- Stores visual-only presentation overrides for room-origin posts.
-- The canonical posts table is NEVER modified by this system.
-- Run in Supabase SQL Editor after reviewing.

CREATE TABLE IF NOT EXISTS post_appearance_overrides (
  post_id         INTEGER PRIMARY KEY REFERENCES public.posts(id) ON DELETE CASCADE,
  display_name    TEXT,        -- overrides author_name in display only
  display_avatar  TEXT,        -- overrides author_avatar in display only (preset key or R2 key — same format as posts.author_avatar)
  display_content TEXT,        -- overrides content in display only
  is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No additional index needed: the only access pattern is
--   WHERE post_id = ANY($1) — covered by the PRIMARY KEY index.

-- RLS note:
-- Reads are public (the override is just a display layer — the result is already public).
-- Writes are gated at the Cloudflare Worker layer via JWT auth + author_id ownership check.
-- If RLS is preferred over Worker-level enforcement, add policies here.
