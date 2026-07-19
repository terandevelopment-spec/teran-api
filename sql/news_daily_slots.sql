-- Immutable, append-only fixed daily News Feed slots.
-- Backs GET /api/rss?category=<category>&date=YYYY-MM-DD (JST calendar date).
-- Run this in the Supabase SQL Editor. Do NOT run automatically.
--
-- For each (category, news_date) there is an ordered set of up to 8 slots
-- (slot_index 0..7). Each row is a COMPLETE, immutable article snapshot taken
-- at selection time; it must never depend on later changes in news_articles.
-- Slots are insert-only: existing slots are never updated, reordered, or
-- deleted. Empty slots may be filled later without touching existing ones.
--
-- Access model: written and read exclusively by the Worker using the Supabase
-- service_role key (which bypasses RLS). RLS is enabled with no policies so the
-- table is never readable through the anon/public API.

CREATE TABLE IF NOT EXISTS news_daily_slots (
  id           bigserial   PRIMARY KEY,
  category     text        NOT NULL,
  news_date    date        NOT NULL,
  slot_index   smallint    NOT NULL,
  source_id    text        NOT NULL,
  article_id   text        NOT NULL,
  title        text        NOT NULL,
  description  text        NOT NULL DEFAULT '',
  image_url    text        NULL,
  link         text        NOT NULL,
  pub_date     timestamptz NOT NULL,
  selected_at  timestamptz NOT NULL DEFAULT now(),

  -- One article per slot for a given category/date.
  CONSTRAINT news_daily_slots_slot_uq
    UNIQUE (category, news_date, slot_index),

  -- The same source article may occupy at most one slot per category/date.
  CONSTRAINT news_daily_slots_article_uq
    UNIQUE (category, news_date, source_id, article_id),

  -- Valid slot range.
  CONSTRAINT news_daily_slots_index_range
    CHECK (slot_index BETWEEN 0 AND 7)
);

-- Ordered read path: slots for a category/date, by slot index. The slot
-- uniqueness constraint already provides the (category, news_date, slot_index)
-- index used by this query, so no additional index is required.

-- Deny-by-default: only the service_role key (used by the Worker) may access.
ALTER TABLE news_daily_slots ENABLE ROW LEVEL SECURITY;
