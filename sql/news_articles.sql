-- Historical news article storage for date-based news browsing.
-- Backs GET /api/rss?category=<category>&date=YYYY-MM-DD (JST calendar date).
-- Run this in the Supabase SQL Editor.
--
-- Access model: written and read exclusively by the Worker using the Supabase
-- service_role key (which bypasses RLS). RLS is enabled with no policies so the
-- table is never readable through the anon/public API.

CREATE TABLE IF NOT EXISTS news_articles (
  id           bigserial   PRIMARY KEY,
  category     text        NOT NULL,
  article_id   text        NOT NULL,
  title        text        NOT NULL,
  description  text        NOT NULL DEFAULT '',
  image_url    text        NULL,
  link         text        NOT NULL,
  source_id    text        NOT NULL DEFAULT 'yahoo_news',
  pub_date     timestamptz NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT news_articles_category_article_uq UNIQUE (category, article_id)
);

-- Primary query path: articles for a category within a UTC instant range,
-- newest first (JST day boundaries are converted to UTC in the Worker).
CREATE INDEX IF NOT EXISTS news_articles_category_pubdate_idx
  ON news_articles (category, pub_date DESC);

-- Deny-by-default: only the service_role key (used by the Worker) may access.
ALTER TABLE news_articles ENABLE ROW LEVEL SECURITY;
