-- Add news_id and news_url to notifications table for news comment notifications
-- Run this in Supabase SQL Editor
-- Both columns are nullable so existing post notification rows are unaffected.

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS news_id text NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS news_url text NULL;
