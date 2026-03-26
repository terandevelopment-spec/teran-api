-- Header Glass Mode: add glass columns to rooms table
-- Run in Supabase SQL Editor

ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_glass_enabled  boolean NOT NULL DEFAULT false;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_glass_style    text    NOT NULL DEFAULT 'frosted';
