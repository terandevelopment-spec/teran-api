-- Room Design: add visual customisation columns to rooms table
-- Run in Supabase SQL Editor

-- Colour fields (free-form hex strings, e.g. '#111111')
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_bg_color   text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_text_color text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS room_bg_color     text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS card_bg_color     text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS card_text_color   text;

-- Like button visibility toggle
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS like_visible      boolean;

-- Header typography
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_font_size   text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_font_family text;
