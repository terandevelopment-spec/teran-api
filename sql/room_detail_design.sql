-- Room Detail Design: add inside-thread/detail page visual customisation columns
-- Run in Supabase SQL Editor

-- Detail page colour fields (free-form hex strings, e.g. '#111111')
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_bg_color           text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_card_bg_color      text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_card_text_color    text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_bg_color   text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_text_color text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_accent_color       text;
