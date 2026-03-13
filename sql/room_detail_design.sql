-- Room Detail Design: add inside-thread/detail page visual customisation columns
-- Run in Supabase SQL Editor

-- Detail page colour fields (free-form hex strings, e.g. '#111111')
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_bg_color           text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_card_bg_color      text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_card_text_color    text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_bg_color   text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_text_color text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_accent_color       text;

-- Comment input-area design fields (inside-thread composer customisation)
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_input_bg_color   text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_input_text_color text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_comment_bar_bg_color     text;

-- Avatar/icon visibility toggle for inside-thread pages
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_show_icons boolean DEFAULT true;

-- Avatar/icon visibility toggle for thread list/feed
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS list_show_icons boolean DEFAULT true;

-- Avatar/icon shape customisation (per layer)
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS list_icon_shape text DEFAULT 'circle';
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS detail_icon_shape text DEFAULT 'circle';

-- Custom header background image (R2 key)
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_bg_image_key text;

-- Header text visibility toggle
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_text_enabled boolean DEFAULT true;

-- Header area height preset (small / medium / large)
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS header_height text DEFAULT 'medium';

-- Room background image (R2 key) and opacity for the image layer
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS room_bg_image_key text;
ALTER TABLE public.rooms ADD COLUMN IF NOT EXISTS room_bg_image_opacity real DEFAULT 1.0;
