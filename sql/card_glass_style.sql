-- Card Glass Style presets
-- Run in Supabase SQL editor, then reload schema cache
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS card_glass_style text DEFAULT 'frosted';
