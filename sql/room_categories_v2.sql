-- Room Categories v2: replace 16 categories with 11
-- Run in Supabase SQL Editor BEFORE deploying API + frontend

-- 1) Remap existing rooms from old categories → new categories
-- Direct matches (key unchanged): lounge, games, sports, creation, tech_gadgets, local_region, work_career
-- Mapped:
UPDATE public.rooms SET category = 'politics'  WHERE category IN ('news_current', 'philosophy_thinking');
UPDATE public.rooms SET category = 'spiritual'  WHERE category = 'health_mind';
-- Unmapped old keys → lounge
UPDATE public.rooms SET category = 'lounge'     WHERE category IN (
  'learning_skills', 'lifestyle_hobbies', 'money_planning',
  'love_relationships', 'help_qa', 'entertainment'
);

-- 2) Drop old constraint
ALTER TABLE public.rooms DROP CONSTRAINT IF EXISTS rooms_category_allowed;

-- 3) Add new constraint with exactly 11 values
ALTER TABLE public.rooms
ADD CONSTRAINT rooms_category_allowed
CHECK (category IN (
  'lounge',
  'anime_manga',
  'games',
  'music',
  'sports',
  'creation',
  'tech_gadgets',
  'local_region',
  'work_career',
  'politics',
  'spiritual'
));
