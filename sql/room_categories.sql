-- Room Categories: add category column, backfill, and constrain allowed values
-- Run in Supabase SQL Editor

-- 1) Add column
alter table public.rooms
add column if not exists category text;

-- 2) Backfill existing rooms with safe default
update public.rooms
set category = 'lounge'
where category is null;

-- 3) Allowed-values constraint
alter table public.rooms
drop constraint if exists rooms_category_allowed;

alter table public.rooms
add constraint rooms_category_allowed
check (category in (
  'local_region',
  'work_career',
  'learning_skills',
  'games',
  'creation',
  'tech_gadgets',
  'lifestyle_hobbies',
  'health_mind',
  'entertainment',
  'sports',
  'money_planning',
  'love_relationships',
  'philosophy_thinking',
  'news_current',
  'help_qa',
  'lounge'
));
