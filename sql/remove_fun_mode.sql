-- remove_fun_mode.sql
-- Removes 'Fun' from the posts_mode_check constraint.
-- Canonical modes after this change: Ask, Discuss, Share
-- Run in Supabase SQL Editor.

-- 1) Confirm no Fun rows exist:
-- SELECT count(*) FROM public.posts WHERE mode = 'Fun';

-- 2) Drop old constraint and add updated one:
ALTER TABLE public.posts DROP CONSTRAINT posts_mode_check;

ALTER TABLE public.posts ADD CONSTRAINT posts_mode_check
  CHECK (mode IN ('Ask', 'Discuss', 'Share'));

-- 3) Verify:
-- SELECT c.conname, pg_get_constraintdef(c.oid) AS def
-- FROM pg_constraint c
-- JOIN pg_class t ON t.oid = c.conrelid
-- JOIN pg_namespace n ON n.oid = t.relnamespace
-- WHERE n.nspname = 'public' AND t.relname = 'posts'
-- ORDER BY c.conname;
