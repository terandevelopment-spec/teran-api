-- posts_mode_constraint.sql
-- Adds DB-level enforcement for posts.mode column.
-- Canonical values: Ask, Discuss, Share, Fun
-- Run in Supabase SQL Editor against production DB.
--
-- SAFE ORDER: inspect → backfill → default → not null → check

-- ============================================================
-- A) Confirm environment
-- ============================================================
-- Run this first to confirm you're on the right DB:
-- select current_database(), current_user, now();

-- ============================================================
-- B) Inspect current data (run these SELECT queries first)
-- ============================================================

-- B1) Current distribution
-- select mode, count(*) as n
-- from public.posts
-- group by mode
-- order by n desc;

-- B2) Null + invalid count
-- select mode, count(*) as n
-- from public.posts
-- where mode is null
--    or mode not in ('Ask','Discuss','Share','Fun')
-- group by mode
-- order by n desc;

-- ============================================================
-- C) Backfill — normalize invalid/null values to 'Discuss'
--    ONLY run if B2 returned rows
-- ============================================================

UPDATE public.posts
SET mode = 'Discuss'
WHERE mode IS NULL
   OR mode NOT IN ('Ask','Discuss','Share','Fun');

-- ============================================================
-- D) Enforce at DB level (run in this exact order)
-- ============================================================

-- D1) Set default so future INSERTs without mode get 'Discuss'
ALTER TABLE public.posts
  ALTER COLUMN mode SET DEFAULT 'Discuss';

-- D2) Set NOT NULL (safe after backfill)
ALTER TABLE public.posts
  ALTER COLUMN mode SET NOT NULL;

-- D3) Add CHECK constraint (final safety net)
ALTER TABLE public.posts
  ADD CONSTRAINT posts_mode_check
  CHECK (mode IN ('Ask','Discuss','Share','Fun'));

-- ============================================================
-- E) Verify — run these after D completes
-- ============================================================

-- E1) Confirm constraint exists:
-- select c.conname, pg_get_constraintdef(c.oid) as def
-- from pg_constraint c
-- join pg_class t on t.oid = c.conrelid
-- join pg_namespace n on n.oid = t.relnamespace
-- where n.nspname='public' and t.relname='posts'
-- order by c.conname;

-- E2) Confirm distribution is clean:
-- select mode, count(*) as n
-- from public.posts
-- group by mode
-- order by n desc;
