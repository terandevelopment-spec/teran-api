-- TEMPORARY: MediaViewer PWA playback debug logging table.
-- Run this in the Supabase SQL Editor before enabling ?mvdbg=1 in the app.
--
-- The frontend (src/lib/mediaViewerDebug.js) inserts rows via the Supabase REST
-- API using the anon key, so we allow anon INSERT only. DROP this table (and the
-- policy) once the playback diagnosis is complete.

create table if not exists public.media_viewer_debug_logs (
  id                    uuid primary key default gen_random_uuid(),
  created_at            timestamptz not null default now(),
  session_id            text,
  sequence_id           text,
  source                text,
  phase                 text not null,
  post_id               text,
  media_key             text,
  media_url             text,
  item_type             text,
  safe_index            int,
  current_group_index   int,
  clamped_group_index   int,
  group_count           int,
  active_group_post_id  text,
  ms_since_sequence_start numeric,
  payload               jsonb
);

create index if not exists media_viewer_debug_logs_created_at_idx
  on public.media_viewer_debug_logs (created_at desc);
create index if not exists media_viewer_debug_logs_sequence_id_idx
  on public.media_viewer_debug_logs (sequence_id);
create index if not exists media_viewer_debug_logs_session_id_idx
  on public.media_viewer_debug_logs (session_id);

-- Allow anon inserts from the installed PWA (temporary diagnostic only).
alter table public.media_viewer_debug_logs enable row level security;

drop policy if exists media_viewer_debug_logs_anon_insert on public.media_viewer_debug_logs;
create policy media_viewer_debug_logs_anon_insert
  on public.media_viewer_debug_logs
  for insert
  to anon, authenticated
  with check (true);

-- Optional: allow reading back from the SQL editor / dashboard is unaffected by
-- RLS (service role bypasses it). If you want to read via anon, add a SELECT
-- policy too:
-- drop policy if exists media_viewer_debug_logs_anon_select on public.media_viewer_debug_logs;
-- create policy media_viewer_debug_logs_anon_select
--   on public.media_viewer_debug_logs for select to anon, authenticated using (true);

-- ── Cleanup when done ──────────────────────────────────────────────────
-- drop table if exists public.media_viewer_debug_logs cascade;
