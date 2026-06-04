-- ============================================================
-- RPC function for comment counts (comments table)
-- ============================================================
--
-- Used by: GET /api/comments/counts?post_ids=1,2,3
-- Current: SELECT post_id FROM comments WHERE post_id IN (...)
--   → fetches ALL rows, counts in JS (wasteful)
-- After: SELECT post_id, count(*) GROUP BY post_id
--   → returns only 13 rows for 13 post_ids (not N*comments rows)
--
-- Safe to run in Supabase SQL Editor.
-- ============================================================

CREATE OR REPLACE FUNCTION public.get_comments_counts(p_post_ids bigint[])
RETURNS TABLE (post_id bigint, comment_count bigint)
LANGUAGE sql
STABLE
AS $$
  SELECT c.post_id, count(*)::bigint AS comment_count
  FROM public.comments c
  WHERE c.post_id = ANY(p_post_ids)
  GROUP BY c.post_id
$$;
