-- Returns direct reply counts for a list of parent post ids.
-- Used by GET /api/posts to enrich each root post with comment_count.
create or replace function public.get_comment_counts(parent_ids bigint[])
returns table (parent_post_id bigint, comment_count bigint)
language sql
stable
as $$
  select p.parent_post_id, count(*)::bigint as comment_count
  from public.posts p
  where p.parent_post_id = any(parent_ids)
  group by p.parent_post_id
$$;
