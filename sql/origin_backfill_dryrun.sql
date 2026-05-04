-- ============================================================
-- Dry-run: Show teran.origin posts with active appearance overrides
-- that need canonical field backfill.
--
-- This query identifies posts where the appearance override has
-- different values than the canonical post fields.
--
-- DO NOT EXECUTE UPDATE STATEMENTS until manually reviewed.
-- ============================================================

-- Step 1: Identify the teran.origin account(s)
-- SELECT a.id AS account_id, a.teran_handle, ad.device_id
-- FROM accounts a
-- JOIN account_devices ad ON ad.account_id = a.id
-- WHERE a.teran_handle = 'teran.origin';

-- Step 2: Dry-run — show all posts with active overrides
-- that belong to teran.origin (by matching user_id to device_ids above)
--
-- Replace '<device_id_1>', '<device_id_2>' with actual device IDs
-- from Step 1, or use the subquery version below.

SELECT
  p.id                AS post_id,
  p.room_id,
  p.author_name       AS current_author_name,
  o.display_name      AS override_display_name,
  CASE WHEN p.author_name IS DISTINCT FROM o.display_name THEN '⚠️ DIFFERS' ELSE '✅ MATCH' END AS name_status,
  p.author_avatar     AS current_author_avatar,
  o.display_avatar    AS override_display_avatar,
  CASE WHEN p.author_avatar IS DISTINCT FROM o.display_avatar THEN '⚠️ DIFFERS' ELSE '✅ MATCH' END AS avatar_status,
  LEFT(p.content, 60) AS current_content_preview,
  LEFT(o.display_content, 60) AS override_content_preview,
  CASE WHEN p.content IS DISTINCT FROM o.display_content THEN '⚠️ DIFFERS' ELSE '✅ MATCH' END AS content_status,
  o.is_enabled,
  o.updated_at        AS override_updated_at
FROM posts p
JOIN post_appearance_overrides o ON o.post_id = p.id
WHERE o.is_enabled = true
  AND p.user_id IN (
    SELECT ad.device_id
    FROM accounts a
    JOIN account_devices ad ON ad.account_id = a.id
    WHERE a.teran_handle = 'teran.origin'
  )
  AND (
    p.author_name IS DISTINCT FROM o.display_name
    OR p.author_avatar IS DISTINCT FROM o.display_avatar
    OR p.content IS DISTINCT FROM o.display_content
  )
ORDER BY p.id;

-- ============================================================
-- Step 3: BACKFILL (run only after reviewing Step 2 results)
-- ============================================================
-- UPDATE posts SET
--   author_name   = COALESCE(o.display_name,   posts.author_name),
--   author_avatar = COALESCE(o.display_avatar,  posts.author_avatar),
--   content       = COALESCE(o.display_content, posts.content)
-- FROM post_appearance_overrides o
-- WHERE o.post_id = posts.id
--   AND o.is_enabled = true
--   AND posts.user_id IN (
--     SELECT ad.device_id
--     FROM accounts a
--     JOIN account_devices ad ON ad.account_id = a.id
--     WHERE a.teran_handle = 'teran.origin'
--   )
--   AND (
--     posts.author_name IS DISTINCT FROM o.display_name
--     OR posts.author_avatar IS DISTINCT FROM o.display_avatar
--     OR posts.content IS DISTINCT FROM o.display_content
--   );
