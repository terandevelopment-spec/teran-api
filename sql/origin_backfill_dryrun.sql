-- ============================================================
-- teran.origin Canonical Backfill
-- ============================================================
--
-- Purpose:
--   Copy active appearance override values into canonical post
--   fields for posts owned by teran.origin ONLY.
--
-- Join path (same pattern as backend PATCH handler):
--   posts.user_id  →  account_devices.device_id
--   account_devices.account_id  →  accounts.id
--   accounts.teran_handle = 'teran.origin'
--
-- Safety:
--   - Only touches posts where teran_handle = 'teran.origin'
--   - Only touches posts with is_enabled = true overrides
--   - Only touches posts where at least one override field is non-null
--   - Only updates fields where the override differs from canonical
--   - COALESCE prevents overwriting canonical with NULL
--
-- DO NOT RUN THE UPDATE UNTIL THE DRY-RUN IS REVIEWED.
-- ============================================================


-- ══════════════════════════════════════════════════════════════
-- STEP 0: Verify teran.origin device IDs
-- ══════════════════════════════════════════════════════════════
-- Run this first to confirm the origin account exists and see
-- which device_ids map to it.

SELECT
  a.id            AS account_id,
  a.teran_handle,
  ad.device_id
FROM accounts a
JOIN account_devices ad ON ad.account_id = a.id
WHERE a.teran_handle = 'teran.origin';


-- ══════════════════════════════════════════════════════════════
-- STEP 1: DRY-RUN SELECT — all affected rows
-- ══════════════════════════════════════════════════════════════
-- Shows every teran.origin post with an active override where
-- at least one field differs from the canonical value.

SELECT
  p.id                                AS post_id,
  p.room_id,
  p.post_type,
  p.author_name                       AS current_author_name,
  o.display_name                      AS override_display_name,
  CASE
    WHEN o.display_name IS NULL                         THEN '— skip (null)'
    WHEN p.author_name IS NOT DISTINCT FROM o.display_name THEN '✅ match'
    ELSE '⚠️ WILL UPDATE'
  END                                 AS name_action,
  p.author_avatar                     AS current_author_avatar,
  o.display_avatar                    AS override_display_avatar,
  CASE
    WHEN o.display_avatar IS NULL                            THEN '— skip (null)'
    WHEN p.author_avatar IS NOT DISTINCT FROM o.display_avatar THEN '✅ match'
    ELSE '⚠️ WILL UPDATE'
  END                                 AS avatar_action,
  LEFT(p.content, 80)                 AS current_content_preview,
  LEFT(o.display_content, 80)         AS override_content_preview,
  CASE
    WHEN o.display_content IS NULL                        THEN '— skip (null)'
    WHEN p.content IS NOT DISTINCT FROM o.display_content THEN '✅ match'
    ELSE '⚠️ WILL UPDATE'
  END                                 AS content_action,
  o.is_enabled,
  o.updated_at                        AS override_updated_at
FROM posts p
JOIN post_appearance_overrides o ON o.post_id = p.id
WHERE
  -- Only active overrides
  o.is_enabled = true
  -- Only teran.origin posts
  AND p.user_id IN (
    SELECT ad.device_id
    FROM accounts a
    JOIN account_devices ad ON ad.account_id = a.id
    WHERE a.teran_handle = 'teran.origin'
  )
  -- At least one override field is non-null
  AND (o.display_name IS NOT NULL
    OR o.display_avatar IS NOT NULL
    OR o.display_content IS NOT NULL)
  -- At least one field actually differs
  AND (
    (o.display_name    IS NOT NULL AND p.author_name   IS DISTINCT FROM o.display_name)
    OR (o.display_avatar IS NOT NULL AND p.author_avatar IS DISTINCT FROM o.display_avatar)
    OR (o.display_content IS NOT NULL AND p.content      IS DISTINCT FROM o.display_content)
  )
ORDER BY p.id;


-- ══════════════════════════════════════════════════════════════
-- STEP 1b: SAFETY COUNT — confirm zero non-origin posts
-- ══════════════════════════════════════════════════════════════
-- This must return 0.  If it returns > 0, STOP — the filter is wrong.

SELECT COUNT(*) AS non_origin_posts_with_overrides
FROM posts p
JOIN post_appearance_overrides o ON o.post_id = p.id
WHERE o.is_enabled = true
  AND p.user_id NOT IN (
    SELECT ad.device_id
    FROM accounts a
    JOIN account_devices ad ON ad.account_id = a.id
    WHERE a.teran_handle = 'teran.origin'
  )
  AND (o.display_name IS NOT NULL
    OR o.display_avatar IS NOT NULL
    OR o.display_content IS NOT NULL);


-- ══════════════════════════════════════════════════════════════
-- STEP 2: BACKFILL UPDATE (do NOT run until Step 1 is reviewed)
-- ══════════════════════════════════════════════════════════════
-- Uncomment to execute.  Uses COALESCE so NULL override fields
-- do not overwrite existing canonical values.

-- UPDATE posts SET
--   author_name   = COALESCE(o.display_name,   posts.author_name),
--   author_avatar = COALESCE(o.display_avatar,  posts.author_avatar),
--   content       = COALESCE(o.display_content, posts.content),
--   edited_at     = now()
-- FROM post_appearance_overrides o
-- WHERE o.post_id = posts.id
--   AND o.is_enabled = true
--   AND posts.user_id IN (
--     SELECT ad.device_id
--     FROM accounts a
--     JOIN account_devices ad ON ad.account_id = a.id
--     WHERE a.teran_handle = 'teran.origin'
--   )
--   AND (o.display_name IS NOT NULL
--     OR o.display_avatar IS NOT NULL
--     OR o.display_content IS NOT NULL)
--   AND (
--     (o.display_name    IS NOT NULL AND posts.author_name   IS DISTINCT FROM o.display_name)
--     OR (o.display_avatar IS NOT NULL AND posts.author_avatar IS DISTINCT FROM o.display_avatar)
--     OR (o.display_content IS NOT NULL AND posts.content      IS DISTINCT FROM o.display_content)
--   );


-- ══════════════════════════════════════════════════════════════
-- STEP 3: VERIFICATION — run after the UPDATE
-- ══════════════════════════════════════════════════════════════
-- After running the UPDATE, re-run Step 1.
-- It should return 0 rows (all canonical fields now match).

-- Also run this to confirm edited_at was set:
-- SELECT id, author_name, author_avatar, LEFT(content, 60), edited_at
-- FROM posts
-- WHERE edited_at >= now() - interval '5 minutes'
-- ORDER BY id;


-- ══════════════════════════════════════════════════════════════
-- ROLLBACK NOTES
-- ══════════════════════════════════════════════════════════════
-- There is no automatic rollback.
--
-- However, the original canonical values are still preserved
-- in the post creation snapshot:
--   - The original author_name was the persona name at creation time.
--     It can be recovered from user_profiles.display_name if the
--     persona hasn't changed, or from notification actor_name snapshots.
--   - The original content was the text entered at post creation.
--     There is no content history table, so once overwritten, the
--     original content is not recoverable from DB alone.
--
-- Recommendation: Before running the UPDATE, capture a backup:
--
-- CREATE TABLE IF NOT EXISTS _backfill_pre_origin (
--   post_id         INTEGER PRIMARY KEY,
--   old_author_name TEXT,
--   old_author_avatar TEXT,
--   old_content     TEXT,
--   backed_up_at    TIMESTAMPTZ DEFAULT now()
-- );
--
-- INSERT INTO _backfill_pre_origin (post_id, old_author_name, old_author_avatar, old_content)
-- SELECT p.id, p.author_name, p.author_avatar, p.content
-- FROM posts p
-- JOIN post_appearance_overrides o ON o.post_id = p.id
-- WHERE o.is_enabled = true
--   AND p.user_id IN (
--     SELECT ad.device_id
--     FROM accounts a
--     JOIN account_devices ad ON ad.account_id = a.id
--     WHERE a.teran_handle = 'teran.origin'
--   )
--   AND (o.display_name IS NOT NULL
--     OR o.display_avatar IS NOT NULL
--     OR o.display_content IS NOT NULL)
--   AND (
--     (o.display_name    IS NOT NULL AND p.author_name   IS DISTINCT FROM o.display_name)
--     OR (o.display_avatar IS NOT NULL AND p.author_avatar IS DISTINCT FROM o.display_avatar)
--     OR (o.display_content IS NOT NULL AND p.content      IS DISTINCT FROM o.display_content)
--   );
