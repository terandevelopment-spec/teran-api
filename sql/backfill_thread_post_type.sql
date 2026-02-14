-- Backfill existing threads that were incorrectly stored as post_type='status'.
-- Threads are identified by: no room_id, no parent_post_id, and a non-empty title.
UPDATE posts
SET post_type = 'thread'
WHERE (post_type IS NULL OR post_type = 'status')
  AND room_id IS NULL
  AND parent_post_id IS NULL
  AND title IS NOT NULL
  AND length(trim(title)) > 0;
