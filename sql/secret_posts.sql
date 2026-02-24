-- Secret Posts: allow threads to hide author identity
-- Only meaningful for post_type='thread'; API enforces is_secret=false for non-threads.
ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_secret BOOLEAN NOT NULL DEFAULT false;
