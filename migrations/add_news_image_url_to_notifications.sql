-- Add news_image_url column to notifications table
-- This stores the OG image thumbnail of the target news article
-- for rendering the right-side context marker in the notification UI.
ALTER TABLE public.notifications
  ADD COLUMN IF NOT EXISTS news_image_url text;

-- Extend the type CHECK constraint to include news notification types
-- (news_comment_like and news_comment_reply may already be in the constraint
-- from a previous migration; this is a safe idempotent re-apply)
ALTER TABLE public.notifications
  DROP CONSTRAINT IF EXISTS notifications_type_check;

ALTER TABLE public.notifications
  ADD CONSTRAINT notifications_type_check
  CHECK (type IN (
    'comment_like',
    'reply',
    'post_comment',
    'post_like',
    'post_reply',
    'news_comment_like',
    'news_comment_reply'
  ));
