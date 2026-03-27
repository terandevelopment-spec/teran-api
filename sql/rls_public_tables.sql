-- ============================================================
-- RLS Policy Pass: Public-Facing Tables
-- ============================================================
-- Defense-in-depth: the app uses service role via teran-api,
-- so these policies only affect direct PostgREST / anon-key access.
-- All writes go through the service role and bypass RLS.
--
-- Run in Supabase SQL Editor. Idempotent: safe to re-run.
-- ============================================================


-- ────────────────────────────────────────────────────────────
-- 1. public.posts
-- Public feed data. Filter out soft-deleted rows.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "posts_select_public"
  ON public.posts
  FOR SELECT
  USING (deleted_at IS NULL);


-- ────────────────────────────────────────────────────────────
-- 2. public.comments
-- Public comment data displayed under posts.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "comments_select_public"
  ON public.comments
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 3. public.user_profiles
-- Public profile data (display name, bio, avatar) for feed.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "user_profiles_select_public"
  ON public.user_profiles
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 4. public.profile_gallery
-- Public gallery slots shown on profile pages.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.profile_gallery ENABLE ROW LEVEL SECURITY;

CREATE POLICY "profile_gallery_select_public"
  ON public.profile_gallery
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 5. public.post_likes
-- Public like data for feed display and counts.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.post_likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "post_likes_select_public"
  ON public.post_likes
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 6. public.comment_likes
-- Public like data for comment display.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.comment_likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "comment_likes_select_public"
  ON public.comment_likes
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 7. public.news_comments
-- Public news comment data.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.news_comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "news_comments_select_public"
  ON public.news_comments
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 8. public.news_comment_likes
-- Public news comment like data.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.news_comment_likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "news_comment_likes_select_public"
  ON public.news_comment_likes
  FOR SELECT
  USING (true);


-- ────────────────────────────────────────────────────────────
-- 9. public.echoes
-- Private follow-like feature. No public visibility needed.
-- RLS enabled with NO policies = fully locked to direct access.
-- Only service role (teran-api) can read/write.
-- ────────────────────────────────────────────────────────────
ALTER TABLE public.echoes ENABLE ROW LEVEL SECURITY;

-- No SELECT policy: echoes are private by design.
