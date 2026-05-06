-- Room anonymous identity IDs
-- Adds a short stable anonymous ID per user per room for room identity posts.
-- room_members.room_anon_id: persistent ID generated on first room identity usage
-- posts.room_anon_id: snapshot of the member's ID at post creation time

ALTER TABLE public.room_members
  ADD COLUMN IF NOT EXISTS room_anon_id text;

ALTER TABLE public.posts
  ADD COLUMN IF NOT EXISTS room_anon_id text;
