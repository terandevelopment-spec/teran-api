-- Room Creator Display Name: allows room creators to define a custom
-- display name that users adopt when posting with the room identity.
-- Coupled with room avatar/icon — together they form the "room identity".

-- 1) rooms — optional creator-defined display name
ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS creator_display_name text;

-- 2) posts — flag to skip live-name overlay for room-identity posts
ALTER TABLE public.posts
  ADD COLUMN IF NOT EXISTS uses_room_display_name boolean DEFAULT false;
