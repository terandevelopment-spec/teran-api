-- Room Avatar Options: selectable icons for Room participants
-- Phase 1: schema only. Phase 2 enables the user-facing selection flow.

-- 1) room_avatar_options — icons defined by Room creator
CREATE TABLE IF NOT EXISTS room_avatar_options (
  id          text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  room_id     text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  icon_key    text NOT NULL,           -- R2 key (full-size)
  thumb_key   text,                    -- R2 key (128px thumb)
  label       text,                    -- optional display label
  sort_order  int NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_room_avatar_options_room
  ON room_avatar_options(room_id, sort_order);

-- 2) room_members — per-user icon choice for a Room
ALTER TABLE room_members
  ADD COLUMN IF NOT EXISTS avatar_mode text DEFAULT 'persona',
  ADD COLUMN IF NOT EXISTS room_avatar_option_id text
    REFERENCES room_avatar_options(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS room_avatar_key text;

-- avatar_mode check constraint (added separately for IF NOT EXISTS safety)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'room_members_avatar_mode_check'
  ) THEN
    ALTER TABLE room_members
      ADD CONSTRAINT room_members_avatar_mode_check
      CHECK (avatar_mode IN ('persona', 'room_icon'));
  END IF;
END $$;

-- 3) posts — flag to skip live-avatar override for Room-icon posts (Phase 2 usage)
ALTER TABLE posts
  ADD COLUMN IF NOT EXISTS uses_room_avatar boolean DEFAULT false;
