-- Rooms feature: rooms, room_members, room_invites
-- Run in Supabase SQL Editor

-- 1) rooms
CREATE TABLE IF NOT EXISTS rooms (
  id          text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name        text NOT NULL,
  description text,
  emoji       text,
  icon_key    text,                          -- R2 key or URL (NO data: URIs)
  owner_id    text NOT NULL,                 -- matches user_profiles.user_id / JWT sub
  visibility  text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'private_invite_only')),
  read_policy text NOT NULL DEFAULT 'public' CHECK (read_policy IN ('public', 'members_only')),
  post_policy text NOT NULL DEFAULT 'members_only' CHECK (post_policy IN ('public', 'members_only')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- 2) room_members
CREATE TABLE IF NOT EXISTS room_members (
  room_id    text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id    text NOT NULL,
  role       text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (room_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_members_room_id ON room_members(room_id);
CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id);

-- 3) room_invites
CREATE TABLE IF NOT EXISTS room_invites (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  room_id    text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  token      text NOT NULL UNIQUE,
  revoked    boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_room_invites_room_id ON room_invites(room_id);
CREATE INDEX IF NOT EXISTS idx_room_invites_token   ON room_invites(token);

-- Index for listing public rooms sorted by creation date
CREATE INDEX IF NOT EXISTS idx_rooms_visibility_created ON rooms(visibility, created_at DESC);
