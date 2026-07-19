-- Room links: Private Room → Private Room navigation relationships
-- Run in Supabase SQL Editor
--
-- A room_links row records that the owner of a *source* Private Room has
-- attached a *target* Private Room for navigation purposes (e.g. a linked-room
-- row in the source Room's feed header).
--
-- IMPORTANT — this table stores NAVIGATION RELATIONSHIPS ONLY.
--   * It NEVER grants membership, roles, or Post/Join permission of any kind.
--   * It NEVER stores an invite token. The target Room's invite token is used
--     once, at link-creation time, purely as proof that the source owner was
--     invited; only the canonical target Room UUID is persisted here.
--   * Revoking the target Room's invite later does NOT remove existing links.
--   * Only Private Rooms (rooms.visibility = 'private_invite_only') are ever
--     linked; Public Rooms are rejected in Worker code before any insert.

CREATE TABLE IF NOT EXISTS room_links (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source_room_id text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  target_room_id text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  created_by     text NOT NULL,                 -- device_id/user_id of the source owner who created the link
  position       integer NOT NULL DEFAULT 0,    -- display order within the source Room (0-based)
  created_at     timestamptz NOT NULL DEFAULT now(),

  -- One link per ordered (source, target) pair
  CONSTRAINT room_links_pair_unique UNIQUE (source_room_id, target_room_id),
  -- A Room may never link to itself
  CONSTRAINT room_links_no_self CHECK (source_room_id <> target_room_id)
);

-- Ordered listing of a source Room's links (position, then created_at tiebreak)
CREATE INDEX IF NOT EXISTS idx_room_links_source_order
  ON room_links (source_room_id, position, created_at);

-- Reverse lookups / cascade support by target Room
CREATE INDEX IF NOT EXISTS idx_room_links_target
  ON room_links (target_room_id);
