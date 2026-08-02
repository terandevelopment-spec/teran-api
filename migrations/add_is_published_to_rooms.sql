-- Adds the Room publication gate.
-- Existing Rooms remain published because the database default is true.
-- New Rooms are explicitly inserted with is_published=false by the Worker.
-- Run this file manually in the Supabase SQL Editor before deploying the Worker.

ALTER TABLE rooms
  ADD COLUMN IF NOT EXISTS is_published boolean NOT NULL DEFAULT true;

CREATE INDEX IF NOT EXISTS rooms_is_published_idx
  ON rooms (is_published);
