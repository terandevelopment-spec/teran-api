-- Add room metadata to notifications table for room-post notification rendering
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS room_id text NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS room_icon_key text NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS room_emoji text NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS room_name text NULL;
