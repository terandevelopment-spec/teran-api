-- Add room_id to notifications table for room-post notification routing
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS room_id text NULL;
