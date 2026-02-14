-- Profile visibility settings: per-tab public/private toggles
CREATE TABLE IF NOT EXISTS profile_settings (
  user_id        text PRIMARY KEY,
  posts_public   boolean NOT NULL DEFAULT true,
  threads_public boolean NOT NULL DEFAULT true,
  rooms_public   boolean NOT NULL DEFAULT true,
  saved_public   boolean NOT NULL DEFAULT false,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
