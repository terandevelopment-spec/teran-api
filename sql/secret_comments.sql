-- Secret Comments: propagate secret identity from thread owner's comments
-- When the thread owner comments on their own secret thread, their comment
-- inherits is_secret=true and the thread's secret_color. Server enforces.
ALTER TABLE comments ADD COLUMN IF NOT EXISTS is_secret BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE comments ADD COLUMN IF NOT EXISTS secret_color TEXT NULL;
