-- Phase 2: Remove Secret Mode columns
-- Run ONLY after code removal is deployed and verified.
-- Safe to run: all values are false/null (neutralized or never used).

ALTER TABLE posts DROP COLUMN IF EXISTS is_secret;
ALTER TABLE comments DROP COLUMN IF EXISTS is_secret;
ALTER TABLE comments DROP COLUMN IF EXISTS secret_color;
