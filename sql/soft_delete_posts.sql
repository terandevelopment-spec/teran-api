-- ============================================================
-- Migration: Add soft-delete support to posts table
-- ============================================================
-- Run in Supabase SQL Editor (one statement at a time).
-- Idempotent: safe to re-run.
-- ============================================================

-- Step 1: Add deleted_at column (NULL = not deleted)
ALTER TABLE posts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- Step 2: Partial index for efficient filtering (only index live posts)
CREATE INDEX IF NOT EXISTS idx_posts_not_deleted
  ON posts (deleted_at)
  WHERE deleted_at IS NULL;

-- Step 3: Index for cascade lookup (mark all descendants deleted by root_post_id)
-- This already exists as part of the replies query, but verify:
CREATE INDEX IF NOT EXISTS idx_posts_root_post_id
  ON posts (root_post_id);
