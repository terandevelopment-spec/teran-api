-- room_design_templates — DB-backed room design template system
-- Run this in the Supabase SQL Editor

CREATE TABLE room_design_templates (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  step          TEXT NOT NULL DEFAULT 'step2'
                  CHECK (step IN ('step2', 'step3', 'full')),
  card_styles   TEXT[] DEFAULT '{}',
  created_by    TEXT,                -- device_id (matches rooms.owner_id)
  visibility    TEXT NOT NULL DEFAULT 'private'
                  CHECK (visibility IN ('private', 'public', 'official')),
  design        JSONB NOT NULL DEFAULT '{}',
  image_keys    JSONB DEFAULT '{}',
  based_on_id   UUID REFERENCES room_design_templates(id) ON DELETE SET NULL,
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);

-- Indexes for common queries
CREATE INDEX idx_rdt_visibility ON room_design_templates(visibility);
CREATE INDEX idx_rdt_created_by ON room_design_templates(created_by);
CREATE INDEX idx_rdt_step ON room_design_templates(step);

-- RLS policies
ALTER TABLE room_design_templates ENABLE ROW LEVEL SECURITY;

-- Anyone can read public/official templates
CREATE POLICY "Public templates readable by all"
  ON room_design_templates FOR SELECT
  USING (visibility IN ('public', 'official'));

-- Creators can read their own private templates
CREATE POLICY "Private templates readable by creator"
  ON room_design_templates FOR SELECT
  USING (visibility = 'private' AND created_by = auth.uid()::text);

-- Authenticated users can insert their own templates
CREATE POLICY "Users can create templates"
  ON room_design_templates FOR INSERT
  WITH CHECK (created_by = auth.uid()::text);

-- Creators can update their own templates
CREATE POLICY "Users can update own templates"
  ON room_design_templates FOR UPDATE
  USING (created_by = auth.uid()::text);

-- Creators can delete their own templates
CREATE POLICY "Users can delete own templates"
  ON room_design_templates FOR DELETE
  USING (created_by = auth.uid()::text);
