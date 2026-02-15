-- Add persona_tags column to user_profiles for storing up to 3 genre/category preferences.
-- Default empty array, max 3 elements enforced by constraint + API validation.
ALTER TABLE public.user_profiles
ADD COLUMN IF NOT EXISTS persona_tags text[] NOT NULL DEFAULT '{}';

-- Enforce max 3 tags at DB level as safety net
ALTER TABLE public.user_profiles
ADD CONSTRAINT persona_tags_max3
CHECK (array_length(persona_tags, 1) IS NULL OR array_length(persona_tags, 1) <= 3);
