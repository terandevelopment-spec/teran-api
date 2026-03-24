-- teran_id: optional custom handle per persona
-- Nullable — existing users will have NULL until they set one.
-- Partial unique index ensures case-insensitive uniqueness for non-null values.

ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS teran_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_teran_id_unique
  ON public.user_profiles (LOWER(teran_id))
  WHERE teran_id IS NOT NULL;
