-- Persona-to-Persona Echo identity migration.
-- Run this in the Supabase SQL Editor. Idempotent and safe to rerun.
--
-- BEFORE: echoes stored only the account/device identity of the echoer
--   user_id        = authenticated account/device identity (JWT sub / device_id)
--   echoed_user_id = target Persona author_id
-- The source Persona that performed the Echo was NOT recorded.
--
-- AFTER: Echo relationships are Persona-to-Persona
--   user_id          = authenticated account/device identity (kept for authorization/audit)
--   echoer_author_id = source Persona author_id  (NEW)
--   echoed_user_id   = target Persona author_id
--   created_at       = relationship creation time
--
-- LEGACY-ROW POLICY (development/test data):
-- Existing rows contain no source Persona, and the schema has no authoritative
-- default-Persona mechanism (account_personas has no is_default flag), so legacy
-- rows CANNOT be correctly attributed to the Persona that actually performed the
-- Echo. Per the migration policy for unreleased development data, un-attributable
-- legacy rows are intentionally discarded rather than assigned an invented source
-- Persona (never the target, never device_id, never an arbitrary Persona).
-- The SELECT at the end reports how many rows were discarded.

BEGIN;

-- 1) Add the source-Persona column (nullable during backfill/cleanup).
ALTER TABLE public.echoes
  ADD COLUMN IF NOT EXISTS echoer_author_id TEXT;

-- 2) Discard un-attributable legacy rows (dev-data reset for rows with no source
--    Persona). Idempotent: only affects rows not yet carrying echoer_author_id.
DELETE FROM public.echoes
  WHERE echoer_author_id IS NULL;

-- 3) Defensive dedupe under the NEW Persona-to-Persona uniqueness rule, keeping the
--    earliest relationship per (echoer_author_id, echoed_user_id). No-op after a
--    clean reset; protects reruns and future backfills.
DELETE FROM public.echoes e
  USING public.echoes d
  WHERE e.echoer_author_id = d.echoer_author_id
    AND e.echoed_user_id  = d.echoed_user_id
    AND e.id > d.id;

-- 4) Enforce presence of the source Persona now that legacy rows are resolved.
ALTER TABLE public.echoes
  ALTER COLUMN echoer_author_id SET NOT NULL;

-- 5) Replace account-level uniqueness with Persona-to-Persona uniqueness so two
--    Personas owned by the same account can independently Echo the same target.
ALTER TABLE public.echoes
  DROP CONSTRAINT IF EXISTS echoes_unique;
ALTER TABLE public.echoes
  ADD CONSTRAINT echoes_persona_unique UNIQUE (echoer_author_id, echoed_user_id);

-- 6) Replace the old account-level self-check with a Persona-level self-check.
--    A Persona may never Echo itself (enforced server-side regardless of the UI).
ALTER TABLE public.echoes
  DROP CONSTRAINT IF EXISTS echoes_no_self;
ALTER TABLE public.echoes
  ADD CONSTRAINT echoes_no_self_persona CHECK (echoer_author_id <> echoed_user_id);

-- 7) Indexes for outgoing (echoer_author_id), incoming (echoed_user_id), and
--    newest-first pagination (created_at). echoed_user_id index already exists.
CREATE INDEX IF NOT EXISTS echoes_echoer_author_id_idx ON public.echoes (echoer_author_id);
CREATE INDEX IF NOT EXISTS echoes_echoed_user_id_idx ON public.echoes (echoed_user_id);
CREATE INDEX IF NOT EXISTS echoes_incoming_idx ON public.echoes (echoed_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS echoes_outgoing_idx ON public.echoes (echoer_author_id, created_at DESC);

COMMIT;

-- 8) Force PostgREST (Supabase REST layer used by the Worker) to reload its schema
--    cache so `echoer_author_id` is recognized immediately. Without this the Worker
--    can keep returning "Could not find the 'echoer_author_id' column ... in the
--    schema cache" until the cache refreshes on its own.
NOTIFY pgrst, 'reload schema';

-- Report: number of legacy rows that could not be attributed to a source Persona.
-- Run AFTER the migration; expected 0 on reruns (rows were discarded in step 2).
-- SELECT COUNT(*) AS remaining_unattributed FROM public.echoes WHERE echoer_author_id IS NULL;
