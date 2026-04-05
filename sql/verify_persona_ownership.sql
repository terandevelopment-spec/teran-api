-- RPC function: verify that a device_id owns a persona_author_id
-- Used by POST /api/posts/:id/like for single-round-trip ownership verification.
-- Joins account_devices → account_personas through shared account_id.

CREATE OR REPLACE FUNCTION verify_persona_ownership(
  p_device_id text,
  p_persona_author_id text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM account_devices ad
    JOIN account_personas ap
      ON ad.account_id = ap.account_id
    WHERE ad.device_id = p_device_id
      AND ap.persona_author_id = p_persona_author_id
  );
$$;
