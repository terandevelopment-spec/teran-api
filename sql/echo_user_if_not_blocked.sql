-- Supabase SQL Migration: Atomic Echo with Block Check
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor)

-- Drop if exists (for idempotent re-runs)
DROP FUNCTION IF EXISTS echo_user_if_not_blocked(uuid, uuid);

-- Create the RPC function
CREATE OR REPLACE FUNCTION echo_user_if_not_blocked(
  p_user_id uuid,
  p_echoed_user_id uuid
)
RETURNS TABLE(status text, was_inserted boolean)
LANGUAGE plpgsql
SECURITY DEFINER  -- Bypasses RLS for internal checks
SET search_path = public
AS $$
DECLARE
  v_blocked boolean;
  v_inserted boolean := false;
BEGIN
  -- Step 1: Check for mutual block (either direction)
  SELECT EXISTS (
    SELECT 1 FROM blocks
    WHERE (blocker_user_id = p_user_id AND blocked_user_id = p_echoed_user_id)
       OR (blocker_user_id = p_echoed_user_id AND blocked_user_id = p_user_id)
  ) INTO v_blocked;

  IF v_blocked THEN
    -- Blocked: return immediately without inserting
    RETURN QUERY SELECT 'BLOCKED'::text, false;
    RETURN;
  END IF;

  -- Step 2: Not blocked - attempt upsert
  INSERT INTO echoes (user_id, echoed_user_id)
  VALUES (p_user_id, p_echoed_user_id)
  ON CONFLICT (user_id, echoed_user_id) DO NOTHING;

  -- Check if row was actually inserted (vs already existed)
  GET DIAGNOSTICS v_inserted = ROW_COUNT;

  RETURN QUERY SELECT 'OK'::text, (v_inserted > 0);
END;
$$;

-- Grant execute permission to authenticated users (Supabase auth)
GRANT EXECUTE ON FUNCTION echo_user_if_not_blocked(uuid, uuid) TO authenticated;

-- Revoke from anon to prevent unauthenticated calls
REVOKE EXECUTE ON FUNCTION echo_user_if_not_blocked(uuid, uuid) FROM anon;

-- Test the function (optional - run manually):
-- SELECT * FROM echo_user_if_not_blocked('user-uuid-here', 'target-uuid-here');
