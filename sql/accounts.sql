-- Account foundation tables for future claim/login flow.
-- Step 1: schema only. No data migration, no JWT changes, no existing table modifications.

-- 1) Core account table
-- Internal account_id is the immutable primary key.
-- teran_handle is the user-facing login/display ID (optional, claimed later).
-- password_hash is set during claim (optional until then).
CREATE TABLE IF NOT EXISTS accounts (
  id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  teran_handle  TEXT UNIQUE,
  password_hash TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for handle lookup during login
CREATE INDEX IF NOT EXISTS idx_accounts_handle ON accounts(teran_handle)
  WHERE teran_handle IS NOT NULL;

-- 2) Device-to-account binding
-- One account can have multiple devices (cross-device restore).
-- Each device_id maps to at most one account.
CREATE TABLE IF NOT EXISTS account_devices (
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  device_id   TEXT NOT NULL UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (account_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_account_devices_device ON account_devices(device_id);

-- 3) Persona-to-account binding
-- Links persona author_ids to an account for cross-device persona restore.
-- persona_name and persona_avatar are snapshots for server-side restore.
CREATE TABLE IF NOT EXISTS account_personas (
  account_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  persona_author_id TEXT NOT NULL,
  persona_name      TEXT,
  persona_avatar    TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (account_id, persona_author_id)
);

CREATE INDEX IF NOT EXISTS idx_account_personas_account ON account_personas(account_id);
