/**
 * profile-rooms.spec.ts
 *
 * Backend tests for the single "default Profile Room" feature (Phase 1).
 *
 * The default is a public-profile PRESENTATION preference stored on the
 * profile_linked_rooms relation via the `is_default` boolean. These tests prove:
 *   - Existing/new links report is_default: false (never auto-defaulted).
 *   - PATCH sets exactly one default per owner and clears any previous one.
 *   - Cross-owner and invalid link IDs are rejected.
 *   - Unlinking (DELETE) naturally removes the default — no stale reference.
 *   - Zero defaults is a valid state.
 *   - A concurrent set-default conflict (DB 23505) is surfaced and never leaves
 *     two defaults.
 *   - The endpoints never touch membership / roles / invites.
 *
 * Supabase is mocked via vi.mock so no production database is touched.
 * KV uses the real in-memory miniflare implementation from the
 * @cloudflare/vitest-pool-workers harness.
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';
import { env as _env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index';
import type { Env } from '../src/index';

const env = _env as unknown as Env;

// ── Hoisted mock state ──────────────────────────────────────────────────
const mockState = vi.hoisted(() => {
  let _id = 1000;
  const db = new Map<string, any[]>();
  const fromCounts: Record<string, number> = {};
  return {
    db,
    fromCounts,
    // When set, the next UPDATE into the named table fails with `error`.
    // If onlyWhenSettingDefault is true, only an update whose payload sets
    // is_default === true fails (targets the "set" step, not the "clear" step).
    failNextUpdate: null as null | { table: string; error: any; onlyWhenSettingDefault?: boolean },
    inc: () => ++_id,
    reset() {
      db.clear();
      _id = 1000;
      for (const k of Object.keys(fromCounts)) delete fromCounts[k];
      this.failNextUpdate = null;
    },
    setRows(table: string, rows: any[]) { db.set(table, [...rows]); },
    getRows(table: string): any[] { return db.get(table) ?? []; },
    countFrom(table: string): number { return fromCounts[table] ?? 0; },
  };
});

// ── Supabase mock ───────────────────────────────────────────────────────
vi.mock('@supabase/supabase-js', () => {
  type St = {
    table: string;
    eqs: [string, any][];
    neqs: [string, any][];
    inFilter: [string, any[]] | null;
    op?: string;
    opData?: any;
  };

  const now = () => new Date().toISOString();

  const chain = (st: St): any => {
    const match = (r: any) =>
      st.eqs.every(([k, v]) => r[k] === v) &&
      st.neqs.every(([k, v]) => r[k] !== v) &&
      (st.inFilter ? st.inFilter[1].includes(r[st.inFilter[0]]) : true);

    const execAndReturn = (): { data: any; error: any } => {
      const { table, op, opData } = st;
      if (op === 'insert' || op === 'upsert') {
        const row = Array.isArray(opData) ? opData[0] : opData;
        const inserted = { id: `gen-${mockState.inc()}`, created_at: now(), ...row };
        mockState.db.set(table, [...mockState.getRows(table), inserted]);
        return { data: inserted, error: null };
      }
      if (op === 'update') {
        if (
          mockState.failNextUpdate &&
          mockState.failNextUpdate.table === table &&
          (mockState.failNextUpdate.onlyWhenSettingDefault ? opData?.is_default === true : true)
        ) {
          const error = mockState.failNextUpdate.error;
          mockState.failNextUpdate = null;
          return { data: null, error };
        }
        const updated = mockState.getRows(table).map(r =>
          match(r) ? { ...r, ...opData } : r
        );
        mockState.db.set(table, updated);
        return { data: null, error: null };
      }
      if (op === 'delete') {
        mockState.db.set(table, mockState.getRows(table).filter(r => !match(r)));
        return { data: null, error: null };
      }
      return { data: mockState.getRows(table).filter(match), error: null };
    };

    const self: any = {
      select: () => chain(st),
      eq:     (c: string, v: any)   => chain({ ...st, eqs: [...st.eqs, [c, v]] }),
      neq:    (c: string, v: any)   => chain({ ...st, neqs: [...st.neqs, [c, v]] }),
      in:     (c: string, v: any[]) => chain({ ...st, inFilter: [c, v] }),
      is:     () => chain(st),
      not:    () => chain(st),
      limit:  () => chain(st),
      order:  () => chain(st),

      insert: (data: any) => chain({ ...st, op: 'insert', opData: data }),
      update: (data: any) => chain({ ...st, op: 'update', opData: data }),
      delete: ()          => chain({ ...st, op: 'delete' }),
      upsert: (data: any) => chain({ ...st, op: 'upsert', opData: data }),

      maybeSingle: () => {
        if (st.op === 'insert' || st.op === 'upsert') {
          return Promise.resolve(execAndReturn());
        }
        const row = mockState.getRows(st.table).find(match) ?? null;
        return Promise.resolve({ data: row, error: null });
      },
      single: () => {
        if (st.op === 'insert' || st.op === 'upsert') {
          return Promise.resolve(execAndReturn());
        }
        const row = mockState.getRows(st.table).find(match) ?? null;
        return Promise.resolve({ data: row, error: row ? null : { message: 'Row not found' } });
      },
    };

    self.then = (resolve: (v: any) => any, reject?: (e: any) => any) =>
      Promise.resolve(execAndReturn()).then(resolve, reject);

    return self;
  };

  return {
    createClient: () => ({
      from: (t: string) => {
        mockState.fromCounts[t] = (mockState.fromCounts[t] ?? 0) + 1;
        return chain({ table: t, eqs: [], neqs: [], inFilter: null });
      },
      rpc: (_fn: string, _params?: any) => Promise.resolve({ data: [], error: null }),
    }),
  };
});

// ── JWT helper ──────────────────────────────────────────────────────────
function b64urlEncode(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlEncodeStr(s: string): string {
  return b64urlEncode(new TextEncoder().encode(s).buffer as ArrayBuffer);
}
async function makeToken(userId: string): Promise<string> {
  const secret = env.JWT_SECRET;
  const header  = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 };
  const h = b64urlEncodeStr(JSON.stringify(header));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const msg = `${h}.${p}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return `${msg}.${b64urlEncode(sig)}`;
}

// ── Request helper ──────────────────────────────────────────────────────
async function req(
  method: string,
  path: string,
  body?: unknown,
  userId?: string,
): Promise<{ status: number; body: any }> {
  const token = userId ? await makeToken(userId) : null;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const init: RequestInit = {
    method,
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  const request = new Request(`https://worker.test${path}`, init);
  const ctx = createExecutionContext();
  const response = await worker.fetch(request as any, env, ctx);
  await waitOnExecutionContext(ctx);
  const text = await response.text();
  let json: any;
  try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  return { status: response.status, body: json };
}

// ── Common test data ────────────────────────────────────────────────────
const OWNER_DEVICE    = 'owner-device';
const OUTSIDER_DEVICE = 'outsider-device';
const OWNER_ACCT      = 'acct-owner';
const OUTSIDER_ACCT   = 'acct-outsider';
const OWNER_AUTHOR    = 'owner-author';
const OUTSIDER_AUTHOR = 'outsider-author';

const TGT  = 'tgt-room';
const TGT2 = 'tgt-room-2';

const LINK1 = 'link-1';
const LINK2 = 'link-2';

const priv = (id: string) => ({
  id, visibility: 'private_invite_only', owner_id: OWNER_DEVICE,
  name: `Room ${id}`, room_key: `key-${id}`, emoji: '🔒',
  icon_key: null, icon_thumb_key: null, description: null,
  room_type: null, thread_card_style: null, catalog_columns: null, catalog_title_enabled: null,
});

const link = (id: string, target: string, position: number, is_default = false, owner = OWNER_AUTHOR) => ({
  id, owner_user_id: owner, target_room_id: target, position,
  created_at: `2026-01-0${position + 1}T00:00:00Z`, is_default,
});

beforeEach(() => {
  mockState.reset();
});

// Seed identity + two linked rooms for the owner, no default set.
function seedOwnerWithTwoLinks() {
  mockState.setRows('rooms', [priv(TGT), priv(TGT2)]);
  mockState.setRows('account_devices', [
    { device_id: OWNER_DEVICE, account_id: OWNER_ACCT },
    { device_id: OUTSIDER_DEVICE, account_id: OUTSIDER_ACCT },
  ]);
  mockState.setRows('account_personas', [
    { account_id: OWNER_ACCT, persona_author_id: OWNER_AUTHOR, created_at: '2026-01-01T00:00:00Z' },
    { account_id: OUTSIDER_ACCT, persona_author_id: OUTSIDER_AUTHOR, created_at: '2026-01-01T00:00:00Z' },
  ]);
  mockState.setRows('user_profiles', [{ user_id: OWNER_AUTHOR }, { user_id: OUTSIDER_AUTHOR }]);
  mockState.setRows('profile_linked_rooms', [
    link(LINK1, TGT, 0, false),
    link(LINK2, TGT2, 1, false),
  ]);
  mockState.setRows('room_members', []);
  mockState.setRows('room_invites', []);
}

function defaultsFor(owner = OWNER_AUTHOR): any[] {
  return mockState.getRows('profile_linked_rooms').filter(r => r.owner_user_id === owner && r.is_default === true);
}

// ═══════════════════════════════════════════════════════════════════════
// GET /api/profile-rooms — is_default in response
// ═══════════════════════════════════════════════════════════════════════
describe('GET /api/profile-rooms — is_default field', () => {
  it('returns is_default:false for existing links with no default', async () => {
    seedOwnerWithTwoLinks();
    const { status, body } = await req('GET', `/api/profile-rooms?user_id=${OWNER_AUTHOR}`);
    expect(status).toBe(200);
    expect(body.rooms.map((r: any) => r.target_room_id)).toEqual([TGT, TGT2]);
    expect(body.rooms.every((r: any) => r.is_default === false)).toBe(true);
    // Existing shape preserved.
    expect(body.rooms[0]).toHaveProperty('link_id');
    expect(body.rooms[0]).toHaveProperty('position');
    expect(body.rooms[0].room.id).toBe(TGT);
  });

  it('reflects a set default as is_default:true for exactly one link', async () => {
    seedOwnerWithTwoLinks();
    mockState.setRows('profile_linked_rooms', [
      link(LINK1, TGT, 0, true),
      link(LINK2, TGT2, 1, false),
    ]);
    const { body } = await req('GET', `/api/profile-rooms?user_id=${OWNER_AUTHOR}`);
    const defaults = body.rooms.filter((r: any) => r.is_default === true);
    expect(defaults).toHaveLength(1);
    expect(defaults[0].target_room_id).toBe(TGT);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PATCH /api/profile-rooms/:linkId — set / clear default
// ═══════════════════════════════════════════════════════════════════════
describe('PATCH /api/profile-rooms/:linkId — set default', () => {
  it('sets one link as default', async () => {
    seedOwnerWithTwoLinks();
    const { status, body } = await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OWNER_DEVICE);
    expect(status).toBe(200);
    expect(body.room.link_id).toBe(LINK1);
    expect(body.room.is_default).toBe(true);
    expect(defaultsFor()).toHaveLength(1);
    expect(defaultsFor()[0].id).toBe(LINK1);
  });

  it('setting a second link as default clears the first (at most one default)', async () => {
    seedOwnerWithTwoLinks();
    await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OWNER_DEVICE);
    await req('PATCH', `/api/profile-rooms/${LINK2}`, { is_default: true }, OWNER_DEVICE);
    const defaults = defaultsFor();
    expect(defaults).toHaveLength(1);
    expect(defaults[0].id).toBe(LINK2);
  });

  it('clearing the default (is_default:false) leaves zero defaults', async () => {
    seedOwnerWithTwoLinks();
    await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OWNER_DEVICE);
    const { status, body } = await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: false }, OWNER_DEVICE);
    expect(status).toBe(200);
    expect(body.room.is_default).toBe(false);
    expect(defaultsFor()).toHaveLength(0);
    // Clearing never auto-selects another Room.
    expect(mockState.getRows('profile_linked_rooms').filter(r => r.is_default === true)).toHaveLength(0);
  });

  it('rejects unauthenticated requests with 401', async () => {
    seedOwnerWithTwoLinks();
    const { status } = await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true });
    expect(status).toBe(401);
  });

  it("cannot set another owner's link as default (404, no mutation)", async () => {
    seedOwnerWithTwoLinks();
    const { status } = await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OUTSIDER_DEVICE);
    expect(status).toBe(404);
    expect(defaultsFor()).toHaveLength(0);
  });

  it('rejects an unknown link ID with 404', async () => {
    seedOwnerWithTwoLinks();
    const { status } = await req('PATCH', `/api/profile-rooms/does-not-exist`, { is_default: true }, OWNER_DEVICE);
    expect(status).toBe(404);
  });

  it('rejects an invalid body (missing/non-boolean is_default) with 400', async () => {
    seedOwnerWithTwoLinks();
    const a = await req('PATCH', `/api/profile-rooms/${LINK1}`, {}, OWNER_DEVICE);
    expect(a.status).toBe(400);
    const b = await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: 'yes' }, OWNER_DEVICE);
    expect(b.status).toBe(400);
  });

  it('surfaces a concurrent set-default conflict (23505) as 409 without leaving two defaults', async () => {
    seedOwnerWithTwoLinks();
    // Pre-existing default on LINK1 to simulate a racing writer.
    mockState.setRows('profile_linked_rooms', [
      link(LINK1, TGT, 0, true),
      link(LINK2, TGT2, 1, false),
    ]);
    // The "set" update (is_default:true) fails with a unique-violation.
    mockState.failNextUpdate = {
      table: 'profile_linked_rooms',
      onlyWhenSettingDefault: true,
      error: { code: '23505', message: 'duplicate key value violates unique constraint' },
    };

    const { status, body } = await req('PATCH', `/api/profile-rooms/${LINK2}`, { is_default: true }, OWNER_DEVICE);
    expect(status).toBe(409);
    expect(body?.error?.code).toBe('DEFAULT_ROOM_CONFLICT');
    // The clear ran first, so at most one default remains — never two.
    expect(defaultsFor().length).toBeLessThanOrEqual(1);
  });

  it('does not touch room_members or room_invites', async () => {
    seedOwnerWithTwoLinks();
    mockState.setRows('room_members', [{ room_id: TGT, user_id: OWNER_DEVICE, role: 'member' }]);
    mockState.setRows('room_invites', [{ id: 'inv-1', room_id: TGT, token: 't', revoked: false }]);
    const membersBefore = JSON.stringify(mockState.getRows('room_members'));
    const invitesBefore = JSON.stringify(mockState.getRows('room_invites'));

    await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OWNER_DEVICE);

    expect(JSON.stringify(mockState.getRows('room_members'))).toBe(membersBefore);
    expect(JSON.stringify(mockState.getRows('room_invites'))).toBe(invitesBefore);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// DELETE /api/profile-rooms/:linkId — unlink clears the default naturally
// ═══════════════════════════════════════════════════════════════════════
describe('DELETE /api/profile-rooms/:linkId — default cleanup', () => {
  it('removing the default link removes the default automatically (no stale reference)', async () => {
    seedOwnerWithTwoLinks();
    await req('PATCH', `/api/profile-rooms/${LINK1}`, { is_default: true }, OWNER_DEVICE);
    expect(defaultsFor()).toHaveLength(1);

    const { status } = await req('DELETE', `/api/profile-rooms/${LINK1}`, undefined, OWNER_DEVICE);
    expect(status).toBe(200);

    // The row (and thus its is_default marker) is gone; zero defaults remain.
    expect(mockState.getRows('profile_linked_rooms').some(r => r.id === LINK1)).toBe(false);
    expect(defaultsFor()).toHaveLength(0);

    const { body } = await req('GET', `/api/profile-rooms?user_id=${OWNER_AUTHOR}`);
    expect(body.rooms.every((r: any) => r.is_default === false)).toBe(true);
  });
});
