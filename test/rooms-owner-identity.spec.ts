/**
 * rooms-owner-identity.spec.ts
 *
 * Wire Room Discovery — Phase 1 (backend/API only).
 *
 * Verifies that GET /api/rooms enriches every returned Room with the owner's
 * public identity (owner_display_name + owner_avatar) sourced from
 * `user_profiles` (keyed by user_id), while preserving all existing listing
 * behavior: public + private discovery, catalog/DM exclusion, ordering,
 * member_count, the { rooms } envelope, and owner_id=me scoping.
 *
 * Supabase is mocked via vi.mock so no production database is touched. This
 * spec uses a self-contained mock that supports the PostgREST `.or()` filter
 * (used by the rooms listing for catalog/DM exclusion), `.order()`, `.limit()`,
 * and per-table call counting (to prove the owner lookup is a single batched
 * query with no N+1).
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
    // When set, the next select from the named table fails with `error`.
    failNextSelect: null as null | { table: string; error: any },
    inc: () => ++_id,
    reset() {
      db.clear();
      _id = 1000;
      for (const k of Object.keys(fromCounts)) delete fromCounts[k];
      this.failNextSelect = null;
    },
    setRows(table: string, rows: any[]) { db.set(table, [...rows]); },
    getRows(table: string): any[] { return db.get(table) ?? []; },
    countFrom(table: string): number { return fromCounts[table] ?? 0; },
  };
});

// ── Supabase mock (supports .or / .order / .limit) ──────────────────────
vi.mock('@supabase/supabase-js', () => {
  type OrGroup = Array<{ col: string; op: string; val: string }>;
  type St = {
    table: string;
    eqs: [string, any][];
    neqs: [string, any][];
    inFilter: [string, any[]] | null;
    orGroups: OrGroup[];
    orderBy: { col: string; ascending: boolean } | null;
    limitN: number | null;
    op?: string;
    opData?: any;
  };

  const now = () => new Date().toISOString();

  // Parse a PostgREST `.or()` string like "room_type.is.null,room_type.neq.catalog"
  const parseOr = (expr: string): OrGroup =>
    expr.split(',').map((clause) => {
      const parts = clause.split('.');
      const col = parts[0];
      const op = parts[1];
      const val = parts.slice(2).join('.');
      return { col, op, val };
    });

  const orGroupMatches = (group: OrGroup, r: any): boolean =>
    group.some(({ col, op, val }) => {
      const cell = r[col];
      if (op === 'is') return val === 'null' ? cell == null : cell === val;
      if (op === 'neq') return String(cell) !== val;
      if (op === 'eq') return String(cell) === val;
      return false;
    });

  const chain = (st: St): any => {
    const match = (r: any) =>
      st.eqs.every(([k, v]) => r[k] === v) &&
      st.neqs.every(([k, v]) => r[k] !== v) &&
      (st.inFilter ? st.inFilter[1].includes(r[st.inFilter[0]]) : true) &&
      st.orGroups.every((g) => orGroupMatches(g, r));

    const execAndReturn = (): { data: any; error: any } => {
      const { table, op, opData } = st;
      if (op === 'insert' || op === 'upsert') {
        const row = Array.isArray(opData) ? opData[0] : opData;
        const inserted = { id: mockState.inc(), created_at: now(), ...row };
        mockState.db.set(table, [...mockState.getRows(table), inserted]);
        return { data: inserted, error: null };
      }
      if (op === 'update') {
        const updated = mockState.getRows(table).map((r) => (match(r) ? { ...r, ...opData } : r));
        mockState.db.set(table, updated);
        return { data: null, error: null };
      }
      if (op === 'delete') {
        mockState.db.set(table, mockState.getRows(table).filter((r) => !match(r)));
        return { data: null, error: null };
      }
      // Multi-row select
      if (mockState.failNextSelect && mockState.failNextSelect.table === table) {
        const error = mockState.failNextSelect.error;
        mockState.failNextSelect = null;
        return { data: null, error };
      }
      let rows = mockState.getRows(table).filter(match);
      if (st.orderBy) {
        const { col, ascending } = st.orderBy;
        rows = [...rows].sort((a, b) => {
          const av = a[col];
          const bv = b[col];
          if (av === bv) return 0;
          const cmp = av > bv ? 1 : -1;
          return ascending ? cmp : -cmp;
        });
      }
      if (st.limitN != null) rows = rows.slice(0, st.limitN);
      return { data: rows, error: null };
    };

    const self: any = {
      select: () => chain(st),
      eq: (c: string, v: any) => chain({ ...st, eqs: [...st.eqs, [c, v]] }),
      neq: (c: string, v: any) => chain({ ...st, neqs: [...st.neqs, [c, v]] }),
      in: (c: string, v: any[]) => chain({ ...st, inFilter: [c, v] }),
      or: (expr: string) => chain({ ...st, orGroups: [...st.orGroups, parseOr(expr)] }),
      is: () => chain(st),
      not: () => chain(st),
      limit: (n: number) => chain({ ...st, limitN: n }),
      order: (col: string, opts?: { ascending?: boolean }) =>
        chain({ ...st, orderBy: { col, ascending: opts?.ascending !== false } }),

      insert: (data: any) => chain({ ...st, op: 'insert', opData: data }),
      update: (data: any) => chain({ ...st, op: 'update', opData: data }),
      delete: () => chain({ ...st, op: 'delete' }),
      upsert: (data: any) => chain({ ...st, op: 'upsert', opData: data }),

      maybeSingle: () => {
        if (st.op === 'insert' || st.op === 'upsert') return Promise.resolve(execAndReturn());
        const row = mockState.getRows(st.table).find(match) ?? null;
        return Promise.resolve({ data: row, error: null });
      },
      single: () => {
        if (st.op === 'insert' || st.op === 'upsert') return Promise.resolve(execAndReturn());
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
        return chain({ table: t, eqs: [], neqs: [], inFilter: null, orGroups: [], orderBy: null, limitN: null });
      },
      rpc: (_fn: string, _params?: any) => Promise.resolve({ data: [], error: null }),
    }),
  };
});

// ── JWT helper (for owner_id=me) ────────────────────────────────────────
function b64urlEncode(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlEncodeStr(s: string): string {
  return b64urlEncode(new TextEncoder().encode(s).buffer as ArrayBuffer);
}
async function makeToken(userId: string): Promise<string> {
  const secret = env.JWT_SECRET;
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 };
  const h = b64urlEncodeStr(JSON.stringify(header));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const msg = `${h}.${p}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return `${msg}.${b64urlEncode(sig)}`;
}

// ── Request helper ──────────────────────────────────────────────────────
async function listRooms(query = '', userId?: string): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (userId) headers['Authorization'] = `Bearer ${await makeToken(userId)}`;
  const request = new Request(`https://worker.test/api/rooms${query}`, { method: 'GET', headers });
  const ctx = createExecutionContext();
  const response = await worker.fetch(request as any, env, ctx);
  await waitOnExecutionContext(ctx);
  const text = await response.text();
  let json: any;
  try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  return { status: response.status, body: json };
}

// ── Fixtures ────────────────────────────────────────────────────────────
const basePublic = (over: Record<string, any>) => ({
  visibility: 'public',
  room_type: 'post',
  is_published: true,
  ...over,
});

beforeEach(() => {
  mockState.reset();
  mockState.setRows('room_members', []);
  mockState.setRows('account_devices', []);
  mockState.setRows('room_links', []);
});

describe('GET /api/rooms — owner identity enrichment (Phase 1)', () => {
  it('1. attaches owner display name + avatar for a room with a valid owner', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'Room 1', owner_id: 'owner-a', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'r2-key-a' }]);

    const { status, body } = await listRooms();
    expect(status).toBe(200);
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.owner_display_name).toBe('Alice');
    expect(room.owner_avatar).toBe('r2-key-a');
  });

  it('2. multiple rooms owned by the same user resolve via a single batched user_profiles query (no N+1)', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-02' }),
      basePublic({ id: 'r2', name: 'B', owner_id: 'owner-a', created_at: '2024-01-01' }),
    ]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'r2-key-a' }]);

    const { status, body } = await listRooms();
    expect(status).toBe(200);
    for (const id of ['r1', 'r2']) {
      const room = body.rooms.find((r: any) => r.id === id);
      expect(room.owner_display_name).toBe('Alice');
      expect(room.owner_avatar).toBe('r2-key-a');
    }
    // Exactly one query to user_profiles for the whole listing.
    expect(mockState.countFrom('user_profiles')).toBe(1);
  });

  it('3. rooms owned by different users receive the correct corresponding owner data', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-02' }),
      basePublic({ id: 'r2', name: 'B', owner_id: 'owner-b', created_at: '2024-01-01' }),
    ]);
    mockState.setRows('user_profiles', [
      { user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' },
      { user_id: 'owner-b', display_name: 'Bob', avatar: 'key-b' },
    ]);

    const { body } = await listRooms();
    expect(body.rooms.find((r: any) => r.id === 'r1').owner_display_name).toBe('Alice');
    expect(body.rooms.find((r: any) => r.id === 'r1').owner_avatar).toBe('key-a');
    expect(body.rooms.find((r: any) => r.id === 'r2').owner_display_name).toBe('Bob');
    expect(body.rooms.find((r: any) => r.id === 'r2').owner_avatar).toBe('key-b');
    expect(mockState.countFrom('user_profiles')).toBe(1);
  });

  it('4. a missing owner profile returns the room with null owner fields (does not fail)', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'A', owner_id: 'ghost', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', []); // no matching profile

    const { status, body } = await listRooms();
    expect(status).toBe(200);
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.owner_display_name).toBeNull();
    expect(room.owner_avatar).toBeNull();
  });

  it('5. a missing avatar does not remove the owner display name', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: null }]);

    const { body } = await listRooms();
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.owner_display_name).toBe('Alice');
    expect(room.owner_avatar).toBeNull();
  });

  it('6. a missing (or placeholder) display name does not remove the avatar', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-02' }),
      basePublic({ id: 'r2', name: 'B', owner_id: 'owner-b', created_at: '2024-01-01' }),
    ]);
    mockState.setRows('user_profiles', [
      { user_id: 'owner-a', display_name: '', avatar: 'key-a' },
      { user_id: 'owner-b', display_name: 'Anonymous', avatar: 'key-b' },
    ]);

    const { body } = await listRooms();
    const r1 = body.rooms.find((r: any) => r.id === 'r1');
    const r2 = body.rooms.find((r: any) => r.id === 'r2');
    expect(r1.owner_display_name).toBeNull();
    expect(r1.owner_avatar).toBe('key-a');
    expect(r2.owner_display_name).toBeNull(); // 'Anonymous' placeholder → null
    expect(r2.owner_avatar).toBe('key-b');
  });

  it('7 & 8. public AND private rooms are both returned (with owner identity)', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'pub', name: 'Public', owner_id: 'owner-a', created_at: '2024-01-02' }),
      { id: 'priv', name: 'Private', visibility: 'private_invite_only', room_type: 'post', is_published: true, owner_id: 'owner-b', created_at: '2024-01-01' },
    ]);
    mockState.setRows('user_profiles', [
      { user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' },
      { user_id: 'owner-b', display_name: 'Bob', avatar: 'key-b' },
    ]);

    const { body } = await listRooms();
    const ids = body.rooms.map((r: any) => r.id);
    expect(ids).toContain('pub');
    expect(ids).toContain('priv');
    expect(body.rooms.find((r: any) => r.id === 'priv').owner_display_name).toBe('Bob');
  });

  it('9. catalog and DM rooms remain excluded from the public listing', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'pub', name: 'Public', owner_id: 'owner-a', created_at: '2024-01-03' }),
      { id: 'cat', name: 'Catalog', visibility: 'public', room_type: 'catalog', is_published: true, owner_id: 'owner-a', created_at: '2024-01-02' },
      { id: 'dm', name: 'DM', visibility: 'public', room_type: 'dm', is_published: true, owner_id: 'owner-a', created_at: '2024-01-01' },
    ]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' }]);

    const { body } = await listRooms();
    const ids = body.rooms.map((r: any) => r.id);
    expect(ids).toContain('pub');
    expect(ids).not.toContain('cat');
    expect(ids).not.toContain('dm');
  });

  it('10. Portal compatibility: default listing still returns the { rooms } envelope with member_count', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' }]);
    mockState.setRows('room_members', [
      { room_id: 'r1', user_id: 'm1' },
      { room_id: 'r1', user_id: 'm2' },
    ]);

    const { body } = await listRooms();
    expect(Array.isArray(body.rooms)).toBe(true);
    expect(body).not.toHaveProperty('catalog_relations'); // non-me envelope unchanged
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.member_count).toBe(2);
    expect(room.owner_display_name).toBe('Alice');
  });

  it('11. owner_id=me still scopes to the caller and adds owner identity fields', async () => {
    mockState.setRows('rooms', [
      { id: 'mine', name: 'Mine', visibility: 'private_invite_only', room_type: 'post', is_published: false, owner_id: 'me-device', created_at: '2024-01-02' },
      basePublic({ id: 'other', name: 'Other', owner_id: 'someone-else', created_at: '2024-01-01' }),
    ]);
    mockState.setRows('user_profiles', [{ user_id: 'me-device', display_name: 'Me', avatar: 'my-key' }]);

    const { status, body } = await listRooms('?owner_id=me', 'me-device');
    expect(status).toBe(200);
    const ids = body.rooms.map((r: any) => r.id);
    expect(ids).toContain('mine'); // owner sees own unpublished/private room
    expect(ids).not.toContain('other'); // scoping unchanged
    const mine = body.rooms.find((r: any) => r.id === 'mine');
    expect(mine.owner_display_name).toBe('Me');
    expect(mine.owner_avatar).toBe('my-key');
  });

  it('12. response order and member_count are unchanged by enrichment', async () => {
    mockState.setRows('rooms', [
      basePublic({ id: 'older', name: 'Older', owner_id: 'owner-a', created_at: '2024-01-01' }),
      basePublic({ id: 'newer', name: 'Newer', owner_id: 'owner-b', created_at: '2024-06-01' }),
    ]);
    mockState.setRows('user_profiles', [
      { user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' },
      { user_id: 'owner-b', display_name: 'Bob', avatar: 'key-b' },
    ]);
    mockState.setRows('room_members', [{ room_id: 'newer', user_id: 'm1' }]);

    const { body } = await listRooms();
    // created_at desc → newer first
    expect(body.rooms.map((r: any) => r.id)).toEqual(['newer', 'older']);
    expect(body.rooms.find((r: any) => r.id === 'newer').member_count).toBe(1);
    expect(body.rooms.find((r: any) => r.id === 'older').member_count).toBe(0);
  });

  it('13. a data: URI avatar is stripped to null (privacy/consistency with feed)', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'data:image/png;base64,AAAA' }]);

    const { body } = await listRooms();
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.owner_display_name).toBe('Alice');
    expect(room.owner_avatar).toBeNull();
  });

  it('14. a failing owner-profile query leaves null owner fields and still returns 200', async () => {
    mockState.setRows('rooms', [basePublic({ id: 'r1', name: 'A', owner_id: 'owner-a', created_at: '2024-01-01' })]);
    mockState.setRows('user_profiles', [{ user_id: 'owner-a', display_name: 'Alice', avatar: 'key-a' }]);
    mockState.failNextSelect = { table: 'user_profiles', error: { message: 'boom' } };

    const { status, body } = await listRooms();
    expect(status).toBe(200);
    const room = body.rooms.find((r: any) => r.id === 'r1');
    expect(room.owner_display_name).toBeNull();
    expect(room.owner_avatar).toBeNull();
  });
});
