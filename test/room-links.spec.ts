/**
 * room-links.spec.ts
 *
 * Private Room → Private Room linking (navigation-only) backend tests.
 *
 * These tests prove the feature is permission-neutral:
 *   - No link route ever writes room_members.
 *   - No link route grants any role / Post / Join permission.
 *   - No link route calls join or join_by_invite.
 *   - The invite token is used once as proof and is NEVER stored.
 *   - Deleting a link never revokes the target invite.
 *
 * They also include a small regression around the extracted read-only
 * invite validator, confirming join_by_invite still behaves identically.
 * (Fuller join_by_invite coverage lives in room-roles.spec.ts.)
 *
 * Supabase is mocked via vi.mock so no production database is touched.
 * KV uses the real in-memory miniflare implementation provided by the
 * @cloudflare/vitest-pool-workers test harness.
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
    // When set, the next insert into the named table fails with `error`.
    failNextInsert: null as null | { table: string; error: any },
    inc: () => ++_id,
    reset() {
      db.clear();
      _id = 1000;
      for (const k of Object.keys(fromCounts)) delete fromCounts[k];
      this.failNextInsert = null;
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
        if (mockState.failNextInsert && mockState.failNextInsert.table === table) {
          const error = mockState.failNextInsert.error;
          mockState.failNextInsert = null;
          return { data: null, error };
        }
        const row = Array.isArray(opData) ? opData[0] : opData;
        const inserted = { id: mockState.inc(), created_at: now(), ...row };
        mockState.db.set(table, [...mockState.getRows(table), inserted]);
        return { data: inserted, error: null };
      }
      if (op === 'update') {
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
      eq:     (c: string, v: any)    => chain({ ...st, eqs: [...st.eqs, [c, v]] }),
      neq:    (c: string, v: any)    => chain({ ...st, neqs: [...st.neqs, [c, v]] }),
      in:     (c: string, v: any[])  => chain({ ...st, inFilter: [c, v] }),
      is:     () => chain(st),
      not:    () => chain(st),
      limit:  () => chain(st),
      order:  () => chain(st),

      insert: (data: any) => chain({ ...st, op: 'insert',  opData: data }),
      update: (data: any) => chain({ ...st, op: 'update',  opData: data }),
      delete: ()          => chain({ ...st, op: 'delete' }),
      upsert: (data: any) => chain({ ...st, op: 'upsert',  opData: data }),

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
const SRC     = 'src-room';
const TGT      = 'tgt-room';
const TGT2     = 'tgt-room-2';
const OWNER    = 'owner-device';
const OUTSIDER = 'outsider-device';
const TOKEN    = 'target-invite-token';
const TOKEN2   = 'target-invite-token-2';

const priv = (id: string) => ({ id, visibility: 'private_invite_only', owner_id: OWNER, name: `Room ${id}`, room_key: `key-${id}`, emoji: '🔒', icon_key: null, icon_thumb_key: null, description: null });
const pub  = (id: string) => ({ id, visibility: 'public', owner_id: OWNER, name: `Room ${id}`, room_key: `key-${id}`, emoji: '🌐' });

const ownerOf = (roomId: string, userId = OWNER) => ({ room_id: roomId, user_id: userId, role: 'owner' });
const activeInviteFor = (roomId: string, token: string) => ({ id: mockStateInviteId(), room_id: roomId, token, revoked: false });

let _inviteId = 1;
function mockStateInviteId() { return _inviteId++; }

// ── beforeEach ──────────────────────────────────────────────────────────
beforeEach(() => {
  mockState.reset();
  _inviteId = 1;
});

// Seed a valid "source owner links a private target with a valid invite" world.
function seedHappyPath() {
  mockState.setRows('rooms', [priv(SRC), priv(TGT), priv(TGT2)]);
  mockState.setRows('room_members', [ownerOf(SRC)]);
  mockState.setRows('account_devices', []);
  mockState.setRows('room_invites', [
    activeInviteFor(TGT, TOKEN),
    activeInviteFor(TGT2, TOKEN2),
  ]);
  mockState.setRows('room_links', []);
}

// ═══════════════════════════════════════════════════════════════════════
// Invite validator regression (via join_by_invite)
// Fuller coverage in room-roles.spec.ts — these confirm the extraction of
// validateRoomInvite did not change behavior.
// ═══════════════════════════════════════════════════════════════════════
describe('join_by_invite — invite validator regression', () => {
  const ROOM = 'jbi-room';
  const USER = 'jbi-user';
  const T = 'jbi-token';

  it('valid invite still joins as member', async () => {
    mockState.setRows('room_invites', [{ id: 1, room_id: ROOM, token: T, revoked: false }]);
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    const { status, body } = await req('POST', `/api/rooms/${ROOM}/join_by_invite`, { token: T }, USER);

    expect(status).toBe(200);
    expect(body?.joined).toBe(true);
    const row = mockState.getRows('room_members').find(r => r.room_id === ROOM && r.user_id === USER);
    expect(row?.role).toBe('member');
  });

  it('invalid invite still rejected with 403', async () => {
    mockState.setRows('room_invites', []);
    const { status } = await req('POST', `/api/rooms/${ROOM}/join_by_invite`, { token: 'wrong' }, USER);
    expect(status).toBe(403);
  });

  it('revoked invite still rejected with 403', async () => {
    mockState.setRows('room_invites', [{ id: 2, room_id: ROOM, token: T, revoked: true }]);
    const { status } = await req('POST', `/api/rooms/${ROOM}/join_by_invite`, { token: T }, USER);
    expect(status).toBe(403);
  });

  it('missing token still rejected with 422', async () => {
    mockState.setRows('room_invites', []);
    const { status } = await req('POST', `/api/rooms/${ROOM}/join_by_invite`, {}, USER);
    expect(status).toBe(422);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/rooms/:sourceRoomId/links
// ═══════════════════════════════════════════════════════════════════════
describe('POST /api/rooms/:sourceRoomId/links', () => {
  it('creates a link (private source + private target + owner + valid invite)', async () => {
    seedHappyPath();

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);

    expect(status).toBe(201);
    expect(body?.link?.source_room_id).toBe(SRC);
    expect(body?.link?.target_room_id).toBe(TGT);
    expect(body?.link?.position).toBe(0);
    expect(body?.link?.room?.id).toBe(TGT);
    expect(body?.link?.room?.visibility).toBe('private_invite_only');
  });

  it('stores the target UUID but NEVER the invite token', async () => {
    seedHappyPath();
    await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);

    const rows = mockState.getRows('room_links');
    expect(rows.length).toBe(1);
    const row = rows[0];
    expect(row.target_room_id).toBe(TGT);
    expect('token' in row).toBe(false);
    expect('invite_token' in row).toBe(false);
    // No invite token value should appear anywhere in the stored row.
    expect(JSON.stringify(row).includes(TOKEN)).toBe(false);
  });

  it('does NOT insert or update room_members and does NOT invalidate membership KV', async () => {
    seedHappyPath();
    const before = JSON.stringify(mockState.getRows('room_members'));
    const kvKey = `room_member:${SRC}:${OWNER}`;
    await env.PROFILE_KV.put(kvKey, 'owner', { expirationTtl: 300 });

    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);

    expect(status).toBe(201);
    expect(JSON.stringify(mockState.getRows('room_members'))).toBe(before);
    // Membership cache untouched by linking.
    expect(await env.PROFILE_KV.get(kvKey)).toBe('owner');
  });

  it('rejects a PUBLIC source with 422 SOURCE_ROOM_NOT_PRIVATE', async () => {
    mockState.setRows('rooms', [pub(SRC), priv(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [activeInviteFor(TGT, TOKEN)]);

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(422);
    expect(body?.error?.code).toBe('SOURCE_ROOM_NOT_PRIVATE');
  });

  it('rejects a PUBLIC target with 422 TARGET_ROOM_NOT_PRIVATE', async () => {
    mockState.setRows('rooms', [priv(SRC), pub(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [activeInviteFor(TGT, TOKEN)]);

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(422);
    expect(body?.error?.code).toBe('TARGET_ROOM_NOT_PRIVATE');
  });

  it('rejects a non-owner source actor with 403', async () => {
    seedHappyPath();
    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OUTSIDER);
    expect(status).toBe(403);
  });

  it('rejects unauthenticated request with 401', async () => {
    seedHappyPath();
    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN });
    expect(status).toBe(401);
  });

  it('rejects a missing source room with 404', async () => {
    mockState.setRows('rooms', [priv(TGT)]);
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [activeInviteFor(TGT, TOKEN)]);

    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(404);
  });

  it('rejects a missing target room with 404', async () => {
    mockState.setRows('rooms', [priv(SRC)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', []);

    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(404);
  });

  it('rejects a missing target_room_id with 422', async () => {
    seedHappyPath();
    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { invite_token: TOKEN }, OWNER);
    expect(status).toBe(422);
  });

  it('rejects a missing invite_token with 422', async () => {
    seedHappyPath();
    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT }, OWNER);
    expect(status).toBe(422);
  });

  it('rejects an invalid invite token with 403', async () => {
    seedHappyPath();
    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: 'nope' }, OWNER);
    expect(status).toBe(403);
  });

  it('rejects a revoked invite token with 403', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [{ id: 9, room_id: TGT, token: TOKEN, revoked: true }]);

    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(403);
  });

  it('rejects an invite token that belongs to a DIFFERENT room with 403', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    // Token is valid, but for some other room — must not authorize linking TGT.
    mockState.setRows('room_invites', [{ id: 10, room_id: 'some-other-room', token: TOKEN, revoked: false }]);

    const { status } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(403);
  });

  it('rejects a self-link with 422 SELF_LINK_NOT_ALLOWED', async () => {
    mockState.setRows('rooms', [priv(SRC)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [activeInviteFor(SRC, TOKEN)]);

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: SRC, invite_token: TOKEN }, OWNER);
    expect(status).toBe(422);
    expect(body?.error?.code).toBe('SELF_LINK_NOT_ALLOWED');
  });

  it('returns 409 ROOM_ALREADY_LINKED for a duplicate pair (application pre-check)', async () => {
    seedHappyPath();
    mockState.setRows('room_links', [
      { id: 700, source_room_id: SRC, target_room_id: TGT, position: 0, created_by: OWNER, created_at: new Date().toISOString() },
    ]);

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(409);
    expect(body?.error?.code).toBe('ROOM_ALREADY_LINKED');
  });

  it('normalizes a database 23505 unique violation to the same 409', async () => {
    seedHappyPath();
    // Pre-check finds nothing (no existing rows), but the INSERT races and fails.
    mockState.failNextInsert = { table: 'room_links', error: { code: '23505', message: 'duplicate key value' } };

    const { status, body } = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(status).toBe(409);
    expect(body?.error?.code).toBe('ROOM_ALREADY_LINKED');
  });

  it('first link gets position 0, next link gets the next position', async () => {
    seedHappyPath();

    const first = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT, invite_token: TOKEN }, OWNER);
    expect(first.status).toBe(201);
    expect(first.body?.link?.position).toBe(0);

    const second = await req('POST', `/api/rooms/${SRC}/links`, { target_room_id: TGT2, invite_token: TOKEN2 }, OWNER);
    expect(second.status).toBe(201);
    expect(second.body?.link?.position).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// GET /api/rooms/:sourceRoomId/links
// ═══════════════════════════════════════════════════════════════════════
describe('GET /api/rooms/:sourceRoomId/links', () => {
  it('returns links in stable position/created order with minimal target summaries', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT), priv(TGT2)]);
    mockState.setRows('room_links', [
      { id: 1, source_room_id: SRC, target_room_id: TGT,  position: 0, created_at: '2026-01-01T00:00:00Z' },
      { id: 2, source_room_id: SRC, target_room_id: TGT2, position: 1, created_at: '2026-01-02T00:00:00Z' },
    ]);

    const { status, body } = await req('GET', `/api/rooms/${SRC}/links`);

    expect(status).toBe(200);
    expect(body?.links?.map((l: any) => l.target_room_id)).toEqual([TGT, TGT2]);
    const room = body.links[0].room;
    // Minimal navigation summary — no permission/identity fields.
    expect(room.id).toBe(TGT);
    expect('token' in room).toBe(false);
    expect('role' in room).toBe(false);
    expect('post_policy' in room).toBe(false);
  });

  it('loads target rooms via ONE batched query (no N+1)', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT), priv(TGT2), priv('tgt-3')]);
    mockState.setRows('room_links', [
      { id: 1, source_room_id: SRC, target_room_id: TGT,     position: 0, created_at: '2026-01-01T00:00:00Z' },
      { id: 2, source_room_id: SRC, target_room_id: TGT2,    position: 1, created_at: '2026-01-02T00:00:00Z' },
      { id: 3, source_room_id: SRC, target_room_id: 'tgt-3', position: 2, created_at: '2026-01-03T00:00:00Z' },
    ]);

    const { status } = await req('GET', `/api/rooms/${SRC}/links`);
    expect(status).toBe(200);
    // 1 query for the source room + 1 batched query for all targets = 2 total,
    // regardless of the number of links (N+1 would be 4 here).
    expect(mockState.countFrom('rooms')).toBe(2);
  });

  it('omits links whose target room no longer exists', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_links', [
      { id: 1, source_room_id: SRC, target_room_id: TGT,       position: 0, created_at: '2026-01-01T00:00:00Z' },
      { id: 2, source_room_id: SRC, target_room_id: 'deleted', position: 1, created_at: '2026-01-02T00:00:00Z' },
    ]);

    const { status, body } = await req('GET', `/api/rooms/${SRC}/links`);
    expect(status).toBe(200);
    expect(body.links.map((l: any) => l.target_room_id)).toEqual([TGT]);
  });

  it('omits links whose target room is no longer Private', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT), pub(TGT2)]);
    mockState.setRows('room_links', [
      { id: 1, source_room_id: SRC, target_room_id: TGT,  position: 0, created_at: '2026-01-01T00:00:00Z' },
      { id: 2, source_room_id: SRC, target_room_id: TGT2, position: 1, created_at: '2026-01-02T00:00:00Z' },
    ]);

    const { status, body } = await req('GET', `/api/rooms/${SRC}/links`);
    expect(status).toBe(200);
    expect(body.links.map((l: any) => l.target_room_id)).toEqual([TGT]);
  });

  it('returns 404 for a missing source room', async () => {
    mockState.setRows('rooms', []);
    const { status } = await req('GET', `/api/rooms/${SRC}/links`);
    expect(status).toBe(404);
  });

  it('returns 422 when the source room is not Private', async () => {
    mockState.setRows('rooms', [pub(SRC)]);
    const { status, body } = await req('GET', `/api/rooms/${SRC}/links`);
    expect(status).toBe(422);
    expect(body?.error?.code).toBe('SOURCE_ROOM_NOT_PRIVATE');
  });

  it('does not mutate any table', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_links', [
      { id: 1, source_room_id: SRC, target_room_id: TGT, position: 0, created_at: '2026-01-01T00:00:00Z' },
    ]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    const linksBefore = JSON.stringify(mockState.getRows('room_links'));
    const membersBefore = JSON.stringify(mockState.getRows('room_members'));

    await req('GET', `/api/rooms/${SRC}/links`);

    expect(JSON.stringify(mockState.getRows('room_links'))).toBe(linksBefore);
    expect(JSON.stringify(mockState.getRows('room_members'))).toBe(membersBefore);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// DELETE /api/rooms/:sourceRoomId/links/:linkId
// ═══════════════════════════════════════════════════════════════════════
describe('DELETE /api/rooms/:sourceRoomId/links/:linkId', () => {
  const LINK_ID = 501;

  function seedDeleteWorld() {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_invites', [{ id: 1, room_id: TGT, token: TOKEN, revoked: false }]);
    mockState.setRows('room_links', [
      { id: LINK_ID, source_room_id: SRC, target_room_id: TGT, position: 0, created_by: OWNER, created_at: '2026-01-01T00:00:00Z' },
    ]);
  }

  it('source owner can remove a link', async () => {
    seedDeleteWorld();
    const { status, body } = await req('DELETE', `/api/rooms/${SRC}/links/${LINK_ID}`, undefined, OWNER);
    expect(status).toBe(200);
    expect(body?.deleted).toBe(true);
    expect(body?.link_id).toBe(LINK_ID);
    expect(mockState.getRows('room_links').length).toBe(0);
  });

  it('non-owner cannot remove a link (403)', async () => {
    seedDeleteWorld();
    const { status } = await req('DELETE', `/api/rooms/${SRC}/links/${LINK_ID}`, undefined, OUTSIDER);
    expect(status).toBe(403);
    expect(mockState.getRows('room_links').length).toBe(1);
  });

  it('cannot delete a link belonging to a different source room (404)', async () => {
    mockState.setRows('rooms', [priv(SRC), priv(TGT)]);
    mockState.setRows('room_members', [ownerOf(SRC)]);
    mockState.setRows('account_devices', []);
    mockState.setRows('room_links', [
      { id: 777, source_room_id: 'other-source', target_room_id: TGT, position: 0, created_by: OWNER, created_at: '2026-01-01T00:00:00Z' },
    ]);

    const { status } = await req('DELETE', `/api/rooms/${SRC}/links/777`, undefined, OWNER);
    expect(status).toBe(404);
    expect(mockState.getRows('room_links').length).toBe(1);
  });

  it('missing link returns 404', async () => {
    seedDeleteWorld();
    const { status } = await req('DELETE', `/api/rooms/${SRC}/links/999999`, undefined, OWNER);
    expect(status).toBe(404);
  });

  it('deletion does not touch room_members', async () => {
    seedDeleteWorld();
    const before = JSON.stringify(mockState.getRows('room_members'));
    await req('DELETE', `/api/rooms/${SRC}/links/${LINK_ID}`, undefined, OWNER);
    expect(JSON.stringify(mockState.getRows('room_members'))).toBe(before);
  });

  it('deletion does not revoke the target invite', async () => {
    seedDeleteWorld();
    const before = JSON.stringify(mockState.getRows('room_invites'));
    await req('DELETE', `/api/rooms/${SRC}/links/${LINK_ID}`, undefined, OWNER);
    expect(JSON.stringify(mockState.getRows('room_invites'))).toBe(before);
  });
});
