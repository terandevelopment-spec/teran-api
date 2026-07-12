/**
 * room-roles.spec.ts
 *
 * Phase 2 tests: normal join → registered, invite join → member,
 * registered cannot post, all roles can comment, kick + invite-upgrade
 * invalidate the membership KV cache.
 *
 * Supabase is mocked via vi.mock so no production database is touched.
 * KV uses the real in-memory miniflare implementation provided by the
 * @cloudflare/vitest-pool-workers test harness.
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';
import { env as _env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index';
import type { Env } from '../src/index';

// Cast the test-harness env to the Worker's full Env type.
// ProvidedEnv only contains bindings declared in worker-configuration.d.ts;
// plain-text vars (JWT_SECRET, etc.) and KV namespaces not generated there
// are defined in the Worker's Env interface in src/index.ts.
const env = _env as unknown as Env;

// ── Hoisted mock state ──────────────────────────────────────────────────
// vi.hoisted runs before vi.mock factories, making the state reachable
// inside the factory closure without triggering the "can't reference
// outer-scope variable from hoist" lint error.
const mockState = vi.hoisted(() => {
  let _id = 1000;
  const db = new Map<string, any[]>();
  return {
    db,
    inc: () => ++_id,
    reset() { db.clear(); _id = 1000; },
    setRows(table: string, rows: any[]) { db.set(table, [...rows]); },
    getRows(table: string): any[] { return db.get(table) ?? []; },
  };
});

// ── Supabase mock ───────────────────────────────────────────────────────
// Provides a chainable query-builder that mirrors the Supabase JS v2 API.
// The chain is also thenable so `await chain` resolves for update/delete.
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
      // Multi-row select
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

    // Thenable: resolves when the chain is awaited directly.
    self.then = (resolve: (v: any) => any, reject?: (e: any) => any) =>
      Promise.resolve(execAndReturn()).then(resolve, reject);

    return self;
  };

  return {
    createClient: () => ({
      from: (t: string) => chain({ table: t, eqs: [], neqs: [], inFilter: null }),
    }),
  };
});

// ── JWT helper ──────────────────────────────────────────────────────────
// Replicates the Worker's HS256 signing logic so tests can create tokens
// that pass requireAuth without calling any external service.
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

// ── Convenience error code checker ─────────────────────────────────────
const isMembershipError = (b: any) =>
  b?.error?.code === 'ROOM_MEMBERSHIP_REQUIRED' || b?.code === 'ROOM_MEMBERSHIP_REQUIRED';

// ── Common test data ────────────────────────────────────────────────────
const ROOM_ID  = 'test-room-1';
const USER_ID  = 'device-user-1';
const TOKEN    = 'valid-invite-token';

const publicRoom   = { id: ROOM_ID, visibility: 'public', read_policy: 'public', post_policy: 'members_only' };
const privateRoom  = { id: ROOM_ID, visibility: 'private_invite_only' };
const activeInvite = { id: 1, room_id: ROOM_ID, token: TOKEN, revoked: false };
const revokedInvite = { id: 2, room_id: ROOM_ID, token: TOKEN, revoked: true };

const memberRow    = { room_id: ROOM_ID, user_id: USER_ID, role: 'member' };
const registeredRow = { room_id: ROOM_ID, user_id: USER_ID, role: 'registered' };
const ownerRow     = { room_id: ROOM_ID, user_id: USER_ID, role: 'owner' };

// ── beforeEach: reset mock DB + clear KV ───────────────────────────────
beforeEach(async () => {
  mockState.reset();
  // Clear the KV namespace between tests (best-effort)
  const kvKey = `room_member:${ROOM_ID}:${USER_ID}`;
  await env.PROFILE_KV.delete(kvKey).catch(() => {});
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/rooms/:id/join — normal public registration
// ═══════════════════════════════════════════════════════════════════════
describe('POST /api/rooms/:id/join — normal registration', () => {
  it('new user gets registered (not member)', async () => {
    mockState.setRows('rooms', [publicRoom]);
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    const { status, body } = await req('POST', `/api/rooms/${ROOM_ID}/join`, {}, USER_ID);

    expect(status).toBe(200);
    expect(body?.joined).toBe(true);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('registered');
  });

  it('existing registered stays registered (not upgraded)', async () => {
    mockState.setRows('rooms', [publicRoom]);
    mockState.setRows('room_members', [registeredRow]);
    mockState.setRows('account_devices', []);

    const { status } = await req('POST', `/api/rooms/${ROOM_ID}/join`, {}, USER_ID);

    expect(status).toBe(200);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('registered');
  });

  it('existing member is NOT downgraded to registered', async () => {
    mockState.setRows('rooms', [publicRoom]);
    mockState.setRows('room_members', [memberRow]);
    mockState.setRows('account_devices', []);

    const { status } = await req('POST', `/api/rooms/${ROOM_ID}/join`, {}, USER_ID);

    expect(status).toBe(200);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('member');
  });

  it('existing owner is NOT downgraded to registered', async () => {
    mockState.setRows('rooms', [publicRoom]);
    mockState.setRows('room_members', [ownerRow]);
    mockState.setRows('account_devices', []);

    const { status } = await req('POST', `/api/rooms/${ROOM_ID}/join`, {}, USER_ID);

    expect(status).toBe(200);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('owner');
  });

  it('private_invite_only room is rejected', async () => {
    mockState.setRows('rooms', [privateRoom]);

    const { status } = await req('POST', `/api/rooms/${ROOM_ID}/join`, {}, USER_ID);

    expect(status).toBe(403);
  });

  it('unauthenticated request is rejected with 401', async () => {
    mockState.setRows('rooms', [publicRoom]);

    const { status } = await req('POST', `/api/rooms/${ROOM_ID}/join`);

    expect(status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/rooms/:id/join_by_invite — QR / invite join
// ═══════════════════════════════════════════════════════════════════════
describe('POST /api/rooms/:id/join_by_invite — invite join', () => {
  it('new user gets member role', async () => {
    mockState.setRows('room_invites', [activeInvite]);
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    const { status, body } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID
    );

    expect(status).toBe(200);
    expect(body?.joined).toBe(true);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('member');
  });

  it('registered user is upgraded to member', async () => {
    mockState.setRows('room_invites', [activeInvite]);
    mockState.setRows('room_members', [registeredRow]);
    mockState.setRows('account_devices', []);
    // Pre-seed the KV cache with the stale registered value
    await env.PROFILE_KV.put(`room_member:${ROOM_ID}:${USER_ID}`, 'registered', { expirationTtl: 300 });

    const { status } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID
    );

    expect(status).toBe(200);
    // DB row should be updated to member
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('member');
    // KV cache should be deleted so the new role is fetched fresh
    const cached = await env.PROFILE_KV.get(`room_member:${ROOM_ID}:${USER_ID}`);
    expect(cached).toBeNull();
  });

  it('existing member stays member (not re-inserted)', async () => {
    mockState.setRows('room_invites', [activeInvite]);
    mockState.setRows('room_members', [memberRow]);
    mockState.setRows('account_devices', []);

    const { status } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID
    );

    expect(status).toBe(200);
    // Still exactly one row with member role
    const rows = mockState.getRows('room_members')
      .filter(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(rows.length).toBe(1);
    expect(rows[0].role).toBe('member');
  });

  it('existing owner is unchanged', async () => {
    mockState.setRows('room_invites', [activeInvite]);
    mockState.setRows('room_members', [ownerRow]);
    mockState.setRows('account_devices', []);

    const { status } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID
    );

    expect(status).toBe(200);
    const row = mockState.getRows('room_members')
      .find(r => r.room_id === ROOM_ID && r.user_id === USER_ID);
    expect(row?.role).toBe('owner');
  });

  it('invalid token is rejected with 403', async () => {
    mockState.setRows('room_invites', []);  // no matching token

    const { status } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: 'wrong' }, USER_ID
    );

    expect(status).toBe(403);
  });

  it('revoked token is rejected with 403', async () => {
    mockState.setRows('room_invites', [revokedInvite]);

    const { status } = await req(
      'POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID
    );

    expect(status).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/posts — Room post creation role enforcement
// ═══════════════════════════════════════════════════════════════════════
describe('POST /api/posts — Room publishing role enforcement', () => {
  const postBody = { room_id: ROOM_ID, content: 'hello room' };

  it('no role → 403 ROOM_MEMBERSHIP_REQUIRED', async () => {
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    const { status, body } = await req('POST', '/api/posts', postBody, USER_ID);

    expect(status).toBe(403);
    expect(isMembershipError(body)).toBe(true);
  });

  it('registered role → 403 ROOM_MEMBERSHIP_REQUIRED', async () => {
    mockState.setRows('room_members', [registeredRow]);
    mockState.setRows('account_devices', []);

    const { status, body } = await req('POST', '/api/posts', postBody, USER_ID);

    expect(status).toBe(403);
    expect(isMembershipError(body)).toBe(true);
  });

  it('member role → not a membership error', async () => {
    mockState.setRows('room_members', [memberRow]);
    mockState.setRows('account_devices', []);
    mockState.setRows('rooms', [publicRoom]);

    const { body } = await req('POST', '/api/posts', postBody, USER_ID);

    // The request passes the membership gate (may fail later for other reasons
    // such as validation, but must NOT fail with ROOM_MEMBERSHIP_REQUIRED).
    expect(isMembershipError(body)).toBe(false);
  });

  it('owner role → not a membership error', async () => {
    mockState.setRows('room_members', [ownerRow]);
    mockState.setRows('account_devices', []);
    mockState.setRows('rooms', [publicRoom]);

    const { body } = await req('POST', '/api/posts', postBody, USER_ID);

    expect(isMembershipError(body)).toBe(false);
  });

  it('global post with no room role → passes the membership gate', async () => {
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    // No room_id → needsRoomCheck = false → no membership check
    const { body } = await req('POST', '/api/posts', { content: 'global post' }, USER_ID);

    expect(isMembershipError(body)).toBe(false);
  });

  it('sibling with registered role → 403 ROOM_MEMBERSHIP_REQUIRED', async () => {
    const siblingId = 'sibling-device';
    // Current device has no direct membership; sibling has registered
    mockState.setRows('room_members', [
      { room_id: ROOM_ID, user_id: siblingId, role: 'registered' },
    ]);
    mockState.setRows('account_devices', [
      { device_id: USER_ID,   account_id: 'acc1' },
      { device_id: siblingId, account_id: 'acc1' },
    ]);

    const { status, body } = await req('POST', '/api/posts', postBody, USER_ID);

    expect(status).toBe(403);
    expect(isMembershipError(body)).toBe(true);
  });

  it('sibling with member role → passes membership gate', async () => {
    const siblingId = 'sibling-device';
    mockState.setRows('room_members', [
      { room_id: ROOM_ID, user_id: siblingId, role: 'member' },
    ]);
    mockState.setRows('account_devices', [
      { device_id: USER_ID,   account_id: 'acc1' },
      { device_id: siblingId, account_id: 'acc1' },
    ]);
    mockState.setRows('rooms', [publicRoom]);

    const { body } = await req('POST', '/api/posts', postBody, USER_ID);

    expect(isMembershipError(body)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// POST /api/comments — comment auth (unchanged: any role passes)
// ═══════════════════════════════════════════════════════════════════════
describe('POST /api/comments — Room comment role enforcement', () => {
  const POST_ID = 42;

  it('registered role → not a membership error', async () => {
    mockState.setRows('posts', [{ id: POST_ID, room_id: ROOM_ID, user_id: 'author', deleted_at: null }]);
    mockState.setRows('room_members', [registeredRow]);
    mockState.setRows('account_devices', []);

    const { body } = await req(
      'POST', '/api/comments', { post_id: POST_ID, content: 'test comment' }, USER_ID
    );

    expect(isMembershipError(body)).toBe(false);
  });

  it('no role → 403 ROOM_MEMBERSHIP_REQUIRED', async () => {
    mockState.setRows('posts', [{ id: POST_ID, room_id: ROOM_ID, user_id: 'author', deleted_at: null }]);
    mockState.setRows('room_members', []);
    mockState.setRows('account_devices', []);

    const { status, body } = await req(
      'POST', '/api/comments', { post_id: POST_ID, content: 'test comment' }, USER_ID
    );

    expect(status).toBe(403);
    expect(isMembershipError(body)).toBe(true);
  });

  it('member role → not a membership error', async () => {
    mockState.setRows('posts', [{ id: POST_ID, room_id: ROOM_ID, user_id: 'author', deleted_at: null }]);
    mockState.setRows('room_members', [memberRow]);
    mockState.setRows('account_devices', []);

    const { body } = await req(
      'POST', '/api/comments', { post_id: POST_ID, content: 'test comment' }, USER_ID
    );

    expect(isMembershipError(body)).toBe(false);
  });

  it('owner role → not a membership error', async () => {
    mockState.setRows('posts', [{ id: POST_ID, room_id: ROOM_ID, user_id: 'author', deleted_at: null }]);
    mockState.setRows('room_members', [ownerRow]);
    mockState.setRows('account_devices', []);

    const { body } = await req(
      'POST', '/api/comments', { post_id: POST_ID, content: 'test comment' }, USER_ID
    );

    expect(isMembershipError(body)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// KV cache invalidation
// ═══════════════════════════════════════════════════════════════════════
describe('KV cache invalidation', () => {
  it('kick removes the kicked user KV entry', async () => {
    const ownerId = 'owner-device';
    const targetId = 'kicked-device';
    const kvKey = `room_member:${ROOM_ID}:${targetId}`;

    mockState.setRows('room_members', [
      { room_id: ROOM_ID, user_id: ownerId,  role: 'owner'  },
      { room_id: ROOM_ID, user_id: targetId, role: 'member' },
    ]);
    mockState.setRows('account_devices', []);

    // Pre-seed the kicked user's KV entry
    await env.PROFILE_KV.put(kvKey, 'member', { expirationTtl: 300 });
    expect(await env.PROFILE_KV.get(kvKey)).toBe('member');

    const { status, body } = await req(
      'POST', `/api/rooms/${ROOM_ID}/kick`, { user_id: targetId }, ownerId
    );

    expect(status).toBe(200);
    expect(body?.kicked).toBe(true);
    // KV entry must be gone
    expect(await env.PROFILE_KV.get(kvKey)).toBeNull();
  });

  it('invite upgrade clears the stale registered KV entry', async () => {
    const kvKey = `room_member:${ROOM_ID}:${USER_ID}`;

    mockState.setRows('room_invites', [activeInvite]);
    mockState.setRows('room_members', [registeredRow]);
    mockState.setRows('account_devices', []);

    await env.PROFILE_KV.put(kvKey, 'registered', { expirationTtl: 300 });
    expect(await env.PROFILE_KV.get(kvKey)).toBe('registered');

    await req('POST', `/api/rooms/${ROOM_ID}/join_by_invite`, { token: TOKEN }, USER_ID);

    expect(await env.PROFILE_KV.get(kvKey)).toBeNull();
  });
});
