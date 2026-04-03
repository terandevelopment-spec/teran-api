// ~/Desktop/teran-api/src/index.ts
import { createClient } from "@supabase/supabase-js";
import { AwsClient } from "aws4fetch";

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_SECRET: string;
  CORS_ORIGIN?: string; // optional: "http://localhost:5173" etc
  R2_MEDIA: R2Bucket;    // R2 bucket for media uploads
  UNREAD_KV: KVNamespace; // KV for unread_count cache
  PROFILE_KV: KVNamespace; // KV for profile cache
  R2_ACCESS_KEY_ID: string;      // R2 S3-compat API token
  R2_SECRET_ACCESS_KEY: string;
  R2_ACCOUNT_ID: string;         // CF account id
  DIAG_LOG?: string;             // "1" to enable sampled request-start logs
}

// --------- request_id + response helpers ----------
function getReqId(req?: Request): string {
  if (req) {
    const incoming = req.headers.get("x-request-id") || req.headers.get("x-req-id");
    if (incoming) return incoming;
  }
  return (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`).toString();
}

function corsHeaders(req: Request, env: Env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = env.CORS_ORIGIN || origin || "*";
  return {
    "Access-Control-Allow-Origin": allowed === "null" ? "*" : allowed,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-teran-caller",
    "Access-Control-Expose-Headers": "X-Cache, X-Cache-Key, X-Request-Id, Cache-Control",
    "Access-Control-Max-Age": "86400",
  };
}

// --------- Device ID cookie helpers ----------
function readDeviceIdFromCookie(req: Request): string | null {
  const cookie = req.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)teran_device_id=([a-f0-9-]{36})/);
  return m ? m[1] : null;
}

function setDeviceIdCookie(origin: string, deviceId: string): string {
  const isSecure = origin.startsWith("https");
  // Same-origin (prod via Pages proxy): SameSite=Lax + Secure
  // Same-origin / localhost (dev): SameSite=Lax, no Secure flag
  if (isSecure) {
    return `teran_device_id=${deviceId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000`;
  }
  return `teran_device_id=${deviceId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000`;
}

function ok(req: Request, env: Env, request_id: string, data: any, status = 200) {
  return new Response(JSON.stringify({ ...data, request_id }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": request_id,
      ...corsHeaders(req, env),
    },
  });
}

function fail(req: Request, env: Env, request_id: string, status: number, code: string, message: string, extra?: any) {
  return new Response(JSON.stringify({ error: { code, message, ...(extra ?? {}) }, request_id }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": request_id,
      ...corsHeaders(req, env),
    },
  });
}

class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// --------- base64url ----------
function b64urlEncode(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlEncodeStr(s: string): string {
  return b64urlEncode(new TextEncoder().encode(s).buffer);
}
function b64urlDecodeToBytes(s: string): Uint8Array {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// --------- JWT HS256 (no deps) ----------
async function hmacSha256(key: string, msg: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg));
  return b64urlEncode(sig);
}

async function jwtSign(env: Env, payload: Record<string, unknown>) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncodeStr(JSON.stringify(header));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const msg = `${h}.${p}`;
  const sig = await hmacSha256(env.JWT_SECRET, msg);
  return `${msg}.${sig}`;
}

async function jwtVerify(env: Env, token: string): Promise<Record<string, any> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  const msg = `${h}.${p}`;
  const expected = await hmacSha256(env.JWT_SECRET, msg);
  if (expected !== sig) return null;

  const payloadJson = new TextDecoder().decode(b64urlDecodeToBytes(p));
  const payload = JSON.parse(payloadJson);

  // exp check (seconds)
  if (payload?.exp && typeof payload.exp === "number") {
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) return null;
  }
  return payload;
}

// --------- Password hashing (PBKDF2-SHA256, Workers-native) ----------
const PBKDF2_ITERATIONS = 100_000;
const SALT_BYTES = 16;

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  const saltHex = [...salt].map(b => b.toString(16).padStart(2, "0")).join("");
  const hashHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, expectedHex] = stored.split(":");
  if (!saltHex || !expectedHex) return false;
  const salt = new Uint8Array((saltHex.match(/.{2}/g) || []).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  const actualHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
  return actualHex === expectedHex;
}

// --------- Teran handle validation ----------
const HANDLE_RE = /^[a-z0-9][a-z0-9._]{1,28}[a-z0-9]$/;
function isValidHandle(h: string): boolean {
  if (!h || h.length < 3 || h.length > 30) return false;
  if (!HANDLE_RE.test(h)) return false;
  if (h.includes("..") || h.includes("__") || h.includes("._") || h.includes("_.")) return false;
  return true;
}

async function requireAuth(req: Request, env: Env): Promise<string> {
  const auth = req.headers.get("Authorization") || "";
  if (!auth) {
    throw new HttpError(401, "AUTH_MISSING", "Missing Authorization header");
  }
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    throw new HttpError(401, "AUTH_INVALID", "Invalid Authorization header format");
  }
  const token = m[1];
  const payload = await jwtVerify(env, token);
  if (!payload) {
    throw new HttpError(401, "AUTH_INVALID", "Invalid or expired token");
  }
  const userId = payload?.sub;
  if (typeof userId !== "string") {
    throw new HttpError(401, "AUTH_INVALID", "Invalid token payload");
  }
  return userId;
}

// --------- Supabase client (singleton per isolate) ----------
let _sbClient: ReturnType<typeof createClient> | null = null;
let _sbUrl: string | null = null;

// ── In-memory stale cache for unread_count (per-isolate, survives across requests) ──
const MEM_CACHE_TTL_MS = 120_000; // 120s — serves stale value when KV times out
const _unreadMem = new Map<string, { count: number; ts: number }>();
function memGet(userId: string): number | null {
  const entry = _unreadMem.get(userId);
  if (!entry) return null;
  if (performance.now() - entry.ts > MEM_CACHE_TTL_MS) { _unreadMem.delete(userId); return null; }
  return entry.count;
}
function memSet(userId: string, count: number) {
  _unreadMem.set(userId, { count, ts: performance.now() });
}

// ── Diagnostic / perf log helpers (compact single-line JSON) ──
function logDiag(tag: string, obj: unknown) {
  console.log(`[diag] ${tag} ${JSON.stringify(obj)}`);
}
function logPerf(tag: string, obj: unknown) {
  console.log(`[perf] ${tag} ${JSON.stringify(obj)}`);
}
function logErr(tag: string, obj: unknown) {
  console.log(`[err] ${tag} ${JSON.stringify(obj)}`);
}


function sb(env: Env) {
  // Reuse client if URL hasn't changed (same isolate)
  if (_sbClient && _sbUrl === env.SUPABASE_URL) return _sbClient;
  _sbClient = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    global: { fetch },
  });
  _sbUrl = env.SUPABASE_URL;
  return _sbClient;
}

// --------- News URL helpers ----------
/**
 * Normalize a URL to a canonical form for consistent news_id generation.
 * - Only http/https allowed
 * - Strip hash fragment
 * - Remove trailing slash (except for root path)
 * Returns canonical URL string or null if invalid.
 */
function normalizeUrl(inputUrl: string): string | null {
  try {
    const url = new URL(inputUrl);
    // Only allow http/https
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    // Remove hash
    url.hash = "";
    // Build canonical form
    let canonical = url.toString();
    // Remove trailing slash except for root
    if (canonical.endsWith("/") && url.pathname !== "/") {
      canonical = canonical.slice(0, -1);
    }
    return canonical;
  } catch {
    return null;
  }
}

/**
 * Compute SHA-256 hash of a string and return as hex.
 */
async function sha256Hex(str: string): Promise<string> {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
// --------- Room metadata helper ----------
async function resolveRoomMeta(
  env: Env,
  room_id: string | null | undefined
): Promise<{ room_id: string | null; room_icon_key: string | null; room_emoji: string | null }> {
  if (!room_id) return { room_id: null, room_icon_key: null, room_emoji: null };
  try {
    const { data } = await sb(env)
      .from("rooms")
      .select("icon_key, emoji")
      .eq("id", room_id)
      .single();
    return {
      room_id,
      room_icon_key: (data as any)?.icon_key ?? null,
      room_emoji: (data as any)?.emoji ?? null,
    };
  } catch {
    return { room_id, room_icon_key: null, room_emoji: null };
  }
}

// --------- Notifications Helper ----------
async function createNotification(
  env: Env,
  payload: {
    recipient_user_id: string;
    actor_user_id: string;
    actor_name?: string | null;
    actor_avatar?: string | null;
    type: "comment_like" | "reply" | "post_comment" | "post_like" | "post_reply" | "news_comment_like" | "news_comment_reply";
    post_id?: number;
    root_post_id?: number;
    comment_id?: number;
    parent_comment_id?: number;
    news_id?: string;
    news_url?: string | null;
    news_image_url?: string | null;
    room_id?: string | null;
    room_icon_key?: string | null;
    room_emoji?: string | null;

    group_key: string;
    snippet?: string | null;
  },
  request_id?: string
) {

  // ── DIAGNOSTIC: entry ──
  console.log(`[news-notif:create][${request_id}] createNotification ENTERED`, {
    type: payload.type,
    recipientId: payload.recipient_user_id,
    actorId: payload.actor_user_id,
    commentId: payload.comment_id,
    parentCommentId: payload.parent_comment_id,
    postId: payload.post_id,
    newsId: payload.news_id,
    newsImageUrl: payload.news_image_url,
    groupKey: payload.group_key,
    recipientIdType: typeof payload.recipient_user_id,
    recipientIdLength: payload.recipient_user_id?.length,
    actorIdType: typeof payload.actor_user_id,
    actorIdLength: payload.actor_user_id?.length,
  });

  // Skip self-notification
  if (payload.recipient_user_id === payload.actor_user_id) {
    console.log(`[news-notif:create][${request_id}] SKIPPED self-notification`, {
      type: payload.type,
      actorId: payload.actor_user_id,
      recipientId: payload.recipient_user_id,
      exactMatch: payload.recipient_user_id === payload.actor_user_id,
    });
    return;
  }

  console.log(`[news-notif:create][${request_id}] passed self-check, building insert payload`, {
    recipientId: payload.recipient_user_id,
    actorId: payload.actor_user_id,
    areDifferent: payload.recipient_user_id !== payload.actor_user_id,
  });

  const insertPayload = {
    recipient_user_id: payload.recipient_user_id,
    actor_user_id: payload.actor_user_id,
    actor_name: payload.actor_name ?? null,
    actor_avatar: payload.actor_avatar ?? null,
    type: payload.type,
    post_id: payload.post_id ?? null,
    root_post_id: payload.root_post_id ?? null,
    comment_id: payload.comment_id ?? null,
    parent_comment_id: payload.parent_comment_id ?? null,
    group_key: payload.group_key,
    news_id: payload.news_id ?? null,
    news_url: payload.news_url ?? null,
    news_image_url: payload.news_image_url ?? null,
    room_id: payload.room_id ?? null,
    room_icon_key: payload.room_icon_key ?? null,
    room_emoji: payload.room_emoji ?? null,
  };

  console.log(`[news-notif:create][${request_id}] DB insert start — full payload:`, JSON.stringify(insertPayload));

  const { data, error } = await sb(env).from("notifications").insert(insertPayload).select("id, recipient_user_id, actor_user_id, type");

  if (error) {
    console.error(`[news-notif:create][${request_id}] DB insert FAILED`, {
      code: error.code,
      message: error.message,
      details: error.details,
      hint: error.hint,
      insertPayloadRecipient: insertPayload.recipient_user_id,
      insertPayloadType: insertPayload.type,
    });
  } else {
    console.log(`[news-notif:create][${request_id}] DB insert SUCCESS`, {
      insertedId: data?.[0]?.id,
      insertedRecipientId: (data?.[0] as any)?.recipient_user_id,
      insertedActorId: (data?.[0] as any)?.actor_user_id,
      insertedType: (data?.[0] as any)?.type,
    });
  }
}

// --------- room helpers ----------
async function optionalAuth(req: Request, env: Env): Promise<string | null> {
  const auth = req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const payload = await jwtVerify(env, m[1]);
  return typeof payload?.sub === "string" ? payload.sub : null;
}

async function checkRoomMembership(env: Env, roomId: string, userId: string): Promise<string | null> {
  // Direct check: membership under this device_id
  const { data } = await sb(env)
    .from("room_members")
    .select("role")
    .eq("room_id", roomId)
    .eq("user_id", userId)
    .maybeSingle();
  if (data?.role) return data.role;

  // Account-aware fallback: after teran ID login, the new device_id may not
  // have room_members rows. Check sibling device_ids on the same account.
  const { data: binding } = await sb(env)
    .from("account_devices")
    .select("account_id")
    .eq("device_id", userId)
    .maybeSingle();
  if (!binding?.account_id) return null;

  const { data: siblings } = await sb(env)
    .from("account_devices")
    .select("device_id")
    .eq("account_id", (binding as any).account_id)
    .neq("device_id", userId);

  if (!siblings || siblings.length === 0) return null;

  const siblingIds = siblings.map((s: any) => s.device_id).filter(Boolean);
  if (siblingIds.length === 0) return null;

  const { data: siblingMembership } = await sb(env)
    .from("room_members")
    .select("role")
    .eq("room_id", roomId)
    .in("user_id", siblingIds)
    .limit(1)
    .maybeSingle();

  return siblingMembership?.role ?? null;
}

function generateInviteToken(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

// --------- cursor pagination helpers ----------
function parseCursor(raw: string | null): { created_at: string; id: number } | null {
  if (!raw || typeof raw !== "string") return null;
  const idx = raw.lastIndexOf(":");
  if (idx <= 0) return null;
  const ts = raw.slice(0, idx);
  const idStr = raw.slice(idx + 1);
  const id = Number(idStr);
  // Validate: ts must look like an ISO date, id must be a positive integer
  if (!ts || isNaN(Date.parse(ts)) || !Number.isFinite(id) || id <= 0 || !Number.isInteger(id)) return null;
  return { created_at: ts, id };
}

function buildNextCursor(items: any[], limit: number): string | null {
  if (!items || items.length < limit) return null;
  const last = items[items.length - 1];
  if (!last?.created_at || !last?.id) return null;
  return `${last.created_at}:${last.id}`;
}

function clampPaginationLimit(raw: string | null, defaultVal = 20, max = 200): number {
  if (!raw) return defaultVal;
  const n = parseInt(raw, 10);
  if (isNaN(n) || n < 1) return defaultVal;
  return Math.min(n, max);
}

// --------- routes ----------
export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const request_id = getReqId(req);
    const t0 = Date.now();
    const cfRay = req.headers.get("cf-ray") || ((req as any).cf?.ray) || "";

    // Preflight (don't log timing for OPTIONS)
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { ...corsHeaders(req, env), "x-req-id": request_id },
      });
    }

    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;
    const colo = (req as any).cf?.colo || "";
    const q = url.searchParams.toString();
    const shortQ = q.length > 120 ? q.slice(0, 120) + "…" : q;
    const label = shortQ ? `${path}?${shortQ}` : path;

    // Shared context for perf breakdown (populated by route handlers)
    const reqCtx: Record<string, number | string> = {};
    let outcome: "ok" | "exception" | "canceled" = "ok";
    let errMsg = "";

    const handleRequest = async (): Promise<Response> => {
      try {
        // /api/identity (POST) -> { user_id, token }
        if (path === "/api/identity" && req.method === "POST") {
          // Stable device ID: prefer existing cookie, else generate new
          let device_id = readDeviceIdFromCookie(req);
          const had_cookie = !!device_id;
          if (!device_id) device_id = crypto.randomUUID();

          // Use device_id as user_id (stable identity across localStorage clears)
          const user_id = device_id;
          const now = Math.floor(Date.now() / 1000);
          const token = await jwtSign(env, {
            sub: user_id,
            iat: now,
            exp: now + 60 * 60 * 24 * 365, // 1 year
          });
          console.log(`[identity] rid=${request_id} had_cookie=${had_cookie} device_id=${device_id} origin=${req.headers.get("Origin")||"none"} ua=${(req.headers.get("user-agent")||"").slice(0,60)}`);

          const resp = ok(req, env, request_id, { user_id, token });
          // Always refresh the cookie Max-Age (rolling expiry)
          const origin = req.headers.get("Origin") || "";
          resp.headers.append("Set-Cookie", setDeviceIdCookie(origin, device_id));
          resp.headers.set("Cache-Control", "no-store");
          resp.headers.set("Pragma", "no-cache");
          return resp;
        }

        // /api/identity/reset (POST) -> { user_id, token }
        // Always generates a NEW device_id, ignores any existing cookie.
        // Used by SetupScreen "Get Started" to ensure a fresh identity context
        // so new accounts never inherit room memberships from a previous identity.
        if (path === "/api/identity/reset" && req.method === "POST") {
          const device_id = crypto.randomUUID();
          const user_id = device_id;
          const now = Math.floor(Date.now() / 1000);
          const token = await jwtSign(env, {
            sub: user_id,
            iat: now,
            exp: now + 60 * 60 * 24 * 365, // 1 year
          });
          console.log(`[identity/reset] rid=${request_id} new_device_id=${device_id}`);

          const resp = ok(req, env, request_id, { user_id, token });
          const origin = req.headers.get("Origin") || "";
          resp.headers.append("Set-Cookie", setDeviceIdCookie(origin, device_id));
          resp.headers.set("Cache-Control", "no-store");
          resp.headers.set("Pragma", "no-cache");
          return resp;
        }

        // /api/posts (GET) - filter by ?id=, ?user_id=, ?author_id=, ?room_id=, ?limit=, ?actor_id=
        if (path === "/api/posts" && req.method === "GET") {
          const FEED_CACHE_TTL = 8;
          const SLOW_MS = 1000;
          const VERY_SLOW_MS = 3000;
          const handlerStart = Date.now();
          const p0 = performance.now();
          let cacheLookupMs = 0;
          let cacheStatus = "BYPASS";

          // Parse all query params
          const id_param = url.searchParams.get("id");
          const user_id_param = url.searchParams.get("user_id");
          const author_id_param = url.searchParams.get("author_id");
          const room_id_param = url.searchParams.get("room_id");
          const limit_param = url.searchParams.get("limit");
          const actor_id_param = url.searchParams.get("actor_id")?.trim() || null;
          // ── NEW scope filters ──
          const post_type_param = url.searchParams.get("post_type");       // e.g. "status" or "status,thread"
          const root_only_param = url.searchParams.get("root_only");       // "1" or "true"
          const parent_post_id_param = url.searchParams.get("parent_post_id"); // integer
          const room_scope_param = url.searchParams.get("room_scope");     // "global"|"rooms"|"any"
          const cursor_param = url.searchParams.get("cursor");             // pagination cursor
          const diag_param = url.searchParams.get("diag");                 // suspect isolation: "posts_only" | "only_parallel:media" etc.
          const mode_param = url.searchParams.get("mode");                 // CSV: "Ask,Discuss"
          const mood_param = url.searchParams.get("mood");                 // CSV: "Happy,Curious"
          const q_param = url.searchParams.get("q");                       // keyword search
          const light = url.searchParams.get("light") === "1";              // lightweight mode: skip enrichment
          const room_category_param = url.searchParams.get("room_category"); // CSV: "games,music"
          const include_global_param = url.searchParams.get("include_global"); // "0" to exclude global threads
          const isReplyQuery = !!parent_post_id_param;
          const isScopedQuery = !!post_type_param || !!root_only_param || !!mode_param || !!mood_param || !!q_param;
          const cursor = (isReplyQuery || isScopedQuery) ? parseCursor(cursor_param) : null;
          const p1 = performance.now();

          // ── Edge cache: eligible for public, non-personalized feeds ──
          // Allow the standard scoped main feed (post_type=status, root_only, room_scope=global)
          // as well as the legacy unfiltered feed.
          const hasPersonalizedFilters = !!mode_param || !!mood_param || !!q_param || !!room_category_param || include_global_param === "0";
          const isStandardScopedFeed = (
            post_type_param === "status" &&
            (root_only_param === "1" || root_only_param === "true") &&
            room_scope_param === "global" &&
            !hasPersonalizedFilters
          );
          // Feed cache: non-reply, non-cursored, non-user-specific queries
          const isFeed = !id_param && !user_id_param && !author_id_param && !isReplyQuery && !cursor && !room_id_param && (!hasPersonalizedFilters) && (!parent_post_id_param) && (isStandardScopedFeed || (!post_type_param && !root_only_param && !room_scope_param));
          let feedCacheKey: Request | null = null;
          const cache = caches.default;

          if (isFeed) {
            const cacheUrl = new URL("https://cache.internal/posts/feed");
            cacheUrl.searchParams.set("limit", limit_param || "50");
            if (actor_id_param) cacheUrl.searchParams.set("actor", actor_id_param);
            // Include scope params in cache key so scoped vs unscoped don't collide
            if (post_type_param) cacheUrl.searchParams.set("pt", post_type_param);
            if (root_only_param) cacheUrl.searchParams.set("ro", root_only_param);
            if (room_scope_param) cacheUrl.searchParams.set("rs", room_scope_param);
            if (room_category_param) cacheUrl.searchParams.set("rc", room_category_param);
            if (include_global_param) cacheUrl.searchParams.set("ig", include_global_param);
            feedCacheKey = new Request(cacheUrl.toString(), { method: "GET" });

            const cacheT0 = performance.now();
            const cached = await cache.match(feedCacheKey);
            cacheLookupMs = +(performance.now() - cacheT0).toFixed(1);
            if (cached) {
              cacheStatus = "HIT";
              const hitBody = await cached.text();
              const pDone = performance.now();
              console.log(`[perf] /api/posts cache=HIT rid=${request_id} total=${(pDone - p0).toFixed(1)}ms cache_lookup_ms=${cacheLookupMs} limit=${limit_param || 50} actor=${actor_id_param || "none"} payloadBytes=${hitBody.length}`);
              return new Response(hitBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "HIT",
                  "Cache-Control": `public, max-age=0, s-maxage=${FEED_CACHE_TTL}, stale-while-revalidate=30`,
                  ...corsHeaders(req, env),
                },
              });
            }
            cacheStatus = "MISS";
            console.log(`[perf] /api/posts cache`, JSON.stringify({ rid: request_id, cache_key: feedCacheKey?.url || "none", ttl_s: FEED_CACHE_TTL, cache: "MISS", cache_lookup_ms: cacheLookupMs }));
          }

          // Build base query with conditional select:
          // - Feed lists: lightweight select (content included for card preview)
          // - Single post by id: include full data for PostDetail
          const feedSelectFields = "id,user_id,created_at,title,content,author_id,author_name,author_avatar,room_id,parent_post_id,post_type,shared_post_id,genre,mode,moods";
          const lightSelectFields = "id,created_at,title,content,author_id,author_name,author_avatar,mode,moods,room_id,parent_post_id,post_type,show_in_feed,room_category,media(type,key,thumb_key)";
          const selectFields = light ? lightSelectFields : feedSelectFields;

          // Step 1: log normalized filter + select cols
          const postsFilterShape = {
            post_type: post_type_param || "all",
            root_only: root_only_param || "false",
            room_scope: room_scope_param || "none",
            room_id: room_id_param || "none",
            user_id: user_id_param ? "set" : "none",
            author_id: author_id_param ? "set" : "none",
            id: id_param ? "set" : "none",
            limit: limit_param || "default",
            cursor: cursor ? "set" : "none",
          };
          logDiag("/api/posts query_shape", { rid: request_id, select_cols: selectFields, light, filter: postsFilterShape });

          let q = sb(env)
            .from("posts")
            .select(selectFields)
            .is("deleted_at", null)
            .order("created_at", { ascending: false });

          // Apply filters - priority: id > user_id > author_id > default
          let lim = 1; // will be set per branch below
          if (id_param) {
            // Single post by ID
            const parsedId = Number(id_param);
            if (!Number.isFinite(parsedId)) {
              throw new HttpError(400, "BAD_REQUEST", "id must be a valid integer");
            }
            q = q.eq("id", parsedId).limit(1);
          } else {
            // Apply user_id filter if provided (canonical account id, takes priority)
            if (user_id_param) {
              q = q.eq("user_id", user_id_param);
            }
            // Apply author_id filter if provided (persona id)
            else if (author_id_param) {
              q = q.eq("author_id", author_id_param);
            }

            // ── post_type filter ──
            // For thread feed: include both post_type='thread' AND show_in_feed=true posts.
            // BUT: only expand with show_in_feed when NOT scoped to room_scope='rooms',
            // because profile room-thread queries should not leak status posts via show_in_feed.
            if (post_type_param) {
              const VALID_POST_TYPES = ["status", "thread", "share"];
              const types = post_type_param.split(",").map(t => t.trim()).filter(Boolean);
              for (const t of types) {
                if (!VALID_POST_TYPES.includes(t)) {
                  throw new HttpError(400, "BAD_REQUEST", `invalid post_type: ${t}`);
                }
              }
              const includesThread = types.includes("thread");
              const isThreadFeedContext = includesThread && room_scope_param !== "rooms";
              if (isThreadFeedContext && types.length === 1) {
                // Thread feed: include post_type='thread' OR show_in_feed=true
                q = q.or("post_type.eq.thread,show_in_feed.eq.true");
              } else if (types.length === 1) {
                q = q.eq("post_type", types[0]);
              } else if (types.length > 1) {
                if (isThreadFeedContext) {
                  // Multi-type including thread: include those types OR show_in_feed=true
                  q = q.or(`post_type.in.(${types.join(",")}),show_in_feed.eq.true`);
                } else {
                  q = q.in("post_type", types);
                }
              }
            }

            // ── root_only / parent_post_id filter ──
            if (parent_post_id_param) {
              const parsedPpid = Number(parent_post_id_param);
              if (!Number.isFinite(parsedPpid)) {
                throw new HttpError(400, "BAD_REQUEST", "parent_post_id must be a valid integer");
              }
              q = q
                .eq("root_post_id", parsedPpid)
                .not("parent_post_id", "is", null);
              // Apply cursor keyset filter for reply pagination
              if (cursor) {
                q = q.or(
                  `created_at.lt.${cursor.created_at},and(created_at.eq.${cursor.created_at},id.lt.${cursor.id})`
                );
              }
            } else if (root_only_param === "1" || root_only_param === "true") {
              q = q.is("parent_post_id", null);
            }

            // Apply cursor keyset filter for scoped (non-reply) pagination
            if (!isReplyQuery && cursor) {
              q = q.or(
                `created_at.lt.${cursor.created_at},and(created_at.eq.${cursor.created_at},id.lt.${cursor.id})`
              );
            }

            // ── room_scope / room_id filter ──
            // room_id takes precedence for specific-room queries;
            // room_scope adds global/rooms scoping for profile tabs.
            if (room_id_param && room_id_param !== "global") {
              // Specific room: enforce membership policy
              const { data: roomRow } = await sb(env).from("rooms").select("read_policy").eq("id", room_id_param).maybeSingle();
              if (roomRow && roomRow.read_policy === "members_only") {
                const callerId = await optionalAuth(req, env);
                if (!callerId) throw new HttpError(403, "FORBIDDEN", "This room requires membership to read");
                const memberRole = await checkRoomMembership(env, room_id_param, callerId);
                if (!memberRole) throw new HttpError(403, "FORBIDDEN", "This room requires membership to read");
              }
              q = q.eq("room_id", room_id_param);
            } else {
              // Determine effective room scope
              let effectiveScope = "any";
              if (room_id_param === "global") effectiveScope = "global";
              else if (room_scope_param) {
                if (!["global", "rooms", "any"].includes(room_scope_param)) {
                  throw new HttpError(400, "BAD_REQUEST", `invalid room_scope: ${room_scope_param}`);
                }
                effectiveScope = room_scope_param;
              }
              if (effectiveScope === "global") {
                // Global posts: room_id is either NULL or 'global'
                q = q.or("room_id.is.null,room_id.eq.global");
              } else if (effectiveScope === "rooms") {
                q = q.not("room_id", "is", null).neq("room_id", "global");
              }
              // effectiveScope === "any": no room filter
            }
            // ── mode filter (CSV → .in) ──
            if (mode_param) {
              const modes = mode_param.split(",").map(m => m.trim()).filter(Boolean);
              if (modes.length > 0) {
                q = q.in("mode", modes);
              }
            }

            // ── mood filter (CSV → .overlaps for array column) ──
            if (mood_param) {
              const moods = mood_param.split(",").map(m => m.trim()).filter(Boolean);
              if (moods.length > 0) {
                q = q.overlaps("moods", moods);
              }
            }

            // ── keyword search (ILIKE on title + content) ──
            if (q_param && q_param.trim().length > 0) {
              const keyword = `%${q_param.trim()}%`;
              q = q.or(
                `title.ilike.${keyword},content.ilike.${keyword}`
              );
            }

            // ── room_category filter (CSV → .in) ──
            if (room_category_param) {
              const categories = room_category_param.split(",").map(c => c.trim()).filter(Boolean);
              if (categories.length > 0) {
                q = q.in("room_category", categories);
              }
            }

            // ── include_global filter ──
            // When include_global=0, exclude global/non-room thread posts
            // (only show room-origin feed posts). Default: include everything.
            if (include_global_param === "0") {
              q = q.not("room_id", "is", null).neq("room_id", "global");
            }

            // Determine limit — for reply queries default 20/max 200, otherwise 50/max 200
            lim = isReplyQuery ? 20 : 50;
            if (limit_param) {
              const parsed = parseInt(limit_param, 10);
              if (!isNaN(parsed)) {
                lim = Math.min(200, Math.max(1, parsed));
              }
            }
            // Add secondary order by id for stable keyset pagination
            q = q.order("id", { ascending: false });
            q = q.limit(lim);
          }
          const p2 = performance.now();

          const queryFilters: string[] = [];
          if (id_param) queryFilters.push(`id=eq.${id_param}`);
          if (user_id_param) queryFilters.push(`user_id=eq.${user_id_param}`);
          else if (author_id_param) queryFilters.push(`author_id=eq.${author_id_param}`);
          if (post_type_param) queryFilters.push(`post_type=in.(${post_type_param})`);
          if (parent_post_id_param) queryFilters.push(`parent_post_id=eq.${parent_post_id_param}`);
          else if (root_only_param === "1" || root_only_param === "true") queryFilters.push(`parent_post_id=is.null`);
          if (room_id_param && room_id_param !== "global") queryFilters.push(`room_id=eq.${room_id_param}`);
          else if (room_scope_param === "global" || room_id_param === "global") queryFilters.push(`room_id=is.null|eq.global`);
          else if (room_scope_param === "rooms") queryFilters.push(`room_id=not.is.null&neq.global`);
          if (cursor) queryFilters.push(`cursor=${cursor.created_at}:${cursor.id}`);
          const queryEvidence = `table=posts select=${selectFields} filters=[${queryFilters.join(",")}] order=created_at.desc,id.desc limit=${lim}`;

          let t1 = Date.now();
          let posts: any[] | null = null;
          let postsQueryMs = 0;
          // HTTP-level metrics (reply queries only)
          let replyHttpMs = "";
          let replyParseMs = "";
          let replyStatus = 0;
          let replyHeaders: Record<string, string> = {};

          // ── Speculative: fire auxiliary queries for single-post fast path ──
          // post_id is known from the URL param, so media + likes can start
          // in parallel with the main SELECT instead of waiting for it.
          let speculativeAux: PromiseLike<any[]> | null = null;
          const specStartMs = Date.now();
          if (id_param && !isReplyQuery) {
            const postId = Number(id_param);
            if (Number.isFinite(postId)) {
              speculativeAux = Promise.all([
                sb(env).from("media")
                  .select("id, post_id, type, key, thumb_key, width, height, duration_ms")
                  .eq("post_id", postId),
                sb(env).from("post_likes")
                  .select("post_id, actor_id")
                  .eq("post_id", postId),
              ]);
            }
          }

          if (isReplyQuery) {
            // ── Direct PostgREST fetch for reply queries: HTTP timing + header capture ──
            const parsedPpid = Number(parent_post_id_param);
            let restUrl = `${env.SUPABASE_URL}/rest/v1/posts?select=${encodeURIComponent(feedSelectFields)}&root_post_id=eq.${parsedPpid}&parent_post_id=not.is.null&deleted_at=is.null&order=created_at.desc,id.desc&limit=${lim}`;
            // Append keyset cursor filter if present
            if (cursor) {
              restUrl += `&or=(created_at.lt.${encodeURIComponent(cursor.created_at)},and(created_at.eq.${encodeURIComponent(cursor.created_at)},id.lt.${cursor.id}))`;
            }

            const tFetchStart = performance.now();
            const res = await fetch(restUrl, {
              method: "GET",
              headers: {
                "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
                "Accept": "application/json",
              },
            });
            const tFetchEnd = performance.now();

            if (!res.ok) {
              const errBody = await res.text().catch(() => "");
              throw new Error(`PostgREST replies ${res.status}: ${errBody}`);
            }

            const rawBody = await res.text();
            const tTextEnd = performance.now();
            posts = JSON.parse(rawBody);
            const tParseEnd = performance.now();

            postsQueryMs = Math.round(tParseEnd - tFetchStart);
            replyHttpMs = (tFetchEnd - tFetchStart).toFixed(1);
            replyParseMs = ((tTextEnd - tFetchEnd) + (tParseEnd - tTextEnd)).toFixed(1);
            replyStatus = res.status;
            replyHeaders = {
              serverTiming: res.headers.get("server-timing") ?? "none",
              xResponseTime: res.headers.get("x-response-time") ?? "none",
              cfRay: res.headers.get("cf-ray") ?? "none",
              cfCache: res.headers.get("cf-cache-status") ?? "none",
              contentRange: res.headers.get("content-range") ?? "none",
            };
          } else {
            // ── Standard Supabase client for non-reply queries ──
            const { data, error: qErr } = await q;
            postsQueryMs = Date.now() - t1;
            if (qErr) throw qErr;
            posts = data;
          }
          const p3 = performance.now();

          // Granular logging + slow-query alert
          // NOTE: no { count: "exact" } is used — entire posts_query time IS select_ms, count_ms=0
          const filterDesc = id_param ? `id=${id_param}` : [user_id_param && `user_id=${user_id_param}`, author_id_param && `author_id=${author_id_param}`, room_id_param && `room_id=${room_id_param}`, post_type_param && `post_type=${post_type_param}`, root_only_param && `root_only=${root_only_param}`, parent_post_id_param && `parent_post_id=${parent_post_id_param}`, room_scope_param && `room_scope=${room_scope_param}`].filter(Boolean).join(",") || "feed";
          console.log(`[perf] /api/posts posts_query_split rid=${request_id} select_ms=${postsQueryMs} count_ms=0 filter=${filterDesc} limit=${limit_param || 50} rows=${posts?.length ?? 0}`);
          if (postsQueryMs > 400) {
            console.log(`[perf] /api/posts SLOW_QUERY rid=${request_id} select_ms=${postsQueryMs} count_ms=0 filter=${filterDesc} limit=${limit_param || 50} rows=${posts?.length ?? 0}`);
          }

          // ── Replies-specific perf logs ──
          if (isReplyQuery) {
            console.log(`[perf][replies] rid=${request_id} parent_post_id=${parent_post_id_param} limit=${lim} order=created_at_desc,id_desc select_ms=${postsQueryMs} http_ms=${replyHttpMs} parse_ms=${replyParseMs} rows=${posts?.length ?? 0}`);
            console.log(`[perf][replies_http] rid=${request_id} parent_post_id=${parent_post_id_param} http_ms=${replyHttpMs} parse_ms=${replyParseMs} status=${replyStatus} server_timing="${replyHeaders.serverTiming}" x_response_time="${replyHeaders.xResponseTime}" cf_ray="${replyHeaders.cfRay}" cf_cache="${replyHeaders.cfCache}" content_range="${replyHeaders.contentRange}"`);
          }

          // Fast path: no posts => return immediately
          const postIds = (posts ?? []).map((p: any) => p.id);

          // Step 1 (cont): log ids shape after posts query returns
          logDiag("/api/posts posts_result", {
            rid: request_id, posts_rows: postIds.length,
            ids_count: postIds.length,
            first_id: postIds[0] ?? null, last_id: postIds[postIds.length - 1] ?? null,
            select_ms: +(p3 - p2).toFixed(1),
          });

          if (postIds.length === 0) {
            // Step 3: parallel_skipped for empty posts
            console.log(`[perf] /api/posts total ${Date.now() - handlerStart}ms (empty)`);
            console.log(`[perf] /api/posts breakdown rid=${request_id} params=${(p1 - p0).toFixed(1)} client=${(p2 - p1).toFixed(1)} db_posts=${(p3 - p2).toFixed(1)} transform=0 total=${(p3 - p0).toFixed(1)} rows=0`);
            console.log(`[perf] /api/posts parallel_skipped`, JSON.stringify({ rid: request_id, reason: "empty_posts", room_id: room_id_param || "none", limit: limit_param || 50, db_posts_ms: +(p3 - p2).toFixed(1), total_ms: +(p3 - p0).toFixed(1) }));
            if (isReplyQuery) {
              return ok(req, env, request_id, { items: [], next_cursor: null });
            }
            return ok(req, env, request_id, { posts: [] });
          }

          // ── Single-post fast path ──
          // Post is already fetched above. media + likes were fired speculatively
          // BEFORE the main SELECT, so they ran in parallel with it.
          // Awaiting them here is nearly free (~0-10ms wait).
          // comment_count defaults to 0 (thread UI fetches comments separately)
          if (id_param && postIds.length === 1 && speculativeAux) {
            const singlePost = (posts as any[])[0];
            const fastStart = Date.now();

            // Profile: KV-cached lookup first, DB fallback only on miss
            const tProf = Date.now();
            let profile: any = null;
            let profSrc = "none";
            if (singlePost.author_id) {
              const profKvKey = `profile:${singlePost.author_id}`;
              try {
                const kvRaw = await env.PROFILE_KV.get(profKvKey, "text");
                if (kvRaw) {
                  profile = JSON.parse(kvRaw);
                  profSrc = "kv";
                }
              } catch { /* KV miss — fall through */ }
            }
            const profKvMs = Date.now() - tProf;

            // Await speculative results (fired before main SELECT — should already be done)
            const tAux = Date.now();
            const auxResults = await speculativeAux;
            // Profile DB fallback if KV missed — fire now (only query that needs post data)
            if (singlePost.author_id && !profile) {
              profSrc = "db";
              const { data: profRow } = await sb(env).from("user_profiles")
                .select("user_id, teran_id, display_name, avatar")
                .eq("user_id", singlePost.author_id)
                .maybeSingle();
              profile = profRow;
            }
            const auxWaitMs = Date.now() - tAux;

            const mediaResult = auxResults[0];
            const likeData = auxResults[1];

            const mediaRows = mediaResult.data ?? [];
            const likes = likeData.data ?? [];
            const likeCount = likes.length;
            const likedByMe = actor_id_param ? likes.some((l: any) => l.actor_id === actor_id_param) : false;

            let avatar = singlePost.author_avatar;
            if (typeof avatar === "string" && avatar.startsWith("data:")) avatar = null;

            const enriched = {
              ...singlePost,
              media: mediaRows,
              author_name: profile?.display_name || singlePost.author_name,
              author_avatar: profile?.avatar || avatar,
              like_count: likeCount,
              liked_by_me: likedByMe,
              comment_count: 0,  // thread UI fetches comments separately
              teran_id: profile?.teran_id ?? null,
            };

            const totalFastMs = Date.now() - fastStart;
            console.log(`[perf] /api/posts single_post_fast`, JSON.stringify({ rid: request_id, path: "single_post_fast", select_ms: postsQueryMs, prof_kv_ms: profKvMs, prof_src: profSrc, aux_wait_ms: auxWaitMs, total_fast_ms: totalFastMs, total_ms: postsQueryMs + totalFastMs, likes: likeCount, media: mediaRows.length }));

            return ok(req, env, request_id, { posts: [enriched] });
          }

          // ── Suspect isolation: diag modes ──
          const postsSelectMs = +(p3 - p2).toFixed(1);
          if (diag_param === "posts_only") {
            const totalMs = +(performance.now() - p0).toFixed(1);
            logDiag("/api/posts mode=posts_only", {
              rid: request_id, posts_select_ms: postsSelectMs, posts_rows: postIds.length,
            });
            logPerf("/api/posts diag_breakdown", {
              rid: request_id, mode: "posts_only",
              posts_select_ms: postsSelectMs, parallel_ms: 0, total_ms: totalMs,
            });
            const body = JSON.stringify({ posts: posts ?? [], diag: { mode: "posts_only" } });
            return new Response(body, {
              status: 200,
              headers: { "Content-Type": "application/json", "X-Request-Id": request_id, ...corsHeaders(req, env) },
            });
          }

          if (diag_param && diag_param.startsWith("only_parallel:")) {
            const which = diag_param.slice("only_parallel:".length);
            if (!["media", "likes", "commentCounts"].includes(which)) {
              return new Response(JSON.stringify({ error: { code: "BAD_REQUEST", message: `invalid diag target: ${which}` } }), {
                status: 400,
                headers: { "Content-Type": "application/json", "X-Request-Id": request_id, ...corsHeaders(req, env) },
              });
            }
            let parallelMs = 0;
            let rowCount = 0;

            if (which === "media") {
              const t = Date.now();
              const { data } = await sb(env).from("media")
                .select("id, post_id, type, key, thumb_key, width, height, duration_ms")
                .in("post_id", postIds);
              parallelMs = Date.now() - t;
              rowCount = (data ?? []).length;
            } else if (which === "likes") {
              const t = Date.now();
              const { data } = await sb(env).from("post_likes")
                .select("post_id, actor_id")
                .in("post_id", postIds);
              parallelMs = Date.now() - t;
              rowCount = (data ?? []).length;
            } else if (which === "commentCounts") {
              const t = Date.now();
              const { data } = await sb(env)
                .rpc("get_comment_counts", { parent_ids: postIds });
              parallelMs = Date.now() - t;
              rowCount = (data ?? []).length;
            }

            const totalMs = +(performance.now() - p0).toFixed(1);
            logDiag(`/api/posts mode=only_parallel which=${which}`, {
              rid: request_id, posts_select_ms: postsSelectMs,
              [`${which}_ms`]: parallelMs, [`${which}_rows`]: rowCount,
            });
            logPerf("/api/posts diag_breakdown", {
              rid: request_id, mode: "only_parallel", which,
              posts_select_ms: postsSelectMs, parallel_ms: parallelMs, total_ms: totalMs,
            });
            const body = JSON.stringify({ posts: posts ?? [], diag: { mode: "only_parallel", which } });
            return new Response(body, {
              status: 200,
              headers: { "Content-Type": "application/json", "X-Request-Id": request_id, ...corsHeaders(req, env) },
            });
          }

          // ── Light mode: skip enrichment, return posts with avatar sanitization only ──
          let enrichedPosts: any[];
          let parallelMs = 0;
          let p4 = performance.now();
          let p5 = p4;
          // Hoisted from else block so perf-logging (after if/else) can reference them
          let mediaMs = 0, likesMs = 0, commentCountMs = 0;
          let mediaRows: any[] = [];
          let allLikeRows: any[] = [];
          let commentCountRows: any[] = [];
          const mediaSelectCols = "id, post_id, type, key, thumb_key, width, height, duration_ms";
          const mediaWhereShape = "post_id IN";
          const likesSelectCols = "post_id, actor_id";
          const likesWhereShape = "post_id IN";
          const commentCountsWhereShape = "rpc:get_comment_counts(parent_ids)";

          // ── Batch-fetch teran_id for all unique author_ids (skip in light mode) ──
          const uniqueAuthorIds = [...new Set((posts ?? []).map((p: any) => p.author_id).filter(Boolean))];
          let teranIdMap: Record<string, string | null> = {};
          let teranIdMs = 0;
          // Build a profileMap for live identity overlay (display_name, avatar)
          const profileMap: Record<string, { display_name?: string; avatar?: string }> = {};
          if (!light && uniqueAuthorIds.length > 0) {
            const tTid = Date.now();
            const { data: tidRows } = await sb(env)
              .from("user_profiles")
              .select("user_id, teran_id, display_name, avatar")
              .in("user_id", uniqueAuthorIds);
            teranIdMs = Date.now() - tTid;
            for (const row of (tidRows ?? []) as any[]) {
              if (row.teran_id) teranIdMap[row.user_id] = row.teran_id;
              profileMap[row.user_id] = { display_name: row.display_name, avatar: row.avatar };
            }
          }

          if (light) {
            // Light path: skip likes + commentCounts + teranId
            // Media is embedded in the posts query via PostgREST relationship
            // (no separate media HTTP round-trip needed)
            mediaMs = 0; // embedded — no separate fetch

            // Start transform timing
            p4 = performance.now();

            let totalMediaRows = 0;
            enrichedPosts = (posts ?? []).map((p: any) => {
              let avatar = p.author_avatar;
              if (typeof avatar === "string" && avatar.startsWith("data:")) {
                avatar = null;
              }
              // media is already attached by PostgREST embed as p.media[]
              const embeddedMedia = Array.isArray(p.media) ? p.media : [];
              totalMediaRows += embeddedMedia.length;
              return { ...p, author_avatar: avatar, media: embeddedMedia, like_count: 0, liked_by_me: false, comment_count: 0, teran_id: null };
            });
            mediaRows = []; // not used in light mode, but keep variable populated for downstream logging
            p5 = performance.now();
            console.log(`[perf] /api/posts light_mode rid=${request_id} posts=${enrichedPosts.length} media_rows=${totalMediaRows} media_embed=true transform_ms=${(p5 - p4).toFixed(1)} skip=likes,commentCounts,teranId,mediaSeparateFetch`);
          } else {
            // Parallel fetch: media + likes + comment counts
            const parallelStart = Date.now();

            // Step 2: log pre-execution query shape for each parallel query
            logDiag("/api/posts parallel_pre", {
              rid: request_id, ids_count: postIds.length,
              media: { select_cols: mediaSelectCols, where_shape: mediaWhereShape, table: "media" },
              likes: { select_cols: likesSelectCols, where_shape: likesWhereShape, table: "post_likes" },
              commentCounts: { where_shape: commentCountsWhereShape, table: "rpc" },
            });

            const mediaQuery = (async () => {
              const t = Date.now();
              const { data } = await sb(env)
                .from("media")
                .select(mediaSelectCols)
                .in("post_id", postIds);
              mediaMs = Date.now() - t;
              return data ?? [];
            })();

            // Merged likes query: fetch post_id + actor_id in one roundtrip
            // Compute like_count (group by post_id) and liked_by_me (filter actor_id) in JS
            const likesQuery = (async () => {
              const t = Date.now();
              const { data } = await sb(env)
                .from("post_likes")
                .select(likesSelectCols)
                .in("post_id", postIds);
              likesMs = Date.now() - t;
              return data ?? [];
            })();

            // Comment counts via RPC (direct replies only)
            const commentCountsQuery = (async () => {
              const t = Date.now();
              const { data, error: rpcErr } = await sb(env)
                .rpc("get_comment_counts", { parent_ids: postIds });
              commentCountMs = Date.now() - t;
              if (rpcErr) {
                console.error(`[perf] /api/posts comment_counts RPC error rid=${request_id}`, rpcErr);
                return [];
              }
              return data ?? [];
            })();

            [mediaRows, allLikeRows, commentCountRows] = await Promise.all([
              mediaQuery,
              likesQuery,
              commentCountsQuery,
            ]);
            parallelMs = Date.now() - parallelStart;
            p4 = performance.now();

            console.log(`[perf] /api/posts parallel_queries ${parallelMs}ms`, {
              media: mediaMs,
              likes: likesMs,
              commentCounts: commentCountMs,
              mediaCount: mediaRows.length,
              likeRows: (allLikeRows as any[]).length,
              commentCountRows: (commentCountRows as any[]).length,
            });

            // Process results
            const mediaByPost: Record<number, any[]> = {};
            for (const m of mediaRows) {
              if (!mediaByPost[m.post_id]) mediaByPost[m.post_id] = [];
              mediaByPost[m.post_id].push(m);
            }

            // Compute like_count and liked_by_me from merged result
            const likeCounts: Record<number, number> = {};
            const likedByActorSet = new Set<number>();
            for (const row of allLikeRows as any[]) {
              likeCounts[row.post_id] = (likeCounts[row.post_id] || 0) + 1;
              if (actor_id_param && row.actor_id === actor_id_param) {
                likedByActorSet.add(row.post_id);
              }
            }

            // Build comment count map from RPC result
            const commentCounts: Record<number, number> = {};
            for (const row of commentCountRows as any[]) {
              commentCounts[row.parent_post_id] = Number(row.comment_count) || 0;
            }

            // Enrich posts with media, like_count, liked_by_me, comment_count
            enrichedPosts = (posts ?? []).map((p: any) => {
              let avatar = p.author_avatar;
              if (typeof avatar === "string" && avatar.startsWith("data:")) {
                avatar = null;
              }
              // Live identity overlay: prefer user_profiles values over post snapshot
              const profile = profileMap[p.author_id];
              const liveDisplayName = profile?.display_name || null;
              const liveAvatar = profile?.avatar || null;
              return {
                ...p,
                author_name: liveDisplayName || p.author_name,
                author_avatar: liveAvatar || avatar,
                media: mediaByPost[p.id] || [],
                like_count: likeCounts[p.id] || 0,
                liked_by_me: likedByActorSet.has(p.id),
                comment_count: commentCounts[p.id] || 0,
                teran_id: teranIdMap[p.author_id] ?? null,
              };
            });
            p5 = performance.now();
          } // end !light

          const responsePayload = isReplyQuery
            ? { items: enrichedPosts, next_cursor: buildNextCursor(enrichedPosts, lim) }
            : { posts: enrichedPosts, next_cursor: isScopedQuery ? buildNextCursor(enrichedPosts, lim) : undefined };
          const tSerialize = performance.now();
          const responseBody = JSON.stringify(responsePayload);
          const serializeMs = performance.now() - tSerialize;
          const postsTotal = performance.now() - p0;
          // Populate reqCtx so [sum] log includes perf breakdown
          // Wrapped in try-catch: perf logging must NEVER crash the endpoint
          try {
            reqCtx.params_ms = +(p1 - p0).toFixed(1);
            reqCtx.client_ms = +(p2 - p1).toFixed(1);
            reqCtx.db_posts_ms = +(p3 - p2).toFixed(1);
            reqCtx.parallel_ms = parallelMs;
            reqCtx.transform_ms = +(p5 - p4).toFixed(1);
            reqCtx.serialize_ms = +serializeMs.toFixed(1);
            reqCtx.total_ms = +postsTotal.toFixed(1);
            reqCtx.cache = cacheStatus;
            reqCtx.select_ms = postsQueryMs;
            reqCtx.media_ms = mediaMs;
            reqCtx.likes_ms = likesMs;
            reqCtx.cc_ms = commentCountMs;
            reqCtx.rows = enrichedPosts.length;
            reqCtx.ids_count = postIds.length;
            reqCtx.media_count = mediaRows.length;
            reqCtx.likes_count = (allLikeRows as any[]).length;
            reqCtx.comment_counts_count = (commentCountRows as any[]).length;
            reqCtx.bytes = responseBody.length;
            console.log(`[perf] /api/posts breakdown rid=${request_id} cache=${cacheStatus} params=${(p1 - p0).toFixed(1)} client=${(p2 - p1).toFixed(1)} db_posts=${(p3 - p2).toFixed(1)} parallel=${(p4 - p3).toFixed(1)} transform=${(p5 - p4).toFixed(1)} total=${postsTotal.toFixed(1)} rows=${enrichedPosts.length}`);
            if (postsTotal >= 300) {
              console.log(`[perf] /api/posts breakdown2`, JSON.stringify({
                rid: request_id,
                filter: { post_type: post_type_param || "all", root_only: root_only_param || "false", room_scope: room_scope_param || "none", limit: limit_param || 50 },
                posts_select_ms: +(p3 - p2).toFixed(1), posts_rows: postIds.length,
                media_ms: mediaMs, media_rows: mediaRows.length,
                likes_ms: likesMs, likes_rows: (allLikeRows as any[]).length,
                comment_counts_ms: commentCountMs, comment_counts_rows: (commentCountRows as any[]).length,
                transform_ms: +(p5 - p4).toFixed(1),
                serialize_ms: +serializeMs.toFixed(1),
                payload_bytes: responseBody.length,
                total_ms: +postsTotal.toFixed(1),
              }));
            }

            // Step 4: breakdown3 — query-shape diagnostics for bottleneck identification
            logPerf("/api/posts breakdown3", {
              rid: request_id,
              filter: postsFilterShape,
              posts_select_cols: selectFields,
              posts_select_ms: +(p3 - p2).toFixed(1),
              posts_rows: postIds.length,
              ids_count: postIds.length,
              ids_first: postIds[0] ?? null, ids_last: postIds[postIds.length - 1] ?? null,
              media_where_shape: mediaWhereShape, media_select_cols: mediaSelectCols,
              media_ms: mediaMs, media_rows: mediaRows.length,
              likes_where_shape: likesWhereShape, likes_select_cols: likesSelectCols,
              likes_ms: likesMs, likes_rows: (allLikeRows as any[]).length,
              commentCounts_where_shape: commentCountsWhereShape,
              commentCounts_ms: commentCountMs, commentCounts_rows: (commentCountRows as any[]).length,
              transform_ms: +(p5 - p4).toFixed(1),
              serialize_ms: +serializeMs.toFixed(1),
              total_ms: +postsTotal.toFixed(1),
            });
            if (isReplyQuery) {
              const serializeMs = performance.now();
              console.log(`[perf][replies_breakdown] rid=${request_id} parent_post_id=${parent_post_id_param} http_ms=${replyHttpMs} parse_ms=${replyParseMs} parallel_ms=${(p4 - p3).toFixed(1)} transform_ms=${(p5 - p4).toFixed(1)} serialize_ms=${(serializeMs - p5).toFixed(1)} total_ms=${(serializeMs - p0).toFixed(1)} rows=${enrichedPosts.length} payload_bytes=${responseBody.length}`);
            }

            if (postsTotal >= SLOW_MS) {
              console.log(JSON.stringify({
                tag: "slow",
                rid: request_id,
                total_ms: +postsTotal.toFixed(1),
                cache_lookup_ms: cacheLookupMs,
                select_ms: +postsQueryMs,
                parallel_ms: parallelMs,
                media_ms: mediaMs,
                likes_ms: likesMs,
                comment_counts_ms: commentCountMs,
                cache_hit: cacheStatus,
                cache_key: feedCacheKey?.url || "none",
                rows: enrichedPosts.length,
                payload_bytes: responseBody.length,
              }));
            }

            if (postsTotal >= VERY_SLOW_MS) {
              console.log(JSON.stringify({
                tag: "very_slow",
                rid: request_id,
                total_ms: +postsTotal.toFixed(1),
                cache_lookup_ms: cacheLookupMs,
                select_ms: +postsQueryMs,
                parallel_ms: parallelMs,
                media_ms: mediaMs,
                likes_ms: likesMs,
                comment_counts_ms: commentCountMs,
                transform_ms: +(p5 - p4).toFixed(1),
                serialize_ms: +serializeMs.toFixed(1),
                cache_hit: cacheStatus,
                cache_key: feedCacheKey?.url || "none",
                rows: enrichedPosts.length,
                payload_bytes: responseBody.length,
                shape: {
                  limit: lim,
                  cursor: cursor ? `${cursor.created_at}:${cursor.id}` : null,
                  root_only: root_only_param || "false",
                  room_scope: room_scope_param || "none",
                  room_id: room_id_param || "none",
                  post_type: post_type_param || "all",
                  select_cols: selectFields,
                  is_reply: isReplyQuery,
                },
                query_evidence: queryEvidence,
                media_rows: mediaRows.length,
                likes_rows: (allLikeRows as any[]).length,
                comment_count_rows: (commentCountRows as any[]).length,
              }));
            }
          } catch (perfErr) {
            console.error(`[perf] /api/posts logging_error rid=${request_id}`, perfErr);
          }

          // ── Store in edge cache (feed only, fire-and-forget) ──
          if (isFeed && feedCacheKey) {
            ctx.waitUntil(
              cache.put(feedCacheKey, new Response(responseBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": `public, max-age=${FEED_CACHE_TTL}`,
                },
              }))
                .then(() => console.log(`[cache] posts/feed put ok rid=${request_id} limit=${limit_param || 50} actor=${actor_id_param || "none"} ttl=${FEED_CACHE_TTL}s bytes=${responseBody.length}`))
                .catch((err) => console.error(`[cache] posts/feed put fail rid=${request_id}`, err))
            );
          }

          return new Response(responseBody, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Request-Id": request_id,
              "X-Cache": isFeed ? "MISS" : "BYPASS",
              ...corsHeaders(req, env),
            },
          });
        }

        // /api/posts (POST)
        if (path === "/api/posts" && req.method === "POST") {
          const t0 = performance.now();
          const marks: Record<string, number> = {};
          const mark = (k: string) => { marks[k] = performance.now(); };

          // ── Phase 1: JWT verification ──
          const user_id = await requireAuth(req, env);
          mark("jwt");

          // ── Phase 2: Body parse ──
          const body = (await req.json().catch(() => null)) as any;
          mark("json_parse");

          // ── Phase 3: All cheap validation (fail-fast before any DB call) ──
          const content = typeof body?.content === "string" ? body.content.trim() : "";
          const mediaInput = Array.isArray(body?.media) ? body.media : [];
          if (!content && mediaInput.length === 0) {
            throw new HttpError(422, "VALIDATION_ERROR", "content or media required");
          }

          const title = typeof body?.title === "string" ? body.title.trim() : "";
          // SECURITY: author_id from body is untrusted — must verify the caller
          // owns this persona before allowing them to post as it.
          const raw_author_id = typeof body?.author_id === "string" ? body.author_id.trim() : null;
          const author_name = typeof body?.author_name === "string" ? body.author_name : null;
          const rawAuthorAvatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;
          if (rawAuthorAvatar && rawAuthorAvatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "author_avatar must be a URL, not a data URI");
          }
          const author_avatar = rawAuthorAvatar;
          const room_id = typeof body?.room_id === "string" ? body.room_id : null;
          const rawShowInFeed = body?.show_in_feed === true || body?.show_in_feed === "true";
          console.log(`[ROOM_FEED_DEBUG][POST_PARSE]`, { rid: request_id, room_id, raw_show_in_feed: body?.show_in_feed, rawShowInFeed, raw_post_type: body?.post_type, resolved_post_type: typeof body?.post_type === "string" && ["status","share","thread"].includes(body.post_type) ? body.post_type : "status" });

          // Parse reply/share fields with robust numeric coercion
          const rawParentPostId = body?.parent_post_id;
          const parent_post_id = rawParentPostId != null ? (Number.isFinite(Number(rawParentPostId)) ? Number(rawParentPostId) : null) : null;

          const rawPostType = body?.post_type;
          const post_type = typeof rawPostType === "string" && ["status", "share", "thread"].includes(rawPostType)
            ? rawPostType
            : "status";

          // ── Text length limits (must match frontend LIMITS constants) ──
          const LIMIT_STATUS_CONTENT = 360;
          const LIMIT_THREAD_TITLE = 100;
          const LIMIT_THREAD_BODY = 600;
          if (post_type === "thread") {
            if (title.length > LIMIT_THREAD_TITLE) throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_THREAD_TITLE} characters for title`);
            if (content.length > LIMIT_THREAD_BODY) throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_THREAD_BODY} characters for content`);
          } else {
            if (content.length > LIMIT_STATUS_CONTENT) throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_STATUS_CONTENT} characters`);
          }

          const rawSharedPostId = body?.shared_post_id;
          const shared_post_id = rawSharedPostId != null ? (Number.isFinite(Number(rawSharedPostId)) ? Number(rawSharedPostId) : null) : null;

          // ── Mode + Moods ──
          // Canonical mode values — enforced here at the API layer, client, and DB (posts_mode_check constraint).
          const ALLOWED_MODES = new Set(["Ask", "Discuss", "Share"]);
          const DEFAULT_MODE = "Discuss";
          const VALID_MOODS = new Set(["Happy", "Curious", "Sad", "Anxious", "Frustrated", "LowBattery", "Meh", "OffUneasy", "Laughing", "Angry", "Tired"]);
          const MAX_MOODS = 2;

          const rawMode = body?.mode;
          const isValidMode = typeof rawMode === "string" && ALLOWED_MODES.has(rawMode);
          const isProd = (env as any).ENVIRONMENT === "production" || !(env as any).ENVIRONMENT;

          if (!isValidMode && !isProd) {
            console.warn(`[posts][${request_id}] REJECT invalid mode`, { raw: rawMode, user_id, ua: req.headers.get("user-agent")?.slice(0, 80) });
            throw new HttpError(400, "invalid_mode", `mode must be one of: ${[...ALLOWED_MODES].join(", ")}`);
          }

          const mode: string = isValidMode ? rawMode! : DEFAULT_MODE;
          if (!isValidMode) {
            console.warn(`[posts][${request_id}] WARN mode_fallback`, {
              received: rawMode, normalized: mode, user_id,
              ua: req.headers.get("user-agent")?.slice(0, 80),
              endpoint: "/api/posts",
            });
          }

          let moods: string[] = [];
          if (Array.isArray(body?.moods)) {
            moods = body.moods
              .filter((m: unknown) => typeof m === "string" && VALID_MOODS.has(m as string))
              .slice(0, MAX_MOODS);
          }

          // Media validation
          const MAX_IMAGES = 4;
          const MAX_VIDEOS = 1;
          const validatedMedia: Array<{
            type: "image" | "video";
            key: string;
            thumb_key?: string | null;
            width?: number | null;
            height?: number | null;
            bytes?: number | null;
            duration_ms?: number | null;
          }> = [];

          let imageCount = 0;
          let videoCount = 0;

          for (const m of mediaInput) {
            const mType = m?.type;
            const mKey = m?.key;
            const mThumbKey = m?.thumb_key;

            if (!mType || !mKey || typeof mKey !== "string" || !mKey.trim()) {
              throw new HttpError(422, "VALIDATION_ERROR", "Each media item must have type and key");
            }

            if (mType === "image") {
              imageCount++;
              if (imageCount > MAX_IMAGES) {
                throw new HttpError(422, "VALIDATION_ERROR", `Maximum ${MAX_IMAGES} images allowed`);
              }
              if (!mThumbKey || typeof mThumbKey !== "string" || !mThumbKey.trim()) {
                throw new HttpError(422, "VALIDATION_ERROR", "thumb_key is required for images");
              }
              validatedMedia.push({
                type: "image",
                key: mKey.trim(),
                thumb_key: mThumbKey.trim(),
                width: typeof m?.width === "number" ? m.width : null,
                height: typeof m?.height === "number" ? m.height : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
              });
            } else if (mType === "video") {
              videoCount++;
              if (videoCount > MAX_VIDEOS) {
                throw new HttpError(422, "VALIDATION_ERROR", `Maximum ${MAX_VIDEOS} video allowed per post`);
              }
              validatedMedia.push({
                type: "video",
                key: mKey.trim(),
                thumb_key: mThumbKey ? mThumbKey.trim() : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
                duration_ms: typeof m?.duration_ms === "number" ? m.duration_ms : null,
              });
            } else {
              throw new HttpError(422, "VALIDATION_ERROR", "Media type must be 'image' or 'video'");
            }
          }
          mark("validation");

          // ── Phase 4: Identity resolution + room permission (DB lookups) ──
          // Strategy:
          //   Step 1 — parallel(acct_resolve, room_direct)
          //            acct_resolve is a SINGLE query (account_id only).
          //            Sibling prefetch is DEFERRED to roomFallbackFn (only when direct misses).
          //   Step 2 — persona + room_fallback in parallel (if needed)
          let author_id: string | null = raw_author_id;
          const needsPersonaCheck = !!author_id && author_id !== user_id;
          const needsRoomCheck = !!room_id && room_id !== "global";
          const needsAccountResolution = needsPersonaCheck || needsRoomCheck;

          // Step 1: parallel branches
          let accountId: string | null = null;
          let roomDirectRole: string | null = null;

          // ── KV-cached device→account_id resolver ──
          // Avoids cold Supabase round-trip (~200-534ms) on every post.
          // Key: acct:dev:<device_id> → account_id string or "__null__"
          // TTL: 300s (device→account bindings are stable)
          const ACCT_CACHE_TTL = 300;
          const acctKvKey = `acct:dev:${user_id}`;
          const resolveAccountIdCached = async (): Promise<string | null> => {
            const tDev = Date.now();
            let kvHit = false;
            try {
              const cached = await env.PROFILE_KV.get(acctKvKey);
              if (cached !== null) {
                kvHit = true;
                mark("acct_devices");
                console.log(`[perf] /api/posts acct_devices_ms=${Date.now() - tDev} rid=${request_id} src=kv`);
                return cached === "__null__" ? null : cached;
              }
            } catch { /* KV read failed — fall through to DB */ }

            const { data: deviceBinding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", user_id)
              .maybeSingle();
            mark("acct_devices");
            const acctId = deviceBinding?.account_id
              ? ((deviceBinding as any).account_id as string)
              : null;
            console.log(`[perf] /api/posts acct_devices_ms=${Date.now() - tDev} rid=${request_id} src=db`);

            // Write-behind: cache result for subsequent requests
            ctx.waitUntil(
              env.PROFILE_KV.put(acctKvKey, acctId ?? "__null__", { expirationTtl: ACCT_CACHE_TTL })
                .catch(() => {})
            );
            return acctId;
          };

          if (needsAccountResolution && needsRoomCheck) {
            const [acctResult, { data: directHit }] = await Promise.all([
              // Branch A: resolve account_id (KV-cached)
              resolveAccountIdCached(),
              // Branch B: room direct check (only needs user_id)
              sb(env)
                .from("room_members")
                .select("role")
                .eq("room_id", room_id!)
                .eq("user_id", user_id)
                .maybeSingle(),
            ]);
            mark("acct_resolve");

            accountId = acctResult;
            roomDirectRole = directHit?.role ?? null;

            // ── Teran ID gate: only claimed accounts can post in rooms ──
            if (!accountId && needsRoomCheck) {
              console.warn(`[posts-auth] REJECTED: unclaimed device ${user_id} tried to post in room ${room_id} ua=${(req.headers.get("user-agent")||"").slice(0,60)}`);
              throw new HttpError(403, "TERAN_ID_REQUIRED", "Create a Teran ID to post in rooms");
            }
            if (!accountId && needsPersonaCheck) {
              console.warn(`[posts-auth] REJECTED: unclaimed device ${user_id} tried to post as author_id ${author_id} ua=${(req.headers.get("user-agent")||"").slice(0,60)}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this persona");
            }
          } else if (needsAccountResolution) {
            // Only persona check needed, no room check
            accountId = await resolveAccountIdCached();
            mark("acct_resolve");

            if (!accountId && needsPersonaCheck) {
              console.warn(`[posts-auth] REJECTED: unclaimed device ${user_id} tried to post as author_id ${author_id}`);
              throw new HttpError(403, "TERAN_ID_REQUIRED", "Create a Teran ID to post");
            }
          }

          // Step 2: Persona + room fallback in parallel
          const personaCheckFn = needsPersonaCheck ? async () => {
            const { data: personaBinding } = await sb(env)
              .from("account_personas")
              .select("persona_author_id")
              .eq("account_id", accountId!)
              .eq("persona_author_id", author_id!)
              .maybeSingle();

            if (!personaBinding) {
              console.warn(`[posts-auth] REJECTED: device ${user_id} account ${accountId} does not own persona ${author_id}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this persona");
            }
            mark("persona_check");
          } : null;

          const roomFallbackFn = (needsRoomCheck && !roomDirectRole) ? async () => {
            // Direct missed — fetch siblings NOW (deferred from Step 1)
            if (!accountId) {
              throw new HttpError(403, "FORBIDDEN", "You must be a member to post in this room");
            }

            const tSib = Date.now();
            const { data: allDevices } = await sb(env)
              .from("account_devices")
              .select("device_id")
              .eq("account_id", accountId)
              .neq("device_id", user_id);
            mark("sibling_fetch");
            const siblingFetchMs = Date.now() - tSib;

            const siblingDeviceIds = allDevices
              ? (allDevices as any[]).map((d: any) => d.device_id).filter(Boolean)
              : [];

            if (siblingDeviceIds.length === 0) {
              console.log(`[perf] /api/posts sibling_fetch_ms=${siblingFetchMs} siblings=0 rid=${request_id}`);
              throw new HttpError(403, "FORBIDDEN", "You must be a member to post in this room");
            }

            const { data: siblingHit } = await sb(env)
              .from("room_members")
              .select("role")
              .eq("room_id", room_id!)
              .in("user_id", siblingDeviceIds)
              .limit(1)
              .maybeSingle();
            mark("room_fallback");
            console.log(`[perf] /api/posts sibling_fetch_ms=${siblingFetchMs} siblings=${siblingDeviceIds.length} rid=${request_id}`);

            if (!siblingHit?.role) {
              throw new HttpError(403, "FORBIDDEN", "You must be a member to post in this room");
            }

            // Self-heal: replicate membership for future direct hits
            ctx.waitUntil((async () => {
              try {
                await sb(env)
                  .from("room_members")
                  .upsert({
                    room_id: room_id,
                    user_id: user_id,
                    role: (siblingHit as any).role,
                  } as any, { onConflict: "room_id,user_id" });
              } catch (e: any) {
                console.warn(`[room-selfheal] upsert failed (non-fatal)`, {
                  rid: request_id, room_id, user_id, error: e?.message,
                });
              }
            })());
          } : null;

          // Run Step 2 tasks in parallel
          const step2Tasks: Promise<void>[] = [];
          if (personaCheckFn) step2Tasks.push(personaCheckFn());
          if (roomFallbackFn) step2Tasks.push(roomFallbackFn());
          if (step2Tasks.length > 0) {
            await Promise.all(step2Tasks);
          } else {
            if (!author_id) author_id = user_id;
          }

          mark("auth_done");

          // ── Resolve feed inclusion eligibility ──────────────────────────
          // Only public room posts may opt into the thread feed.
          // Private rooms silently force show_in_feed = false.
          let show_in_feed = false;
          let room_category: string | null = null;

          if (rawShowInFeed && room_id && room_id !== "global") {
            try {
              const { data: roomRow } = await sb(env)
                .from("rooms")
                .select("visibility, category")
                .eq("id", room_id)
                .maybeSingle();
              if (roomRow && roomRow.visibility === "public" && roomRow.category) {
                show_in_feed = true;
                room_category = roomRow.category;
              }
              // else: private room, missing room, or missing category → stay false
            } catch (e: any) {
              // Fail closed: if room lookup fails, do not allow feed inclusion
              console.warn(`[posts] feed_eligibility lookup failed (non-fatal)`, {
                rid: request_id, room_id, error: e?.message,
              });
            }
          }
          console.log(`[ROOM_FEED_DEBUG][ROOM_ELIGIBILITY]`, { rid: request_id, room_id, rawShowInFeed, show_in_feed, room_category, entered_lookup: !!(rawShowInFeed && room_id && room_id !== "global") });
          mark("feed_eligibility");

          // ── Resolve root_post_id before insert ──
          let root_post_id: number | null = null;
          if (parent_post_id) {
            const { data: parentRow, error: parentErr } = await sb(env)
              .from("posts")
              .select("id, root_post_id")
              .eq("id", parent_post_id)
              .single();
            if (parentErr) {
              console.error(`[posts][${request_id}] failed to fetch parent for root_post_id`, { parent_post_id, error: parentErr });
            }
            if (parentRow) {
              root_post_id = parentRow.root_post_id ?? parentRow.id;
            }
          }

          // Narrow select on insert: only return columns needed for response + post-insert logic
          const POST_RETURN_COLS = "id, user_id, content, title, author_id, author_name, author_avatar, room_id, parent_post_id, root_post_id, post_type, shared_post_id, mode, moods, created_at";
          let data: any;
          console.log(`[ROOM_FEED_DEBUG][POST_INSERT]`, { rid: request_id, room_id, show_in_feed, room_category, post_type, parent_post_id, has_title: !!(title && title.trim()) });
          try {
            const insertResult = await sb(env)
              .from("posts")
              .insert({
                user_id,
                content,
                title,
                author_id,
                author_name,
                author_avatar,
                room_id,
                parent_post_id,
                root_post_id,
                post_type,
                shared_post_id,
                mode,
                moods,
                show_in_feed,
                room_category,
              })
              .select(POST_RETURN_COLS)
              .single();
            if (insertResult.error) throw insertResult.error;
            data = insertResult.data;
          } catch (dbErr: any) {
            // Translate DB constraint / validation errors to 400
            const msg = dbErr?.message || String(dbErr);
            const isConstraint = /check|not-null|violat|invalid input|bad input/i.test(msg);
            if (isConstraint) {
              console.warn(`[posts][${request_id}] DB constraint error`, { message: msg, mode, post_type });
              throw new HttpError(400, "bad_request", "Invalid post payload");
            }
            throw dbErr; // truly unexpected → 500
          }

          // ── Case A: root post → set root_post_id = own id (fire-and-forget) ──
          if (!parent_post_id && data.id) {
            data.root_post_id = data.id;
            ctx.waitUntil(
              Promise.resolve(
                sb(env)
                  .from("posts")
                  .update({ root_post_id: data.id } as any)
                  .eq("id", data.id)
              ).catch((e: any) => console.warn(`[posts] root_post_id self-update failed`, { rid: request_id, id: data.id, error: e?.message }))
            );
          }
          mark("post_insert_done");

          // Insert media rows into unified 'media' table
          let mediaRows: any[] = [];
          if (validatedMedia.length > 0) {
            const postId = data.id;
            const mediaInsert = validatedMedia.map((m) => ({
              post_id: postId,
              type: m.type,
              key: m.key,
              thumb_key: m.thumb_key,
              width: m.width ?? null,
              height: m.height ?? null,
              bytes: m.bytes ?? null,
              duration_ms: m.duration_ms ?? null,
            }));
            const { data: insertedMedia, error: mediaError } = await sb(env)
              .from("media")
              .insert(mediaInsert)
              .select("*");
            if (mediaError) throw mediaError;
            mediaRows = insertedMedia ?? [];
            mark("media_insert_done");
          }

          // Create notification for replies (if this is a reply to another post)
          if (parent_post_id) {
            // Fetch the parent post owner's user_id (NOT author_id/persona)
            const { data: parentPost, error: parentFetchError } = await sb(env)
              .from("posts")
              .select("user_id, author_id, room_id")
              // room_id used for notification room meta
              .eq("id", parent_post_id)
              .single();

            if (parentFetchError) {
              console.error(`[notif][${request_id}] failed to fetch parent post owner`, { parent_post_id, error: parentFetchError });
            }

            mark("notif_prepare_done");

            // Use user_id (JWT sub) for notification recipient, NOT author_id (persona)
            if (parentPost?.user_id && parentPost.user_id !== user_id) {
              console.log(`[notif] creating post_reply`, {
                request_id,
                parent_post_id,
                actor_user_id: user_id,
                recipient_user_id: parentPost.user_id,
                actor_persona_id: author_id,
                parent_author_id: parentPost.author_id,
              });
              const replyRoomId = (parentPost as any).room_id ?? room_id ?? null;
              const replyRoomMeta = await resolveRoomMeta(env, replyRoomId);
              await createNotification(env, {
                recipient_user_id: parentPost.user_id,  // JWT sub of parent post owner
                actor_user_id: user_id,                  // JWT sub of replier
                actor_name: author_name,
                actor_avatar: author_avatar,
                type: "post_reply",
                post_id: parent_post_id, // Link to parent so notification opens the thread
                root_post_id: root_post_id ?? parent_post_id, // Always point to root for navigation
                ...replyRoomMeta,
                group_key: `post_reply:${parent_post_id}`,
              }, request_id);
              mark("notif_insert_done");
            } else if (!parentPost?.user_id) {
              console.warn(`[notif][${request_id}] parent post user_id not found, skipping notification`, { parent_post_id });
            } else {
              console.log(`[notif][${request_id}] skipping self-reply`, { parent_post_id, user_id });
            }
          }

          mark("handler_done");
          const ms = (k: string) => marks[k] ? +((marks[k] - t0).toFixed(1)) : null;
          const delta = (a: string, b: string) => (marks[a] && marks[b]) ? +((marks[a] - marks[b]).toFixed(1)) : null;
          logPerf("/api/posts", {
            rid: request_id,
            post_type,
            parent_post_id: parent_post_id ?? null,
            jwt_ms: ms("jwt"),
            json_parse_ms: delta("json_parse", "jwt"),
            validation_ms: delta("validation", "json_parse"),
            acct_devices_ms: delta("acct_devices", "validation"),
            acct_resolve_ms: delta("acct_resolve", "validation"),
            persona_check_ms: delta("persona_check", "acct_resolve") ?? delta("persona_check", "validation"),
            sibling_fetch_ms: delta("sibling_fetch", "acct_resolve"),
            room_fallback_ms: delta("room_fallback", "acct_resolve"),
            auth_total_ms: ms("auth_done"),
            post_insert_ms: delta("post_insert_done", "auth_done"),
            media_insert_ms: delta("media_insert_done", "post_insert_done"),
            notif_prepare_ms: delta("notif_prepare_done", "media_insert_done") ?? delta("notif_prepare_done", "post_insert_done"),
            notif_insert_ms: delta("notif_insert_done", "notif_prepare_done"),
            total_ms: ms("handler_done"),
          });

          return ok(req, env, request_id, { post: { ...data, media: mediaRows } }, 201);
        }

        // /api/posts/:id (DELETE) — cascade soft-delete
        {
          const m = path.match(/^\/api\/posts\/(\d+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const postId = Number(m[1]);

            // First check if the post exists and belongs to the user
            const { data: existingPost, error: fetchError } = await sb(env)
              .from("posts")
              .select("id, user_id, root_post_id")
              .eq("id", postId)
              .is("deleted_at", null)
              .single();

            if (fetchError || !existingPost) {
              throw new HttpError(404, "NOT_FOUND", "Post not found");
            }

            if (existingPost.user_id !== user_id) {
              throw new HttpError(403, "FORBIDDEN", "You can only delete your own posts");
            }

            const now = new Date().toISOString();

            // Soft-delete the post itself
            const { error: selfErr } = await sb(env)
              .from("posts")
              .update({ deleted_at: now })
              .eq("id", postId);
            if (selfErr) throw selfErr;

            // Cascade: if this is a root post, soft-delete all descendants too
            const isRoot = !existingPost.root_post_id || existingPost.root_post_id === postId;
            if (isRoot) {
              const { error: cascadeErr, count } = await sb(env)
                .from("posts")
                .update({ deleted_at: now })
                .eq("root_post_id", postId)
                .is("deleted_at", null);
              console.log(`[DELETE post] cascade soft-delete root=${postId} children_marked=${count ?? "unknown"}`, cascadeErr ?? "ok");
            }

            console.log(`[DELETE post] soft-deleted id=${postId} isRoot=${isRoot}`);
            return ok(req, env, request_id, { ok: true }, 200);
          }
        }

        // /api/comments/:id (DELETE)
        {
          const m = path.match(/^\/api\/comments\/(\d+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const commentId = Number(m[1]);

            // First check if the comment exists and belongs to the user
            const { data: existingComment, error: fetchError } = await sb(env)
              .from("comments")
              .select("id, user_id")
              .eq("id", commentId)
              .single();

            if (fetchError || !existingComment) {
              throw new HttpError(404, "NOT_FOUND", "Comment not found");
            }

            if (existingComment.user_id !== user_id) {
              throw new HttpError(403, "FORBIDDEN", "You can only delete your own comments");
            }

            // Fetch related media rows BEFORE deleting the comment
            const { data: mediaRows } = await sb(env)
              .from("media")
              .select("key, thumb_key")
              .eq("comment_id", commentId);

            console.log("[DELETE comment] id=", commentId, "mediaCount=", (mediaRows ?? []).length);

            // Delete R2 objects (key + thumb_key) for each media row
            for (const row of mediaRows ?? []) {
              if (row.key) {
                try {
                  await env.R2_MEDIA.delete(row.key);
                } catch (e) {
                  console.warn("[DELETE comment] R2 delete failed for key=", row.key, e);
                }
              }
              if (row.thumb_key) {
                try {
                  await env.R2_MEDIA.delete(row.thumb_key);
                } catch (e) {
                  console.warn("[DELETE comment] R2 delete failed for thumb_key=", row.thumb_key, e);
                }
              }
            }

            // Delete the comment (cascade deletes media rows in DB)
            const { error } = await sb(env)
              .from("comments")
              .delete()
              .eq("id", commentId);
            if (error) throw error;

            return new Response(null, { status: 204, headers: corsHeaders(req, env) });
          }
        }

        // GET /api/comments/counts?post_ids=1,2,3 - Get comment counts for multiple posts (public)
        if (path === "/api/comments/counts" && req.method === "GET") {
          const t0 = Date.now();
          const postIdsParam = url.searchParams.get("post_ids") || "";
          const postIds = postIdsParam
            .split(",")
            .map(s => parseInt(s.trim(), 10))
            .filter(n => Number.isFinite(n) && n > 0)
            .slice(0, 200); // Limit to 200

          if (postIds.length === 0) {
            return ok(req, env, request_id, { counts: {} });
          }

          // Count actual comments from the comments table (not reply-posts from posts table)
          const tDb = Date.now();
          const { data: countRows, error } = await sb(env)
            .from("comments")
            .select("post_id")
            .in("post_id", postIds);
          const dbMs = Date.now() - tDb;
          if (error) throw error;

          // Build response — tally rows by post_id
          const counts: Record<string, number> = {};
          for (const id of postIds) {
            counts[String(id)] = 0;
          }
          for (const row of countRows ?? []) {
            const key = String((row as any).post_id);
            counts[key] = (counts[key] || 0) + 1;
          }

          const totalMs = Date.now() - t0;
          console.log(`[perf] /api/comments/counts`, JSON.stringify({ rid: request_id, db_ms: dbMs, total_ms: totalMs, post_ids: postIds.length }));

          return ok(req, env, request_id, { counts });
        }

        // GET /api/comments/preview?post_ids=1,2,3&per_post=1 (Cache API, 60s TTL)
        // Returns minimal fields: id, post_id, content, author_name, author_avatar, created_at
        // No media, no liked_by_me, no heavy joins
        if (path === "/api/comments/preview" && req.method === "GET") {
          const PREVIEW_CACHE_TTL = 60; // seconds
          const t0 = Date.now();
          const rid = request_id;
          let idsCount = 0;
          let perPostUsed = 1;
          try {
            const postIdsParam = url.searchParams.get("post_ids") || "";
            const perPostParam = url.searchParams.get("per_post");
            const perPost = Math.min(3, Math.max(1, parseInt(perPostParam || "1", 10) || 1));
            perPostUsed = perPost;

            const postIds = postIdsParam
              .split(",")
              .map(s => parseInt(s.trim(), 10))
              .filter(n => Number.isFinite(n) && n > 0)
              .slice(0, 100);
            idsCount = postIds.length;

            if (postIds.length === 0) {
              console.log(`[perf] comments/preview rid=${rid} cache=SKIP total=${Date.now() - t0}ms ids=0 per_post=${perPostUsed} error=0`);
              return ok(req, env, request_id, { previews: {} });
            }

            // Stable cache key: sorted IDs + per_post
            const sortedKey = [...postIds].sort((a, b) => a - b).join(",");
            const cacheKeyUrl = new URL("https://cache.internal/comments/preview");
            cacheKeyUrl.searchParams.set("ids", sortedKey);
            cacheKeyUrl.searchParams.set("per_post", String(perPost));
            const cacheKey = new Request(cacheKeyUrl.toString(), { method: "GET" });
            const cache = caches.default;
            const cached = await cache.match(cacheKey);
            const tCache = Date.now();

            if (cached) {
              const hitBody = await cached.text();
              console.log(`[perf] comments/preview rid=${rid} cache=HIT total=${Date.now() - t0}ms ids=${idsCount} per_post=${perPostUsed} payloadBytes=${hitBody.length}`);
              return new Response(hitBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "HIT",
                  ...corsHeaders(req, env),
                },
              });
            }

            // Cache MISS — query DB
            const fetchLimit = postIds.length * perPost * 3;
            const tDb0 = Date.now();
            const { data: rows, error } = await sb(env)
              .from("comments")
              .select("id, post_id, content, author_name, author_avatar, created_at")
              .in("post_id", postIds)
              .order("created_at", { ascending: false })
              .limit(fetchLimit);
            const tDb1 = Date.now();
            if (error) throw error;

            // Group by post_id and keep only perPost per group
            const previews: Record<string, Array<{
              id: number;
              content: string;
              author_name: string | null;
              author_avatar: string | null;
              created_at: string;
            }>> = {};
            for (const id of postIds) {
              previews[String(id)] = [];
            }
            for (const row of rows ?? []) {
              const key = String(row.post_id);
              if (previews[key] && previews[key].length < perPost) {
                previews[key].push({
                  id: row.id,
                  content: row.content,
                  author_name: row.author_name,
                  author_avatar: row.author_avatar,
                  created_at: row.created_at,
                });
              }
            }
            const tEnd = Date.now();

            const responseBody = { previews, request_id };
            const body = JSON.stringify(responseBody);

            // Store in edge cache
            ctx.waitUntil(
              cache.put(cacheKey, new Response(body, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": `public, max-age=${PREVIEW_CACHE_TTL}`,
                },
              }))
                .then(() => console.log(`[cache] comments/preview put ok rid=${rid} ids=${idsCount}`))
                .catch((err) => console.error(`[cache] comments/preview put fail rid=${rid}`, err))
            );

            console.log(`[perf] comments/preview rid=${rid} cache=MISS cacheCheck=${tCache - t0}ms db=${tDb1 - tDb0}ms transform=${tEnd - tDb1}ms total=${tEnd - t0}ms payloadBytes=${body.length} ids=${idsCount} per_post=${perPostUsed} rows=${(rows ?? []).length} error=0`);
            return new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "MISS",
                ...corsHeaders(req, env),
              },
            });
          } catch (err: any) {
            console.log(`[perf] comments/preview rid=${rid} total=${Date.now() - t0}ms ids=${idsCount} per_post=${perPostUsed} error=1 msg=${err?.message?.slice(0, 100)}`);
            throw err;
          }
        }

        // GET /api/posts/reply-previews?parent_ids=1,2,3&per_post=2
        // Returns lightweight post-based reply previews for room thread cards.
        // Unlike /api/comments/preview (which queries the comments table),
        // this queries the posts table where parent_post_id IN (parent_ids).
        if (path === "/api/posts/reply-previews" && req.method === "GET") {
          const PREVIEW_CACHE_TTL = 60;
          const t0 = Date.now();
          const rid = request_id;

          const parentIdsParam = url.searchParams.get("parent_ids") || "";
          const perPostParam = url.searchParams.get("per_post");
          const perPost = Math.min(3, Math.max(1, parseInt(perPostParam || "2", 10) || 2));

          const parentIds = parentIdsParam
            .split(",")
            .map(s => parseInt(s.trim(), 10))
            .filter(n => Number.isFinite(n) && n > 0)
            .slice(0, 100);

          if (parentIds.length === 0) {
            return ok(req, env, request_id, { previews: {} });
          }

          // Stable cache key
          const sortedKey = [...parentIds].sort((a, b) => a - b).join(",");
          const cacheKeyUrl = new URL("https://cache.internal/posts/reply-previews");
          cacheKeyUrl.searchParams.set("ids", sortedKey);
          cacheKeyUrl.searchParams.set("per_post", String(perPost));
          const cacheKey = new Request(cacheKeyUrl.toString(), { method: "GET" });
          const cache = caches.default;
          const cached = await cache.match(cacheKey);

          if (cached) {
            const hitBody = await cached.text();
            console.log(`[perf] posts/reply-previews rid=${rid} cache=HIT total=${Date.now() - t0}ms ids=${parentIds.length}`);
            return new Response(hitBody, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "HIT",
                ...corsHeaders(req, env),
              },
            });
          }

          // Cache MISS — query posts table for child replies
          const fetchLimit = parentIds.length * perPost * 3;
          const tDb0 = Date.now();
          const { data: rows, error } = await sb(env)
            .from("posts")
            .select("id, parent_post_id, content, author_name, author_avatar, created_at")
            .in("parent_post_id", parentIds)
            .is("deleted_at", null)
            .order("created_at", { ascending: false })
            .limit(fetchLimit);
          const tDb1 = Date.now();
          if (error) throw error;

          // Group by parent_post_id, keep only perPost per group
          const previews: Record<string, Array<{
            id: number;
            parent_post_id: number;
            content: string;
            author_name: string | null;
            author_avatar: string | null;
            created_at: string;
          }>> = {};
          for (const id of parentIds) {
            previews[String(id)] = [];
          }
          for (const row of rows ?? []) {
            const key = String(row.parent_post_id);
            if (previews[key] && previews[key].length < perPost) {
              previews[key].push({
                id: row.id,
                parent_post_id: row.parent_post_id,
                content: row.content,
                author_name: row.author_name,
                author_avatar: row.author_avatar,
                created_at: row.created_at,
              });
            }
          }

          const responseBody = { previews, request_id };
          const body = JSON.stringify(responseBody);

          // Store in edge cache
          ctx.waitUntil(
            cache.put(cacheKey, new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "Cache-Control": `public, max-age=${PREVIEW_CACHE_TTL}`,
              },
            }))
              .then(() => console.log(`[cache] posts/reply-previews put ok rid=${rid} ids=${parentIds.length}`))
              .catch((err) => console.error(`[cache] posts/reply-previews put fail rid=${rid}`, err))
          );

          console.log(`[perf] posts/reply-previews rid=${rid} cache=MISS db=${tDb1 - tDb0}ms total=${Date.now() - t0}ms ids=${parentIds.length} per_post=${perPost} rows=${(rows ?? []).length}`);
          return new Response(body, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Request-Id": request_id,
              "X-Cache": "MISS",
              ...corsHeaders(req, env),
            },
          });
        }

        // /api/comments (GET) ?post_id=123 (REQUIRED) &limit=20&cursor=<ts>:<id>
        // Returns { items: [...], next_cursor: string|null }
        if (path === "/api/comments" && req.method === "GET") {
          const handlerStart = Date.now();
          const post_id_param = url.searchParams.get("post_id");

          // Require post_id to prevent expensive global queries
          if (!post_id_param) {
            throw new HttpError(400, "BAD_REQUEST", "post_id is required");
          }
          const post_id = Number(post_id_param);
          if (!Number.isFinite(post_id) || post_id <= 0) {
            throw new HttpError(400, "BAD_REQUEST", "post_id must be a valid positive integer");
          }

          // Pagination params
          const limit = clampPaginationLimit(url.searchParams.get("limit"), 20, 200);
          const cursor = parseCursor(url.searchParams.get("cursor"));

          // Try to get current user (optional auth for liked_by_me)
          let current_user_id: string | null = null;
          try {
            const auth = req.headers.get("Authorization") || "";
            const m = auth.match(/^Bearer\s+(.+)$/i);
            if (m) {
              const payload = await jwtVerify(env, m[1]);
              if (payload?.sub) current_user_id = payload.sub;
            }
          } catch { /* ignore auth errors for GET */ }

          // Query 1: Fetch comments (select only needed fields) with keyset pagination
          const tSelect = Date.now();
          let commentsQuery = sb(env)
            .from("comments")
            .select("id, post_id, user_id, content, parent_comment_id, author_id, author_name, author_avatar, created_at")
            .eq("post_id", post_id);
          if (cursor) {
            commentsQuery = commentsQuery.or(
              `created_at.gt.${cursor.created_at},and(created_at.eq.${cursor.created_at},id.gt.${cursor.id})`
            );
          }
          const { data: comments, error } = await commentsQuery
            .order("created_at", { ascending: true })
            .order("id", { ascending: true })
            .limit(limit);
          const selectMs = Date.now() - tSelect;
          if (error) throw error;

          const commentList = comments ?? [];
          if (commentList.length === 0) {
            const totalMs = Date.now() - handlerStart;
            console.log(`[perf] /api/comments`, JSON.stringify({ rid: request_id, select_ms: selectMs, rows: 0, total_ms: totalMs, empty: true }));
            return ok(req, env, request_id, { items: [], next_cursor: null });
          }

          const commentIds = commentList.map((c: any) => c.id);

          // Profile overlay: KV-cached first, DB fallback only for misses
          const tProf = Date.now();
          const commentAuthorIds = [...new Set(commentList.map((c: any) => c.author_id).filter(Boolean))];
          let commentProfileMap: Record<string, { display_name?: string; avatar?: string }> = {};
          const kvMissIds: string[] = [];
          let profKvHits = 0;
          for (const authorId of commentAuthorIds) {
            try {
              const kvRaw = await env.PROFILE_KV.get(`profile:${authorId}`, "text");
              if (kvRaw) {
                const parsed = JSON.parse(kvRaw);
                commentProfileMap[authorId] = { display_name: parsed.display_name, avatar: parsed.avatar };
                profKvHits++;
              } else {
                kvMissIds.push(authorId);
              }
            } catch {
              kvMissIds.push(authorId);
            }
          }
          const profKvMs = Date.now() - tProf;

          // Queries 2-4(5): Run enrichment in parallel (likes, user likes, media, + profile DB fallback)
          const tParallel = Date.now();
          const parallelQueries: PromiseLike<any>[] = [
            // Query 2: Get like counts for all comments
            sb(env)
              .from("comment_likes")
              .select("comment_id")
              .in("comment_id", commentIds),
            // Query 3: Get liked_by_me for current user (skip if no auth)
            current_user_id
              ? sb(env)
                .from("comment_likes")
                .select("comment_id")
                .in("comment_id", commentIds)
                .eq("user_id", current_user_id)
              : Promise.resolve({ data: [] }),
            // Query 4: Fetch media for all comments
            sb(env)
              .from("media")
              .select("id, comment_id, type, key, thumb_key, width, height")
              .in("comment_id", commentIds),
          ];
          // Query 5 (conditional): profile DB fallback only for KV misses
          if (kvMissIds.length > 0) {
            parallelQueries.push(
              sb(env)
                .from("user_profiles")
                .select("user_id, display_name, avatar")
                .in("user_id", kvMissIds)
            );
          }
          const results = await Promise.all(parallelQueries);
          const parallelMs = Date.now() - tParallel;
          const dbQueries = parallelQueries.length;

          const likesResult = results[0];
          const userLikesResult = results[1];
          const mediaResult = results[2];

          // Merge profile DB fallback results
          if (results.length > 3 && results[3]?.data) {
            for (const row of results[3].data as any[]) {
              commentProfileMap[row.user_id] = { display_name: row.display_name, avatar: row.avatar };
            }
          }

          // Aggregate like counts
          const tTransform = Date.now();
          const likeCounts: Record<number, number> = {};
          for (const like of likesResult.data ?? []) {
            likeCounts[like.comment_id] = (likeCounts[like.comment_id] || 0) + 1;
          }

          // Set of liked comment IDs for current user
          const likedByMe: Set<number> = new Set();
          for (const like of userLikesResult.data ?? []) {
            likedByMe.add(like.comment_id);
          }

          // Map media by comment
          const mediaByComment: Record<number, any[]> = {};
          for (const m of mediaResult.data ?? []) {
            if (!mediaByComment[m.comment_id]) mediaByComment[m.comment_id] = [];
            mediaByComment[m.comment_id].push(m);
          }

          // Enrich comments with like data, media, and live identity overlay
          const enrichedComments = commentList.map((c: any) => {
            const prof = commentProfileMap[c.author_id];
            return {
              ...c,
              author_name: prof?.display_name || c.author_name,
              author_avatar: prof?.avatar || c.author_avatar,
              like_count: likeCounts[c.id] || 0,
              liked_by_me: likedByMe.has(c.id),
              media: mediaByComment[c.id] || [],
            };
          });
          const transformMs = Date.now() - tTransform;

          const next_cursor = buildNextCursor(commentList, limit);
          const totalMs = Date.now() - handlerStart;
          console.log(`[perf] /api/comments`, JSON.stringify({ rid: request_id, select_ms: selectMs, prof_kv_ms: profKvMs, prof_kv_hits: profKvHits, prof_kv_misses: kvMissIds.length, parallel_ms: parallelMs, db_queries: dbQueries, transform_ms: transformMs, rows: commentList.length, total_ms: totalMs }));
          return ok(req, env, request_id, { items: enrichedComments, next_cursor });
        }

        // /api/comments (POST) -> { post_id, content, author_id, author_name, author_avatar, media? }
        if (path === "/api/comments" && req.method === "POST") {
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const post_id = Number(body?.post_id);
          const content = typeof body?.content === "string" ? body.content.trim() : "";
          const parent_comment_id =
            typeof body?.parent_comment_id === "number" ? body.parent_comment_id : null;

          // Parse media first so we can validate content OR media requirement
          const mediaInput = Array.isArray(body?.media) ? body.media : [];

          if (!post_id) {
            throw new HttpError(422, "VALIDATION_ERROR", "post_id required");
          }

          // Require either content OR media
          if (!content && mediaInput.length === 0) {
            throw new HttpError(400, "BAD_REQUEST", "Comment must have text or media");
          }

          // ── Text length limit (must match frontend LIMITS.COMMENT) ──
          const LIMIT_COMMENT = 600;
          if (content.length > LIMIT_COMMENT) {
            throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_COMMENT} characters`);
          }

          // Parse optional author fields from request (display only)
          // author_id is always set to user_id from auth (canonical account id)
          const author_id = user_id;
          const author_name = typeof body?.author_name === "string" ? body.author_name : null;
          const rawAuthorAvatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;
          // Reject data URIs to prevent storing MB-sized base64 in DB
          if (rawAuthorAvatar && rawAuthorAvatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "author_avatar must be a URL, not a data URI");
          }
          const author_avatar = rawAuthorAvatar;

          // Validate media array (same limits as posts for images)
          const MAX_COMMENT_IMAGES = 4;

          const validatedMedia: Array<{
            type: "image" | "video";
            key: string;
            thumb_key?: string | null;
            width?: number | null;
            height?: number | null;
            bytes?: number | null;
          }> = [];

          let imageCount = 0;
          for (const m of mediaInput) {
            const mType = m?.type;
            const mKey = m?.key;
            const mThumbKey = m?.thumb_key;

            if (!mType || !mKey || typeof mKey !== "string" || !mKey.trim()) {
              throw new HttpError(422, "VALIDATION_ERROR", "Each media item must have type and key");
            }

            if (mType === "image") {
              imageCount++;
              if (imageCount > MAX_COMMENT_IMAGES) {
                throw new HttpError(422, "VALIDATION_ERROR", `Maximum ${MAX_COMMENT_IMAGES} images allowed per comment`);
              }
              // Require thumb_key for images, key should start with "image/" or "image_original/"
              if (!mThumbKey || typeof mThumbKey !== "string" || !mThumbKey.trim()) {
                throw new HttpError(422, "VALIDATION_ERROR", "thumb_key is required for images");
              }
              // Accept both legacy "image/" prefix and new "image_original/" prefix
              const validImagePrefixes = ["image/", "image_original/"];
              if (!validImagePrefixes.some(prefix => mKey.startsWith(prefix))) {
                throw new HttpError(422, "VALIDATION_ERROR", "Image key must start with 'image/' or 'image_original/'");
              }
              // Also validate thumb_key accepts "image_thumb/" prefix
              const validThumbPrefixes = ["image/", "image_thumb/", "thumb/"];
              if (!validThumbPrefixes.some(prefix => mThumbKey.startsWith(prefix))) {
                throw new HttpError(422, "VALIDATION_ERROR", "Image thumb_key must start with 'image/', 'image_thumb/', or 'thumb/'");
              }
              validatedMedia.push({
                type: "image",
                key: mKey.trim(),
                thumb_key: mThumbKey.trim(),
                width: typeof m?.width === "number" ? m.width : null,
                height: typeof m?.height === "number" ? m.height : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
              });
            } else if (mType === "video") {
              // Video support in comments - validate key starts with "video/"
              if (!mKey.startsWith("video/")) {
                throw new HttpError(422, "VALIDATION_ERROR", "Video key must start with 'video/'");
              }
              // Optional poster_key for video thumbnails
              const posterKey = m?.poster_key;
              let validatedPosterKey: string | null = null;
              if (posterKey && typeof posterKey === "string" && posterKey.trim()) {
                if (!posterKey.startsWith("thumb/") && !posterKey.startsWith("image/")) {
                  throw new HttpError(422, "VALIDATION_ERROR", "poster_key must start with 'thumb/' or 'image/'");
                }
                validatedPosterKey = posterKey.trim();
              }
              validatedMedia.push({
                type: "video",
                key: mKey.trim(),
                thumb_key: validatedPosterKey, // Store poster_key in thumb_key field for videos
                width: typeof m?.width === "number" ? m.width : null,
                height: typeof m?.height === "number" ? m.height : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
              });
            } else {
              throw new HttpError(422, "VALIDATION_ERROR", "Media type must be 'image' or 'video'");
            }
          }

          // ── Room membership gate ──────────────────────────────────────
          // If the parent post belongs to a room (non-global), only room
          // members may create comments. Global / non-room posts pass through.
          {
            const { data: parentPost } = await sb(env)
              .from("posts")
              .select("room_id")
              .eq("id", post_id)
              .maybeSingle();
            if (!parentPost) {
              throw new HttpError(404, "NOT_FOUND", "Parent post not found");
            }
            const roomId = parentPost.room_id;
            if (roomId && roomId !== "global") {
              const memberRole = await checkRoomMembership(env, roomId, user_id);
              if (!memberRole) {
                throw new HttpError(403, "ROOM_MEMBERSHIP_REQUIRED", "You must be a member of this room to comment");
              }
            }
          }

          const { data, error } = await sb(env)
            .from("comments")
            .insert({
              post_id, user_id, content, parent_comment_id,
              author_id, author_name, author_avatar,
            })
            .select("*")
            .single();
          if (error) throw error;

          // Insert media rows for the comment
          let mediaRows: any[] = [];
          if (validatedMedia.length > 0) {
            const commentId = data.id;
            const mediaInsert = validatedMedia.map((m) => ({
              comment_id: commentId,
              post_id: null, // null because this is comment media, not post media
              type: m.type,
              key: m.key,
              thumb_key: m.thumb_key,
              width: m.width ?? null,
              height: m.height ?? null,
              bytes: m.bytes ?? null,
            }));
            const { data: insertedMedia, error: mediaError } = await sb(env)
              .from("media")
              .insert(mediaInsert)
              .select("*");
            if (mediaError) throw mediaError;
            mediaRows = insertedMedia ?? [];
          }

          // Create notification for comment
          if (parent_comment_id == null) {
            // Top-level comment on a post -> notify post owner
            const { data: postData } = await sb(env)
              .from("posts")
              .select("user_id, room_id")
              .eq("id", post_id)
              .single();
            if (postData) {
              const pcRoomMeta = await resolveRoomMeta(env, (postData as any).room_id);
              await createNotification(env, {
                recipient_user_id: postData.user_id,
                actor_user_id: user_id,
                actor_name: author_name,
                actor_avatar: author_avatar,
                type: "post_comment",
                post_id,
                comment_id: data.id,
                ...pcRoomMeta,
                group_key: `pc:${post_id}`,
              }, request_id);
            }
          } else {
            // Reply to a comment -> notify parent comment owner
            const { data: parentComment } = await sb(env)
              .from("comments")
              .select("user_id, post_id")
              .eq("id", parent_comment_id)
              .single();
            // Resolve room from parent comment's post
            let replyCommentRoomMeta = { room_id: null as string | null, room_icon_key: null as string | null, room_emoji: null as string | null };
            if (parentComment) {
              const { data: replyPostData } = await sb(env).from("posts").select("room_id").eq("id", (parentComment as any).post_id).single();
              replyCommentRoomMeta = await resolveRoomMeta(env, (replyPostData as any)?.room_id);
            }
            if (parentComment) {
              await createNotification(env, {
                recipient_user_id: parentComment.user_id,
                actor_user_id: user_id,
                actor_name: author_name,
                actor_avatar: author_avatar,
                type: "reply",
                post_id: parentComment.post_id,
                comment_id: data.id,
                parent_comment_id,
                ...replyCommentRoomMeta,
                group_key: `rp:${parent_comment_id}`,
              }, request_id);
            }
          }

          // Update post's last_activity_at timestamp (bump on new comment)
          await sb(env)
            .from("posts")
            .update({ last_activity_at: new Date().toISOString() })
            .eq("id", post_id);

          return ok(req, env, request_id, { comment: { ...data, media: mediaRows } }, 201);
        }

        // /api/comments/:id/like (POST = like, DELETE = unlike) - IDEMPOTENT
        {
          const m = path.match(/^\/api\/comments\/(\d+)\/like$/);
          if (m) {
            const handlerStart = Date.now();
            const comment_id = Number(m[1]);
            const user_id = await requireAuth(req, env);

            if (!Number.isFinite(comment_id)) {
              throw new HttpError(400, "BAD_REQUEST", "invalid comment_id");
            }

            // POST = ensure liked (idempotent)
            if (req.method === "POST") {
              // Parse optional actor fields from request body
              const body = (await req.json().catch(() => ({}))) as any;
              const actor_name = typeof body?.actor_name === "string" ? body.actor_name : null;
              const actor_avatar = typeof body?.actor_avatar === "string" ? body.actor_avatar : null;

              // Single upsert - no-op if already liked (ignoreDuplicates)
              let t1 = Date.now();
              const { data, error: insertError } = await sb(env)
                .from("comment_likes")
                .upsert(
                  { comment_id, user_id },
                  { onConflict: "user_id,comment_id", ignoreDuplicates: true }
                )
                .select("comment_id");
              const wasInserted = (data?.length ?? 0) > 0;
              console.log(`[perf] /api/comments/:id/like POST upsert ${Date.now() - t1}ms`, { comment_id, wasInserted });

              if (insertError) throw insertError;

              // Only create notification if this was a new like (not already liked)
              if (wasInserted) {
                t1 = Date.now();
                const { data: commentData } = await sb(env)
                  .from("comments")
                  .select("user_id, post_id, parent_comment_id")
                  .eq("id", comment_id)
                  .single();
                if (commentData) {
                  // Resolve room from liked comment's post
                  const { data: clPostData } = await sb(env).from("posts").select("room_id").eq("id", (commentData as any).post_id).single();
                  const clRoomMeta = await resolveRoomMeta(env, (clPostData as any)?.room_id);
                  await createNotification(env, {
                    recipient_user_id: commentData.user_id,
                    actor_user_id: user_id,
                    actor_name,
                    actor_avatar,
                    type: "comment_like",
                    post_id: commentData.post_id,
                    comment_id,
                    parent_comment_id: commentData.parent_comment_id,
                    ...clRoomMeta,
                    group_key: `cl:${comment_id}`,
                  }, request_id);
                }
                console.log(`[perf] /api/comments/:id/like POST notification ${Date.now() - t1}ms`);
              }

              console.log(`[perf] /api/comments/:id/like POST total ${Date.now() - handlerStart}ms`, { comment_id });
              return ok(req, env, request_id, { liked: true }, wasInserted ? 201 : 200);
            }

            // DELETE = ensure unliked (idempotent)
            if (req.method === "DELETE") {
              const t1 = Date.now();
              const { error } = await sb(env)
                .from("comment_likes")
                .delete()
                .eq("comment_id", comment_id)
                .eq("user_id", user_id);
              console.log(`[perf] /api/comments/:id/like DELETE ${Date.now() - t1}ms`, { comment_id });
              if (error) throw error;

              console.log(`[perf] /api/comments/:id/like DELETE total ${Date.now() - handlerStart}ms`, { comment_id });
              return ok(req, env, request_id, { liked: false });
            }

            throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
          }
        }

        // /api/posts/:id/like (POST = like, DELETE = unlike) - IDEMPOTENT, actor-based
        {
          const m = path.match(/^\/api\/posts\/(\d+)\/like$/);
          if (m) {
            const handlerStart = Date.now();
            const post_id = Number(m[1]);

            if (!Number.isFinite(post_id)) {
              throw new HttpError(400, "BAD_REQUEST", "invalid post_id");
            }

            // POST = ensure liked (idempotent)
            if (req.method === "POST") {
              // Get JWT user_id for notifications
              const jwt_user_id = await requireAuth(req, env);

              // Parse actor fields from request body (for post_likes table and UI display)
              // SECURITY: actor_id from body is untrusted — must verify the caller
              // owns this persona before allowing them to like as it.
              const body = (await req.json().catch(() => ({}))) as any;
              const raw_actor_id = typeof body?.actor_id === "string" ? body.actor_id.trim() : null;
              const actor_name = typeof body?.actor_name === "string" ? body.actor_name : null;
              const actor_avatar = typeof body?.actor_avatar === "string" ? body.actor_avatar : null;

              if (!raw_actor_id) {
                throw new HttpError(400, "BAD_REQUEST", "actor_id is required");
              }

              // OWNERSHIP CHECK: actor_id must belong to the caller.
              // If actor_id matches the JWT device_id, allow (self-like).
              // Otherwise, check via account_devices → account_personas binding.
              const actor_id = raw_actor_id;
              if (actor_id !== jwt_user_id) {
                const { data: deviceBinding } = await sb(env)
                  .from("account_devices")
                  .select("account_id")
                  .eq("device_id", jwt_user_id)
                  .maybeSingle();

                if (!deviceBinding?.account_id) {
                  console.warn(`[like-auth] REJECTED: unclaimed device ${jwt_user_id} tried to like as actor_id ${actor_id}`);
                  throw new HttpError(403, "FORBIDDEN", "You do not own this persona");
                }

                const { data: personaBinding } = await sb(env)
                  .from("account_personas")
                  .select("persona_author_id")
                  .eq("account_id", deviceBinding.account_id)
                  .eq("persona_author_id", actor_id)
                  .maybeSingle();

                if (!personaBinding) {
                  console.warn(`[like-auth] REJECTED: device ${jwt_user_id} account ${deviceBinding.account_id} does not own actor ${actor_id}`);
                  throw new HttpError(403, "FORBIDDEN", "You do not own this persona");
                }
              }

              // Single upsert - no-op if already liked (ignoreDuplicates)
              let t1 = Date.now();
              const { data, error: insertError } = await sb(env)
                .from("post_likes")
                .upsert(
                  { post_id, actor_id, actor_name, actor_avatar },
                  { onConflict: "post_id,actor_id", ignoreDuplicates: true }
                )
                .select("post_id");
              const wasInserted = (data?.length ?? 0) > 0;
              console.log(`[perf] /api/posts/:id/like POST upsert ${Date.now() - t1}ms`, { post_id, wasInserted });

              if (insertError) throw insertError;

              // Create notification if this was a new like
              if (wasInserted) {
                t1 = Date.now();
                // Fetch the post owner's user_id (NOT author_id/persona)
                const { data: postData, error: postFetchError } = await sb(env)
                  .from("posts")
                  .select("user_id, author_id, root_post_id, room_id")
                  .eq("id", post_id)
                  .single();

                if (postFetchError) {
                  console.error(`[notif][${request_id}] failed to fetch post owner`, { post_id, error: postFetchError });
                }

                // Use user_id (JWT sub) for notification recipient, NOT author_id (persona)
                if (postData?.user_id && postData.user_id !== jwt_user_id) {
                  console.log(`[notif] creating post_like`, {
                    request_id,
                    post_id,
                    actor_user_id: jwt_user_id,
                    recipient_user_id: postData.user_id,
                    actor_persona_id: actor_id,
                    post_author_id: postData.author_id,
                  });
                  // Resolve root_post_id for navigation
                  const likedPostRootId = postData.root_post_id ?? post_id;
                  const plRoomMeta = await resolveRoomMeta(env, (postData as any).room_id);
                  await createNotification(env, {
                    recipient_user_id: postData.user_id,  // JWT sub of post owner
                    actor_user_id: jwt_user_id,           // JWT sub of liker
                    actor_name,
                    actor_avatar,
                    type: "post_like",
                    post_id,
                    root_post_id: likedPostRootId,
                    ...plRoomMeta,
                    group_key: `post_like:${post_id}`,
                  }, request_id);
                } else if (!postData?.user_id) {
                  console.warn(`[notif][${request_id}] post user_id not found, skipping notification`, { post_id });
                } else {
                  console.log(`[notif][${request_id}] skipping self-like`, { post_id, user_id: jwt_user_id });
                }
                console.log(`[perf] /api/posts/:id/like POST notification ${Date.now() - t1}ms`);
              }

              console.log(`[perf] /api/posts/:id/like POST total ${Date.now() - handlerStart}ms`, { post_id });
              return ok(req, env, request_id, { liked: true }, wasInserted ? 201 : 200);
            }

            // DELETE = ensure unliked (idempotent)
            if (req.method === "DELETE") {
              // AUTH GATE: require valid JWT — was previously missing entirely.
              const jwt_device_id = await requireAuth(req, env);

              // Parse actor_id from query param
              // SECURITY: actor_id is untrusted input — must verify caller owns it.
              const actor_id = url.searchParams.get("actor_id")?.trim() || null;

              if (!actor_id) {
                throw new HttpError(400, "BAD_REQUEST", "actor_id query param is required");
              }

              // OWNERSHIP CHECK: actor_id must belong to the caller.
              // If actor_id matches the JWT device_id, allow (self-unlike).
              // Otherwise, check via account_personas binding.
              if (actor_id !== jwt_device_id) {
                const { data: deviceBinding } = await sb(env)
                  .from("account_devices")
                  .select("account_id")
                  .eq("device_id", jwt_device_id)
                  .maybeSingle();

                if (!deviceBinding?.account_id) {
                  console.warn(`[like-auth] REJECTED: unclaimed device ${jwt_device_id} tried to unlike with actor_id ${actor_id}`);
                  throw new HttpError(403, "FORBIDDEN", "You do not own this like");
                }

                const { data: personaBinding } = await sb(env)
                  .from("account_personas")
                  .select("persona_author_id")
                  .eq("account_id", deviceBinding.account_id)
                  .eq("persona_author_id", actor_id)
                  .maybeSingle();

                if (!personaBinding) {
                  console.warn(`[like-auth] REJECTED: device ${jwt_device_id} account ${deviceBinding.account_id} does not own actor ${actor_id}`);
                  throw new HttpError(403, "FORBIDDEN", "You do not own this like");
                }
              }

              const t1 = Date.now();
              const { error } = await sb(env)
                .from("post_likes")
                .delete()
                .eq("post_id", post_id)
                .eq("actor_id", actor_id);
              console.log(`[perf] /api/posts/:id/like DELETE ${Date.now() - t1}ms`, { post_id });
              if (error) throw error;

              console.log(`[perf] /api/posts/:id/like DELETE total ${Date.now() - handlerStart}ms`, { post_id });
              return ok(req, env, request_id, { liked: false });
            }

            throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
          }
        }

        // GET /api/notifications?limit=50&cursor=<id?>
        if (path === "/api/notifications" && req.method === "GET") {
          const user_id = await requireAuth(req, env);

          // ── DIAGNOSTIC: identity keys used for notification fetch ──
          const cookieHeader = req.headers.get("cookie") ?? "";
          const deviceIdMatch = cookieHeader.match(/device_id=([^;]+)/);
          const deviceIdFromCookie = deviceIdMatch ? deviceIdMatch[1] : null;
          const authHeader = req.headers.get("Authorization") ?? "";

          const limitParam = url.searchParams.get("limit");
          const cursorParam = url.searchParams.get("cursor");

          console.log(`[news-notif:fetch][${request_id}] identity + query`, {
            route: "GET /api/notifications",
            jwtUserId: user_id,
            recipientWhereKey: "recipient_user_id",
            recipientWhereValue: user_id,
            deviceIdFromCookie,
            authHeaderPrefix: authHeader.slice(0, 20) + "...",
            queryParams: { limit: limitParam, cursor: cursorParam },
            categoryFilter: "none (fetches all types)",
          });

          let limit = 50;
          if (limitParam) {
            const parsed = Number(limitParam);
            if (Number.isFinite(parsed) && parsed > 0) {
              limit = Math.min(parsed, 200);
            }
          }

          let q = sb(env)
            .from("notifications")
            .select("*")
            .eq("recipient_user_id", user_id)
            .order("created_at", { ascending: false })
            .order("id", { ascending: false })
            .limit(limit);

          if (cursorParam) {
            const cursorId = Number(cursorParam);
            if (Number.isFinite(cursorId)) {
              q = q.lt("id", cursorId);
            }
          }

          const { data, error } = await q;

          console.log(`[news-notif:fetch][${request_id}] query result`, {
            userId: user_id,
            limit,
            cursor: cursorParam,
            rowCount: data?.length ?? 0,
            error: error ? { code: error.code, message: error.message } : null,
            types: data ? [...new Set(data.map((n: any) => n.type))] : [],
            newsRows: data ? data.filter((n: any) => n.type?.startsWith('news_')).length : 0,
          });

          if (error) throw error;

          const notifications = data ?? [];
          const next_cursor = notifications.length > 0 ? notifications[notifications.length - 1].id : null;

          // Helper to create excerpt from comment content
          const excerpt = (text: string | null | undefined, maxLen = 80): string | null => {
            if (!text) return null;
            const cleaned = text.replace(/[\r\n]+/g, " ").trim();
            if (cleaned.length <= maxLen) return cleaned;
            return cleaned.slice(0, maxLen - 1) + "…";
          };

          // Collect comment IDs for thread/post comments
          const commentIdSet = new Set<number>();
          for (const n of notifications) {
            if (n.comment_id) commentIdSet.add(n.comment_id);
            if (n.parent_comment_id) commentIdSet.add(n.parent_comment_id);
          }

          // Fetch thread/post comments in one query
          let commentsMap: Record<number, string> = {};
          const postCommentIds = Array.from(commentIdSet);
          if (postCommentIds.length > 0) {
            const { data: commentsData } = await sb(env)
              .from("comments")
              .select("id, content")
              .in("id", postCommentIds);
            for (const c of commentsData ?? []) {
              commentsMap[c.id] = c.content;
            }
          }

          // For IDs not found in comments table, try news_comments table
          const missingIds = postCommentIds.filter(id => !(id in commentsMap));
          if (missingIds.length > 0) {
            const { data: newsCommentsData } = await sb(env)
              .from("news_comments")
              .select("id, content")
              .in("id", missingIds);
            for (const c of newsCommentsData ?? []) {
              commentsMap[c.id] = c.content;
            }
          }



          // Enrich notifications with primary_text and secondary_text
          const enriched = notifications.map((n: any) => {
            let primary_text: string | null = null;
            let secondary_text: string | null = null;

            if (n.comment_id && commentsMap[n.comment_id]) {
              primary_text = excerpt(commentsMap[n.comment_id]);
            }
            if (n.type === "reply" && n.parent_comment_id && commentsMap[n.parent_comment_id]) {
              secondary_text = excerpt(commentsMap[n.parent_comment_id]);
            }

            return {
              id: n.id,
              type: n.type,
              created_at: n.created_at,
              is_read: n.is_read,
              group_key: n.group_key,
              actor_user_id: n.actor_user_id,
              actor_name: n.actor_name,
              actor_avatar: n.actor_avatar,
              post_id: n.post_id,
              root_post_id: n.root_post_id ?? n.post_id,
              comment_id: n.comment_id,
              parent_comment_id: n.parent_comment_id,
              news_id: n.news_id ?? null,
              news_url: n.news_url ?? null,
              news_image_url: n.news_image_url ?? null,
              room_id: n.room_id ?? null,
              room_icon_key: n.room_icon_key ?? null,
              room_emoji: n.room_emoji ?? null,
              primary_text,
              secondary_text,
            };
          });

          return ok(req, env, request_id, { notifications: enriched, next_cursor });
        }

        // POST /api/notifications/read
        if (path === "/api/notifications/read" && req.method === "POST") {
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const markAll = body?.all === true;
          const ids = Array.isArray(body?.ids) ? body.ids.filter((id: any) => typeof id === "number") : null;
          const group_key = typeof body?.group_key === "string" ? body.group_key : null;

          if (markAll) {
            // Mark ALL unread notifications for this user as read
            await sb(env)
              .from("notifications")
              .update({ is_read: true })
              .eq("recipient_user_id", user_id)
              .eq("is_read", false);
            // Invalidate KV cache so next unread_count poll returns 0
            const kvKey = `unread_count:${user_id}`;
            await env.UNREAD_KV.put(kvKey, "0", { expirationTtl: 300 });
          } else if (ids && ids.length > 0) {
            await sb(env)
              .from("notifications")
              .update({ is_read: true })
              .eq("recipient_user_id", user_id)
              .in("id", ids);
          } else if (group_key) {
            await sb(env)
              .from("notifications")
              .update({ is_read: true })
              .eq("recipient_user_id", user_id)
              .eq("group_key", group_key);
          }

          return ok(req, env, request_id, { ok: true });
        }

        // GET /api/notifications/unread_count (KV-cached, SWR + stale-mem fallback)
        // Priority: KV hit → stale mem (if KV timeout) → sync Supabase (cold start)
        // Background refresh keeps KV + in-memory cache fresh.
        if (path === "/api/notifications/unread_count" && req.method === "GET") {
          const KV_TTL = 300;           // seconds for KV expiry
          const KV_TIMEOUT_1 = 120;     // ms — first KV attempt
          const KV_TIMEOUT_2 = 200;     // ms — second KV attempt (retry)
          const p0 = performance.now();

          const user_id = await requireAuth(req, env);
          const p1 = performance.now();

          const kvKey = `unread_count:${user_id}`;

          // ── Helper: direct PostgREST fetch with HTTP timing + header capture ──
          const fetchUnreadCount = async (): Promise<{
            count: number;
            httpMs: string; parseMs: string; status: number;
            serverTiming: string; xResponseTime: string;
            cfRay: string; cfCache: string; contentRange: string;
          }> => {
            const restUrl = `${env.SUPABASE_URL}/rest/v1/notifications?select=id&recipient_user_id=eq.${encodeURIComponent(user_id)}&is_read=eq.false`;
            const tStart = performance.now();
            const res = await fetch(restUrl, {
              method: "HEAD",
              headers: {
                "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
                "Prefer": "count=exact",
              },
            });
            const tFetchEnd = performance.now();

            if (!res.ok) {
              const errBody = await res.text().catch(() => "");
              throw new Error(`PostgREST ${res.status}: ${errBody}`);
            }

            const cr = res.headers.get("content-range") ?? "";
            const m = cr.match(/\/(\d+)$/);
            const count = m ? parseInt(m[1], 10) : 0;
            const tParseEnd = performance.now();

            return {
              count,
              httpMs: (tFetchEnd - tStart).toFixed(1),
              parseMs: (tParseEnd - tFetchEnd).toFixed(1),
              status: res.status,
              serverTiming: res.headers.get("server-timing") ?? "none",
              xResponseTime: res.headers.get("x-response-time") ?? "none",
              cfRay: res.headers.get("cf-ray") ?? "none",
              cfCache: res.headers.get("cf-cache-status") ?? "none",
              contentRange: cr,
            };
          };

          // ── Helper: background refresh (updates KV + in-memory) ──
          const backgroundRefresh = (reason: string) => {
            ctx.waitUntil(
              (async () => {
                try {
                  const r = await fetchUnreadCount();
                  memSet(user_id, r.count);
                  await env.UNREAD_KV.put(kvKey, String(r.count), { expirationTtl: KV_TTL });
                  console.log(`[bg_refresh] ok rid=${request_id} me=${user_id} reason=${reason} count=${r.count} http_ms=${r.httpMs} parse_ms=${r.parseMs} status=${r.status}`);
                } catch (err) {
                  console.error(`[bg_refresh] fail rid=${request_id} me=${user_id} reason=${reason}`, err);
                }
              })()
            );
          };

          // ── KV lookup: attempt 1 ──
          const KV_TIMED_OUT = Symbol("KV_TIMED_OUT");
          let kvResult = await Promise.race([
            env.UNREAD_KV.get(kvKey, "text"),
            new Promise<typeof KV_TIMED_OUT>((resolve) =>
              setTimeout(() => resolve(KV_TIMED_OUT), KV_TIMEOUT_1)
            ),
          ]);
          let kvAttempts = 1;

          // ── KV retry: attempt 2 (only if first timed out) ──
          if (kvResult === KV_TIMED_OUT) {
            kvResult = await Promise.race([
              env.UNREAD_KV.get(kvKey, "text"),
              new Promise<typeof KV_TIMED_OUT>((resolve) =>
                setTimeout(() => resolve(KV_TIMED_OUT), KV_TIMEOUT_2)
              ),
            ]);
            kvAttempts = 2;
          }

          const p2 = performance.now();
          const kvTimedOut = kvResult === KV_TIMED_OUT;
          const cached = kvTimedOut ? null : kvResult;
          const kvGetMs = (p2 - p1).toFixed(1);

          // ── PATH 1: KV HIT — serve immediately, SWR background refresh ──
          if (cached !== null) {
            const count = parseInt(cached as string, 10);
            memSet(user_id, count); // keep in-memory fresh
            backgroundRefresh("swr");
            const pDone = performance.now();
            const kvHitTotal = pDone - p0;
            console.log(`[perf][unread_count] rid=${request_id} me=${user_id} kv_reason=hit kv_get_ms=${kvGetMs} kv_attempts=${kvAttempts} count=${count} total_ms=${kvHitTotal.toFixed(1)} source=kv bg_refresh=started`);
            if (kvHitTotal >= 200) {
              console.log(`[perf][unread_count] breakdown2`, JSON.stringify({
                rid: request_id, me: user_id,
                kv_reason: "hit", kv_attempts: kvAttempts,
                auth_ms: +(p1 - p0).toFixed(1),
                kv_get_ms: +kvGetMs,
                db_fallback_ms: 0,
                kv_put_mode: "none",
                total_ms: +kvHitTotal.toFixed(1),
              }));
            }
            return new Response(JSON.stringify({ unread_count: count, source: "kv" }), {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "HIT",
                ...corsHeaders(req, env),
              },
            });
          }

          // ── PATH 2: KV TIMEOUT — try in-memory stale serve ──
          if (kvTimedOut) {
            const stale = memGet(user_id);
            if (stale !== null) {
              backgroundRefresh("timeout_stale_mem");
              const pDone = performance.now();
              console.log(`[perf][unread_count] rid=${request_id} me=${user_id} kv_reason=timeout_stale_mem kv_get_ms=${kvGetMs} kv_attempts=${kvAttempts} count=${stale} total_ms=${(pDone - p0).toFixed(1)} source=mem bg_refresh=started`);
              return new Response(JSON.stringify({ unread_count: stale, source: "mem" }), {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "STALE_MEM",
                  ...corsHeaders(req, env),
                },
              });
            }
            // No stale value — must fall through to sync DB
            console.log(`[kv] unread_count TIMEOUT_NO_MEM rid=${request_id} me=${user_id} kv_get_ms=${kvGetMs} kv_attempts=${kvAttempts}`);
          } else {
            // True KV MISS (key doesn't exist)
            console.log(`[kv] unread_count MISS rid=${request_id} me=${user_id} kv_get_ms=${kvGetMs}`);
          }

          // ── PATH 3: Sync DB fallback (KV miss or timeout with no stale) ──
          const kvLabel = kvTimedOut ? "timeout_fallback_db" : "miss";
          try {
            const tDbFallback = performance.now();
            const r = await fetchUnreadCount();
            const p3 = performance.now();
            const dbFallbackMs = p3 - tDbFallback;

            memSet(user_id, r.count);

            // Fire-and-forget KV put
            const tKvPut = performance.now();
            ctx.waitUntil(
              env.UNREAD_KV.put(kvKey, String(r.count), { expirationTtl: KV_TTL })
                .then(() => console.log(`[kv] unread_count put ok=true rid=${request_id} me=${user_id} count=${r.count}`))
                .catch((err) => console.error(`[kv] unread_count put ok=false rid=${request_id} me=${user_id}`, err))
            );
            const kvPutEnqueueMs = performance.now() - tKvPut;

            const dbTotal = p3 - p0;
            console.log(`[perf][unread_count] rid=${request_id} me=${user_id} kv_reason=${kvLabel} kv_get_ms=${kvGetMs} kv_attempts=${kvAttempts} count=${r.count} http_ms=${r.httpMs} parse_ms=${r.parseMs} total_ms=${dbTotal.toFixed(1)} source=db kv_put=async`);
            console.log(`[perf][unread_count_http] rid=${request_id} me=${user_id} kv_reason=${kvLabel} http_ms=${r.httpMs} parse_ms=${r.parseMs} status=${r.status} server_timing="${r.serverTiming}" x_response_time="${r.xResponseTime}" cf_ray="${r.cfRay}" cf_cache="${r.cfCache}" content_range="${r.contentRange}"`);
            if (dbTotal >= 200) {
              console.log(`[perf][unread_count] breakdown2`, JSON.stringify({
                rid: request_id, me: user_id,
                kv_reason: kvLabel, kv_attempts: kvAttempts,
                auth_ms: +(p1 - p0).toFixed(1),
                kv_get_ms: +kvGetMs,
                db_fallback_ms: +dbFallbackMs.toFixed(1),
                db_http_ms: +r.httpMs, db_parse_ms: +r.parseMs,
                kv_put_mode: "async", kv_put_enqueue_ms: +kvPutEnqueueMs.toFixed(1),
                total_ms: +dbTotal.toFixed(1),
              }));
            }

            return new Response(JSON.stringify({ unread_count: r.count, source: "db" }), {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": kvTimedOut ? "TIMEOUT_DB" : "MISS_DB",
                ...corsHeaders(req, env),
              },
            });
          } catch (dbErr) {
            console.error(`[unread_count] db_fallback_error rid=${request_id} me=${user_id} kv_reason=${kvLabel}`, dbErr);
            // Last resort: return stale mem if it appeared since we started
            const lastChance = memGet(user_id);
            if (lastChance !== null) {
              return new Response(JSON.stringify({ unread_count: lastChance, source: "mem_error" }), {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "ERROR_MEM",
                  ...corsHeaders(req, env),
                },
              });
            }
            throw dbErr; // re-throw to hit outer error handler
          }
        }

        // GET /api/debug/notifications?type=post_like&limit=20 (DEV ONLY - no auth)
        if (path === "/api/debug/notifications" && req.method === "GET") {
          const type = url.searchParams.get("type") || null;
          const limit = Math.min(Number(url.searchParams.get("limit")) || 20, 100);
          const post_id = url.searchParams.get("post_id") || null;

          let query = sb(env)
            .from("notifications")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(limit);

          if (type) query = query.eq("type", type);
          if (post_id) query = query.eq("post_id", Number(post_id));

          const { data, error } = await query;
          if (error) throw error;

          console.log(`[debug] /api/debug/notifications`, { type, limit, post_id, count: data?.length });
          return ok(req, env, request_id, { notifications: data ?? [], count: data?.length ?? 0 });
        }

        // POST /api/upload-url -> presigned PUT URL for R2
        // Body: { kind: "image_original" | "image_thumb" | "video_original" | "video_thumb" | "video" | "thumb", content_type: string }
        if (path === "/api/upload-url" && req.method === "POST") {
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const kind = body?.kind as string | undefined;
          const content_type = typeof body?.content_type === "string" ? body.content_type : null;

          // Validate kind
          const validKinds = ["image_original", "image_thumb", "video_original", "video_thumb", "video", "thumb", "avatar"] as const;
          if (!kind || !validKinds.includes(kind as any)) {
            throw new HttpError(422, "VALIDATION_ERROR", `kind must be one of: ${validKinds.join(", ")}`);
          }

          // Validate content_type
          if (!content_type) {
            throw new HttpError(422, "VALIDATION_ERROR", "content_type required");
          }

          // Validate content_type matches kind
          const isImage = kind.startsWith("image_");
          const isVideo = kind.startsWith("video_") || kind === "video";
          const isThumb = kind === "thumb"; // thumbs are images but go to thumb/ prefix
          const isAvatar = kind === "avatar"; // avatars are images, go to avatar/ prefix
          if (isImage && !content_type.startsWith("image/")) {
            throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with image/ for image kinds");
          }
          if (isVideo && !content_type.startsWith("video/")) {
            throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with video/ for video kinds");
          }
          if (isThumb && !content_type.startsWith("image/")) {
            throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with image/ for thumb kind");
          }
          if (isAvatar && !content_type.startsWith("image/")) {
            throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with image/ for avatar kind");
          }

          // Server-side video size limit (50MB)
          const MAX_VIDEO_BYTES = 50 * 1024 * 1024;
          const bytes = typeof body?.bytes === "number" ? body.bytes : null;
          if (isVideo && bytes !== null && bytes > MAX_VIDEO_BYTES) {
            throw new HttpError(400, "SIZE_LIMIT_EXCEEDED", "Video exceeds 50MB limit");
          }

          // Generate unique object key: {prefix}/{user_id}/{timestamp}_{uuid}.{ext}
          // Map kind to key prefix
          let keyPrefix = kind;
          if (kind === "thumb") keyPrefix = "thumb";

          const ext = content_type.split("/")[1]?.split(";")[0] || (isImage || isThumb || isAvatar ? "jpg" : "mp4");
          const timestamp = Date.now();
          const uniqueId = crypto.randomUUID();
          const key = `${keyPrefix}/${user_id}/${timestamp}_${uniqueId}.${ext}`;

          // Validate key prefix (defense-in-depth)
          const allowedPrefixes = ["image_original/", "image_thumb/", "video_original/", "video_thumb/", "video/", "thumb/", "avatar/"];
          if (!allowedPrefixes.some(p => key.startsWith(p))) {
            throw new HttpError(422, "VALIDATION_ERROR", "Invalid key prefix");
          }

          // ── Generate S3-compatible presigned PUT URL (direct-to-R2) ──
          const bucket = "teran-media";
          const endpoint = `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
          const objectUrl = `${endpoint}/${bucket}/${key}`;

          const aws = new AwsClient({
            accessKeyId: env.R2_ACCESS_KEY_ID,
            secretAccessKey: env.R2_SECRET_ACCESS_KEY,
            region: "auto",
            service: "s3",
          });

          const expiresSeconds = 300;
          const presignUrl = new URL(objectUrl);
          presignUrl.searchParams.set("X-Amz-Expires", String(expiresSeconds));

          const signedReq = await aws.sign(
            new Request(presignUrl.toString(), {
              method: "PUT",
              headers: { "Content-Type": content_type },
            }),
            { aws: { signQuery: true } }
          );

          const uploadUrl = signedReq.url;

          console.log(`[upload-url] rid=${request_id} kind=${kind} key=${key} direct_r2=true`);

          return ok(req, env, request_id, {
            key,
            uploadUrl,
            direct_r2: true,
          }, 201);
        }

        // PUT /api/upload/:key (presigned upload receiver)
        {
          const uploadMatch = path.match(/^\/api\/upload\/(.+)$/);
          if (uploadMatch && req.method === "PUT") {
            console.log(`[upload] DEPRECATED worker-proxy path hit key=${decodeURIComponent(uploadMatch[1])}`);
            const uploadT0 = Date.now();
            const key = decodeURIComponent(uploadMatch[1]);
            const expiresStr = url.searchParams.get("expires");
            const content_type = url.searchParams.get("content_type");
            const sig = url.searchParams.get("sig");

            if (!expiresStr || !content_type || !sig) {
              throw new HttpError(400, "BAD_REQUEST", "Missing required query parameters");
            }

            const expiresAt = Number(expiresStr);
            const now = Math.floor(Date.now() / 1000);
            if (now > expiresAt) {
              throw new HttpError(403, "EXPIRED", "Upload URL has expired");
            }

            // Verify signature
            const signPayload = `PUT:${key}:${content_type}:${expiresAt}`;
            const expectedSig = await hmacSha256(env.JWT_SECRET, signPayload);
            if (sig !== expectedSig) {
              throw new HttpError(403, "FORBIDDEN", "Invalid signature");
            }

            // ── Upload diagnostics ──
            const cf = (req as any).cf || {};
            const contentLength = req.headers.get("content-length");
            const cfRay = req.headers.get("cf-ray") ?? "?";
            const reqHost = url.host;
            const reqPath = url.pathname;
            console.log(`[upload-diag] rid=${request_id} key=${key} content_type=${content_type} content_length=${contentLength ?? "unknown"} host=${reqHost} path=${reqPath} cfRay=${cfRay} colo=${cf.colo ?? "?"} city=${cf.city ?? "?"} region=${cf.region ?? "?"} country=${cf.country ?? "?"} asn=${cf.asOrganization ?? cf.asn ?? "?"} httpVersion=${cf.httpProtocol ?? "?"} tlsCipher=${cf.tlsCipher ?? "?"} tlsVersion=${cf.tlsVersion ?? "?"} clientTcpRtt=${cf.clientTcpRtt ?? "?"}ms`);

            // Get body and upload to R2 (split timing)
            const bodyT0 = Date.now();
            const body = await req.arrayBuffer();
            const bodyMs = Date.now() - bodyT0;
            if (!body || body.byteLength === 0) {
              throw new HttpError(400, "BAD_REQUEST", "Empty body");
            }

            const r2T0 = Date.now();
            await env.R2_MEDIA.put(key, body, {
              httpMetadata: {
                contentType: content_type,
              },
            });
            const r2Ms = Date.now() - r2T0;

            const totalMs = Date.now() - uploadT0;
            console.log(`[upload-diag] rid=${request_id} DONE key=${key} body_bytes=${body.byteLength} body_read_ms=${bodyMs} r2_put_ms=${r2Ms} total_ms=${totalMs} colo=${cf.colo ?? "?"}`);

            return ok(req, env, request_id, { key, uploaded: true }, 201);
          }
        }

        // GET /api/media/:key - serve R2 objects
        {
          const mediaMatch = path.match(/^\/api\/media\/(.+)$/);
          if (mediaMatch) {
            const t0 = performance.now();
            const rid = request_id;

            // Safely decode URL-encoded key (handle double-encoding)
            let key = mediaMatch[1];
            try {
              const decoded1 = decodeURIComponent(key);
              // If first decode changed the string and it still contains %, try again
              if (decoded1 !== key && decoded1.includes('%')) {
                try {
                  const decoded2 = decodeURIComponent(decoded1);
                  key = decoded2;
                } catch {
                  key = decoded1;
                }
              } else {
                key = decoded1;
              }
            } catch {
              // If decode fails, use original key
            }

            // ── Extract request + Cloudflare fields ──
            const host = url.hostname;
            const range = req.headers.get("Range") || "none";
            const accept = req.headers.get("Accept") || "none";
            const cfRay = req.headers.get("cf-ray") || "none";
            const cf = (req as any).cf || {};
            const colo = cf.colo || (cfRay !== "none" ? cfRay.split("-").pop() : "unknown");
            const city = cf.city || "unknown";
            const region = cf.region || "unknown";
            const country = cf.country || "unknown";
            const asn = cf.asn || "unknown";
            const httpVersion = cf.httpProtocol || "unknown";

            // ── Entry log ──
            console.log(`[media-diag] rid=${rid} key=${key} method=${req.method} host=${host} path=${path} range=${range} accept=${accept} cfRay=${cfRay} colo=${colo} city=${city} region=${region} country=${country} asn=${asn} httpVersion=${httpVersion}`);
            console.log(`[media] legacy_proxy_used rid=${rid} key=${key} referer=${req.headers.get("Referer") || "none"}`);

            if (req.method === "OPTIONS") {
              return new Response(null, {
                status: 204,
                headers: {
                  "Access-Control-Allow-Origin": "*",
                  "Access-Control-Allow-Methods": "GET, OPTIONS",
                  "Access-Control-Allow-Headers": "Range, Content-Type",
                  "Access-Control-Max-Age": "86400",
                },
              });
            }

            if (req.method !== "GET") {
              throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
            }

            // Parse Range header for partial content support
            const rangeHeader = req.headers.get("Range");
            let r2Options: R2GetOptions | undefined;
            let rangeStart: number | undefined;
            let rangeEnd: number | undefined;
            if (rangeHeader) {
              const rangeMatch = rangeHeader.match(/^bytes=(\d*)-(\d*)$/);
              if (rangeMatch) {
                rangeStart = rangeMatch[1] ? parseInt(rangeMatch[1], 10) : undefined;
                rangeEnd = rangeMatch[2] ? parseInt(rangeMatch[2], 10) : undefined;
                if (rangeStart !== undefined) {
                  r2Options = {
                    range: {
                      offset: rangeStart,
                      length: rangeEnd !== undefined ? rangeEnd - rangeStart + 1 : undefined,
                    },
                  };
                }
              }
            }

            // ── R2 GET with timing ──
            const tR2Start = performance.now();
            let obj: R2ObjectBody | null;
            try {
              obj = r2Options
                ? await env.R2_MEDIA.get(key, r2Options)
                : await env.R2_MEDIA.get(key);
            } catch (r2Err) {
              const totalMs = performance.now() - t0;
              console.log(`[media-diag] rid=${rid} ERROR key=${key} r2_get_ms=${(performance.now() - tR2Start).toFixed(1)} total_ms=${totalMs.toFixed(1)} err=${String(r2Err)}`);
              throw r2Err;
            }
            const r2GetMs = performance.now() - tR2Start;

            if (!obj) {
              const totalMs = performance.now() - t0;
              console.log(`[media-diag] rid=${rid} DONE key=${key} status=404 r2_get_ms=${r2GetMs.toFixed(1)} total_ms=${totalMs.toFixed(1)} bytes_out=0 cache_control=none etag=none cfRay=${cfRay} colo=${colo}`);
              return new Response(JSON.stringify({
                error: { code: "NOT_FOUND", message: "Media not found", key_decoded: key },
                request_id
              }), {
                status: 404,
                headers: {
                  "Content-Type": "application/json",
                  "Access-Control-Allow-Origin": "*",
                  "Cross-Origin-Resource-Policy": "cross-origin",
                },
              });
            }

            // Determine content type
            let contentType = obj.httpMetadata?.contentType;
            if (!contentType) {
              // Infer from extension
              const ext = key.split(".").pop()?.toLowerCase();
              const mimeMap: Record<string, string> = {
                jpg: "image/jpeg",
                jpeg: "image/jpeg",
                png: "image/png",
                webp: "image/webp",
                gif: "image/gif",
                mp4: "video/mp4",
                webm: "video/webm",
                mov: "video/quicktime",
              };
              contentType = mimeMap[ext || ""] || "application/octet-stream";
            }

            // Determine cache control (thumbs get longer cache)
            const isThumb = key.includes("_thumb") || key.startsWith("image_thumb/") || key.startsWith("video_thumb/");
            const cacheControl = isThumb
              ? "public, max-age=31536000, immutable"
              : "public, max-age=86400";

            const headers: Record<string, string> = {
              "Content-Type": contentType,
              "Cache-Control": cacheControl,
              "Accept-Ranges": "bytes",
              "Access-Control-Allow-Origin": "*",
              "Cross-Origin-Resource-Policy": "cross-origin",
            };

            if (obj.etag) {
              headers["ETag"] = obj.etag;
            }

            const etag = obj.etag || "none";

            // Handle partial content response
            if (rangeHeader && rangeStart !== undefined) {
              const start = rangeStart;
              const end = rangeEnd !== undefined ? rangeEnd : obj.size - 1;
              const length = end - start + 1;
              headers["Content-Range"] = `bytes ${start}-${end}/${obj.size}`;
              headers["Content-Length"] = String(length);

              const totalMs = performance.now() - t0;
              console.log(`[media-diag] rid=${rid} DONE key=${key} status=206 r2_get_ms=${r2GetMs.toFixed(1)} total_ms=${totalMs.toFixed(1)} bytes_out=${length} obj_size=${obj.size} range=${start}-${end} cache_control="${cacheControl}" etag=${etag} cfRay=${cfRay} colo=${colo}`);
              return new Response(obj.body, { status: 206, headers });
            }

            headers["Content-Length"] = String(obj.size);

            const totalMs = performance.now() - t0;
            console.log(`[media-diag] rid=${rid} DONE key=${key} status=200 r2_get_ms=${r2GetMs.toFixed(1)} total_ms=${totalMs.toFixed(1)} bytes_out=${obj.size} cache_control="${cacheControl}" etag=${etag} cfRay=${cfRay} colo=${colo}`);
            return new Response(obj.body, { status: 200, headers });
          }
        }

        // =====================================================
        // SAVES (Bookmarks) API
        // =====================================================

        // POST /api/saves - Save a post (bookmark) - OPTIMIZED: single DB call
        if (path === "/api/saves" && req.method === "POST") {
          const handlerStart = Date.now();

          let t1 = Date.now();
          const user_id = await requireAuth(req, env);
          console.log(`[perf] POST /api/saves auth ${Date.now() - t1}ms`);

          t1 = Date.now();
          const body = (await req.json().catch(() => null)) as any;
          const post_id = Number(body?.post_id);
          console.log(`[perf] POST /api/saves parse ${Date.now() - t1}ms`, { post_id });

          if (!Number.isFinite(post_id) || post_id <= 0) {
            throw new HttpError(422, "VALIDATION_ERROR", "post_id must be a valid positive integer");
          }

          // Single upsert - FK constraint will catch invalid post_ids
          // No need for separate "post exists" check (saves ~150ms roundtrip)
          t1 = Date.now();
          const { data, error: insertError } = await sb(env)
            .from("saves")
            .upsert(
              { user_id, post_id },
              { onConflict: "user_id,post_id", ignoreDuplicates: true }
            )
            .select("post_id");
          const wasInserted = (data?.length ?? 0) > 0;
          console.log(`[perf] POST /api/saves upsert ${Date.now() - t1}ms`, { post_id, wasInserted });

          // Handle FK violation (post doesn't exist) - Postgres error 23503
          if (insertError) {
            if (insertError.code === "23503") {
              throw new HttpError(404, "NOT_FOUND", "Post not found");
            }
            throw insertError;
          }

          console.log(`[perf] POST /api/saves total ${Date.now() - handlerStart}ms`, { post_id });
          return ok(req, env, request_id, { ok: true }, wasInserted ? 201 : 200);
        }

        // DELETE /api/saves/:post_id - Unsave a post
        {
          const m = path.match(/^\/api\/saves\/(\d+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const post_id = Number(m[1]);

            if (!Number.isFinite(post_id)) {
              throw new HttpError(400, "BAD_REQUEST", "Invalid post_id");
            }

            // Delete (idempotent - no error if not exists)
            const { error } = await sb(env)
              .from("saves")
              .delete()
              .eq("user_id", user_id)
              .eq("post_id", post_id);
            if (error) throw error;

            return ok(req, env, request_id, { ok: true });
          }
        }

        // GET /api/saves - List user's saved posts
        if (path === "/api/saves" && req.method === "GET") {
          const user_id = await requireAuth(req, env);

          const { data: saves, error } = await sb(env)
            .from("saves")
            .select("post_id, created_at")
            .eq("user_id", user_id)
            .order("created_at", { ascending: false })
            .limit(200);
          if (error) throw error;

          return ok(req, env, request_id, { saves: saves ?? [] });
        }

        // GET /api/saves/counts?post_ids=1,2,3 (Cache API, 60s TTL)
        if (path === "/api/saves/counts" && req.method === "GET") {
          const SAVES_CACHE_TTL = 60; // seconds
          const t0 = Date.now();
          const rid = request_id;
          let idsCount = 0;
          try {
            const postIdsParam = url.searchParams.get("post_ids") || "";
            const postIds = postIdsParam
              .split(",")
              .map(s => parseInt(s.trim(), 10))
              .filter(n => Number.isFinite(n) && n > 0)
              .slice(0, 200);
            idsCount = postIds.length;

            if (postIds.length === 0) {
              throw new HttpError(400, "BAD_REQUEST", "post_ids is required (comma-separated integers)");
            }

            // Stable cache key: sorted IDs
            const sortedKey = [...postIds].sort((a, b) => a - b).join(",");
            const cacheKeyUrl = new URL("https://cache.internal/saves/counts");
            cacheKeyUrl.searchParams.set("ids", sortedKey);
            const cacheKey = new Request(cacheKeyUrl.toString(), { method: "GET" });
            const cache = caches.default;
            const cached = await cache.match(cacheKey);
            const tCache = Date.now();

            if (cached) {
              const hitBody = await cached.text();
              console.log(`[perf] saves/counts rid=${rid} cache=HIT total=${Date.now() - t0}ms ids=${idsCount} payloadBytes=${hitBody.length}`);
              return new Response(hitBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "HIT",
                  ...corsHeaders(req, env),
                },
              });
            }

            // Cache MISS — query DB
            const tDb0 = Date.now();
            const { data: rows, error } = await sb(env)
              .from("saves")
              .select("post_id")
              .in("post_id", postIds);
            const tDb1 = Date.now();
            if (error) throw error;

            // Count occurrences
            const countMap: Record<number, number> = {};
            for (const row of rows ?? []) {
              countMap[row.post_id] = (countMap[row.post_id] || 0) + 1;
            }

            // Fill zeros for requested IDs not in result
            const counts: Record<string, number> = {};
            for (const id of postIds) {
              counts[String(id)] = countMap[id] || 0;
            }
            const tEnd = Date.now();

            const responseBody = { counts, request_id };
            const body = JSON.stringify(responseBody);

            // Store in edge cache
            ctx.waitUntil(
              cache.put(cacheKey, new Response(body, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": `public, max-age=${SAVES_CACHE_TTL}`,
                },
              }))
                .then(() => console.log(`[cache] saves/counts put ok rid=${rid} ids=${idsCount}`))
                .catch((err) => console.error(`[cache] saves/counts put fail rid=${rid}`, err))
            );

            console.log(`[perf] saves/counts rid=${rid} cache=MISS cacheCheck=${tCache - t0}ms db=${tDb1 - tDb0}ms transform=${tEnd - tDb1}ms total=${tEnd - t0}ms payloadBytes=${body.length} ids=${idsCount} error=0`);
            return new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "MISS",
                ...corsHeaders(req, env),
              },
            });
          } catch (err: any) {
            if (err instanceof HttpError) throw err;
            console.log(`[perf] saves/counts rid=${rid} total=${Date.now() - t0}ms ids=${idsCount} error=1 msg=${err?.message?.slice(0, 100)}`);
            throw err;
          }
        }

        // =====================================================
        // BLOCKS API (Mutual visibility enforced client-side)
        // =====================================================

        // POST /api/blocks - Block a user
        if (path === "/api/blocks" && req.method === "POST") {
          const blocker_user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const blocked_user_id = body?.user_id;

          if (!blocked_user_id || typeof blocked_user_id !== "string") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }
          if (blocked_user_id === blocker_user_id) {
            throw new HttpError(400, "BAD_REQUEST", "Cannot block yourself");
          }

          // Insert (idempotent - ignore duplicates)
          const { error } = await sb(env)
            .from("blocks")
            .insert({ blocker_user_id, blocked_user_id });

          // Postgres 23505 = unique_violation (already blocked)
          if (error && error.code !== "23505") {
            throw error;
          }

          return ok(req, env, request_id, { ok: true });
        }

        // DELETE /api/blocks/:userId - Unblock a user
        {
          const m = path.match(/^\/api\/blocks\/([^/]+)$/);
          if (m && req.method === "DELETE") {
            const blocker_user_id = await requireAuth(req, env);
            const blocked_user_id = m[1];

            // Delete (idempotent - no error if not exists)
            const { error } = await sb(env)
              .from("blocks")
              .delete()
              .eq("blocker_user_id", blocker_user_id)
              .eq("blocked_user_id", blocked_user_id);
            if (error) throw error;

            return ok(req, env, request_id, { ok: true });
          }
        }

        // GET /api/blocks - List users I have blocked
        if (path === "/api/blocks" && req.method === "GET") {
          const handlerStart = Date.now();
          const blocker_user_id = await requireAuth(req, env);
          const authMs = Date.now() - handlerStart;

          const t1 = Date.now();
          const { data: rows, error } = await sb(env)
            .from("blocks")
            .select("blocked_user_id, created_at")
            .eq("blocker_user_id", blocker_user_id)
            .order("created_at", { ascending: false });
          const dbMs = Date.now() - t1;
          if (error) throw error;

          const blocked = (rows ?? []).map(r => ({
            user_id: r.blocked_user_id,
            created_at: r.created_at,
          }));

          console.log(`[perf] GET /api/blocks rid=${request_id} auth=${authMs}ms db=${dbMs}ms total=${Date.now() - handlerStart}ms rows=${blocked.length}`);
          return ok(req, env, request_id, { blocked });
        }

        // GET /api/blocks/relations?user_ids=a,b,c - Check mutual blocks for filtering
        // CACHED: 60s TTL using Cloudflare Cache API
        //
        // ─── Safari DevTools fetch() snippet ───────────────────────────────
        // This endpoint uses Authorization Bearer token (NOT cookies).
        // Do NOT use credentials: "include" — it causes CORS errors.
        // To force MISS in manual tests, add cache: "no-store".
        //
        //   const r = await fetch("https://teran-api.teran-development.workers.dev/api/blocks/relations?user_ids=a,b,c", {
        //     method: "GET",
        //     mode: "cors",
        //     cache: "no-store", // remove this to observe HIT on 2nd call
        //     headers: {
        //       "Authorization": "Bearer YOUR_TOKEN",
        //       "Accept": "application/json"
        //     }
        //   });
        //   console.log("x-cache:", r.headers.get("x-cache"));
        //   console.log("x-cache-key:", r.headers.get("x-cache-key"));
        //   console.log("x-request-id:", r.headers.get("x-request-id"));
        //   console.log(await r.json());
        //
        // ────────────────────────────────────────────────────────────────────
        if (path === "/api/blocks/relations" && req.method === "GET") {
          const BLOCKS_CACHE_TTL_SECONDS = 60;
          const handlerStart = Date.now();

          // Debug: confirm auth header is present on original request
          const hasAuth = req.headers.has("Authorization");
          console.log(`[debug] blocks/relations auth header present=${hasAuth} rid=${request_id}`);

          const my_user_id = await requireAuth(req, env);

          // Normalize user_ids: split, trim, filter, dedupe, sort
          const userIdsParam = url.searchParams.get("user_ids") || "";
          const userIds = [...new Set(
            userIdsParam
              .split(",")
              .map(s => s.trim())
              .filter(s => s.length > 0)
          )].sort().slice(0, 200);

          // Fast path: empty list
          if (userIds.length === 0) {
            console.log(`[cache] blocks/relations SKIP_EMPTY rid=${request_id}`);
            return ok(req, env, request_id, { blocked_user_ids: [] });
          }

          // Build stable cache key: deterministic URL from hash
          const cacheKeyData = `blocks:${my_user_id}:${userIds.join(",")}`;
          const cacheKeyHash = await sha256Hex(cacheKeyData);
          const cacheUrl = `https://cache.internal/__cache/blocks_relations?me=${encodeURIComponent(my_user_id)}&key=${cacheKeyHash}`;
          const cacheReq = new Request(cacheUrl, { method: "GET" });

          // Try cache first
          const cache = caches.default;
          const cachedResponse = await cache.match(cacheReq);

          if (cachedResponse) {
            // ─── CACHE HIT ───
            console.log(`[cache] blocks/relations HIT rid=${request_id} url=${cacheUrl.slice(0, 100)} userCount=${userIds.length}`);
            const body = await cachedResponse.text();
            return new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "HIT",
                "X-Cache-Key": cacheKeyHash.slice(0, 12),
                ...corsHeaders(req, env),
              },
            });
          }

          // ─── CACHE MISS ───
          console.log(`[cache] blocks/relations MISS rid=${request_id} url=${cacheUrl.slice(0, 100)} userCount=${userIds.length} hash=${cacheKeyHash.slice(0, 12)}`);

          // Query DB — both directions in parallel
          const t1 = Date.now();

          const [res1, res2] = await Promise.all([
            sb(env)
              .from("blocks")
              .select("blocked_user_id")
              .eq("blocker_user_id", my_user_id)
              .in("blocked_user_id", userIds),
            sb(env)
              .from("blocks")
              .select("blocker_user_id")
              .eq("blocked_user_id", my_user_id)
              .in("blocker_user_id", userIds),
          ]);
          if (res1.error) throw res1.error;
          if (res2.error) throw res2.error;

          const blockedSet = new Set<string>();
          for (const row of res1.data ?? []) blockedSet.add(row.blocked_user_id);
          for (const row of res2.data ?? []) blockedSet.add(row.blocker_user_id);

          const responseData = { blocked_user_ids: Array.from(blockedSet), request_id };
          const responseBody = JSON.stringify(responseData);

          const dbMs = Date.now() - t1;
          console.log(`[perf] blocks/relations db=${dbMs}ms total=${Date.now() - handlerStart}ms rid=${request_id}`);

          // Response to client
          const response = new Response(responseBody, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Request-Id": request_id,
              "X-Cache": "MISS",
              "X-Cache-Key": cacheKeyHash.slice(0, 12),
              ...corsHeaders(req, env),
            },
          });

          // Fire-and-forget cache put via waitUntil (non-blocking)
          ctx.waitUntil(
            (async () => {
              try {
                const responseToCache = new Response(responseBody, {
                  status: 200,
                  headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": `public, max-age=${BLOCKS_CACHE_TTL_SECONDS}`,
                  },
                });
                await cache.put(cacheReq, responseToCache);
                console.log(`[cache] blocks/relations put ok=true rid=${request_id} hash=${cacheKeyHash.slice(0, 12)}`);
              } catch (err) {
                console.error(`[cache] blocks/relations put ok=false rid=${request_id} hash=${cacheKeyHash.slice(0, 12)}`, err);
              }
            })()
          );

          return response;
        }

        // =====================================================
        // ECHOES API (Private follow-like, no counts/notifications)
        // =====================================================

        // Helper: check if mutual block exists (head-only, no rows returned)
        async function isMutuallyBlocked(userId1: string, userId2: string): Promise<boolean> {
          const { count, error } = await sb(env)
            .from("blocks")
            .select("id", { count: "exact", head: true })
            .or(`and(blocker_user_id.eq.${userId1},blocked_user_id.eq.${userId2}),and(blocker_user_id.eq.${userId2},blocked_user_id.eq.${userId1})`)
            .limit(1);
          return !error && (count ?? 0) > 0;
        }

        // POST /api/echoes - Echo a user - OPTIMIZED
        if (path === "/api/echoes" && req.method === "POST") {
          const handlerStart = Date.now();

          let t1 = Date.now();
          const user_id = await requireAuth(req, env);
          console.log(`[perf] POST /api/echoes auth ${Date.now() - t1}ms`);

          t1 = Date.now();
          const body = (await req.json().catch(() => null)) as any;
          const echoed_user_id = body?.user_id;
          console.log(`[perf] POST /api/echoes parse ${Date.now() - t1}ms`);

          if (!echoed_user_id || typeof echoed_user_id !== "string") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }
          if (echoed_user_id === user_id) {
            throw new HttpError(400, "BAD_REQUEST", "Cannot echo yourself");
          }

          // Block enforcement: check mutual block (required for safety)
          t1 = Date.now();
          if (await isMutuallyBlocked(user_id, echoed_user_id)) {
            console.log(`[perf] POST /api/echoes block_check ${Date.now() - t1}ms (blocked)`);
            throw new HttpError(403, "BLOCKED", "Cannot echo a blocked user");
          }
          console.log(`[perf] POST /api/echoes block_check ${Date.now() - t1}ms`);

          // Upsert (idempotent - no-op if already echoing)
          t1 = Date.now();
          const { data, error } = await sb(env)
            .from("echoes")
            .upsert(
              { user_id, echoed_user_id },
              { onConflict: "user_id,echoed_user_id", ignoreDuplicates: true }
            )
            .select("echoed_user_id");
          const wasInserted = (data?.length ?? 0) > 0;
          console.log(`[perf] POST /api/echoes upsert ${Date.now() - t1}ms`, { wasInserted });

          if (error) throw error;

          console.log(`[perf] POST /api/echoes total ${Date.now() - handlerStart}ms`);
          return ok(req, env, request_id, { ok: true }, wasInserted ? 201 : 200);
        }

        // DELETE /api/echoes/:userId - Un-echo a user
        {
          const m = path.match(/^\/api\/echoes\/([^/]+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const echoed_user_id = m[1];

            // Delete (idempotent - no error if not exists)
            const { error } = await sb(env)
              .from("echoes")
              .delete()
              .eq("user_id", user_id)
              .eq("echoed_user_id", echoed_user_id);
            if (error) throw error;

            return ok(req, env, request_id, { ok: true });
          }
        }

        // GET /api/echoes - List users I echo (private, newest first) - OPTIMIZED v2: PARALLEL
        if (path === "/api/echoes" && req.method === "GET") {
          const handlerStart = Date.now();
          const user_id = await requireAuth(req, env);
          const authMs = Date.now() - handlerStart;

          // Run BOTH queries in parallel (saves ~150ms)
          const t1 = Date.now();
          const [echoesResult, blocksResult] = await Promise.all([
            // Query 1: Get echoed users (minimal columns)
            sb(env)
              .from("echoes")
              .select("echoed_user_id, created_at")
              .eq("user_id", user_id)
              .order("created_at", { ascending: false })
              .limit(200),
            // Query 2: All my block relations
            sb(env)
              .from("blocks")
              .select("blocker_user_id, blocked_user_id")
              .or(`blocker_user_id.eq.${user_id},blocked_user_id.eq.${user_id}`),
          ]);
          const dbMs = Date.now() - t1;
          console.log(`[perf] /api/echoes rid=${request_id} auth=${authMs}ms db=${dbMs}ms`, {
            echoes: echoesResult.data?.length,
            blocks: blocksResult.data?.length,
          });

          if (echoesResult.error) throw echoesResult.error;

          const rows = echoesResult.data ?? [];
          if (rows.length === 0) {
            console.log(`[perf] /api/echoes total ${Date.now() - handlerStart}ms (empty)`);
            return ok(req, env, request_id, { echoed: [] });
          }

          // Split block results: users I blocked + users who blocked me
          const blockedIds = new Set<string>();
          for (const r of blocksResult.data ?? []) {
            if (r.blocker_user_id === user_id) {
              blockedIds.add(r.blocked_user_id);
            } else if (r.blocked_user_id === user_id) {
              blockedIds.add(r.blocker_user_id);
            }
          }

          const echoed = rows
            .filter(r => !blockedIds.has(r.echoed_user_id))
            .map(r => ({
              user_id: r.echoed_user_id,
              created_at: r.created_at,
            }));

          console.log(`[perf] /api/echoes total ${Date.now() - handlerStart}ms`, { echoed: echoed.length });
          return ok(req, env, request_id, { echoed });
        }

        // GET /api/echoes/relations?user_ids=a,b,c - Check which of these I echo
        if (path === "/api/echoes/relations" && req.method === "GET") {
          const user_id = await requireAuth(req, env);

          const userIdsParam = url.searchParams.get("user_ids") || "";
          const userIds = userIdsParam
            .split(",")
            .map(s => s.trim())
            .filter(s => s.length > 0)
            .slice(0, 200);

          if (userIds.length === 0) {
            return ok(req, env, request_id, { echoed_user_ids: [] });
          }

          const { data: rows, error } = await sb(env)
            .from("echoes")
            .select("echoed_user_id")
            .eq("user_id", user_id)
            .in("echoed_user_id", userIds);
          if (error) throw error;

          const echoed_user_ids = (rows ?? []).map(r => r.echoed_user_id);

          return ok(req, env, request_id, { echoed_user_ids });
        }

        // GET /api/echoes/incoming_counts?user_ids=a,b,c — How many users echo each target
        if (path === "/api/echoes/incoming_counts" && req.method === "GET") {
          const handlerStart = Date.now();
          const callerId = await requireAuth(req, env);

          const raw = url.searchParams.get("user_ids") || "";
          const ids = [...new Set(
            raw.split(",").map(s => s.trim()).filter(Boolean)
          )].slice(0, 200);

          if (ids.length === 0) {
            throw new HttpError(400, "BAD_REQUEST", "user_ids is required");
          }

          // Query all echo rows targeting these user_ids (minimal column)
          const { data: rows, error } = await sb(env)
            .from("echoes")
            .select("echoed_user_id")
            .in("echoed_user_id", ids);
          if (error) throw error;

          // Build counts map: initialize all requested IDs to 0, then tally
          const counts: Record<string, number> = Object.fromEntries(ids.map(id => [id, 0]));
          for (const r of rows ?? []) {
            if (counts[r.echoed_user_id] !== undefined) {
              counts[r.echoed_user_id]++;
            }
          }

          console.log(`[perf] /api/echoes/incoming_counts rid=${request_id} ids=${ids.length} rows=${(rows ?? []).length} t=${Date.now() - handlerStart}ms`);
          return ok(req, env, request_id, { counts });
        }


        // =====================================================
        // ACCOUNTS — read-only account state (Step 1 foundation)
        // =====================================================

        // GET /api/accounts/me — returns claimed state for the current session
        if (path === "/api/accounts/me" && req.method === "GET") {
          const t0 = Date.now();
          const user_id = await requireAuth(req, env);
          const tAuth = Date.now();

          // KV-cached device→account_id resolution (same as POST /api/posts)
          const ACCT_CACHE_TTL = 300;
          const acctKvKey = `acct:dev:${user_id}`;
          let acctSrc = "db";
          let accountId: string | null = null;
          const tAcct = Date.now();
          try {
            const cached = await env.PROFILE_KV.get(acctKvKey);
            if (cached !== null) {
              acctSrc = "kv";
              accountId = cached === "__null__" ? null : cached;
            }
          } catch { /* KV read failed — fall through */ }

          if (acctSrc === "db") {
            const { data: binding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", user_id)
              .maybeSingle();
            accountId = binding?.account_id ? (binding as any).account_id : null;
            // Write-behind cache
            ctx.waitUntil(
              env.PROFILE_KV.put(acctKvKey, accountId ?? "__null__", { expirationTtl: ACCT_CACHE_TTL })
                .catch(() => {})
            );
          }
          const acctMs = Date.now() - tAcct;

          if (!accountId) {
            console.log(`[perf] /api/accounts/me`, JSON.stringify({ rid: request_id, auth_ms: tAuth - t0, acct_ms: acctMs, acct_src: acctSrc, total_ms: Date.now() - t0, claimed: false }));
            return ok(req, env, request_id, {
              claimed: false,
              account_id: null,
              teran_handle: null,
              personas: [],
            });
          }

          // Parallelize: fetch account details + personas simultaneously
          const tPar = Date.now();
          const [{ data: account }, { data: personas }] = await Promise.all([
            sb(env)
              .from("accounts")
              .select("id, teran_handle, created_at")
              .eq("id", accountId)
              .single(),
            sb(env)
              .from("account_personas")
              .select("persona_author_id, persona_name, persona_avatar, created_at")
              .eq("account_id", accountId)
              .order("created_at", { ascending: true }),
          ]);
          const parMs = Date.now() - tPar;

          if (!account) {
            return ok(req, env, request_id, {
              claimed: false,
              account_id: null,
              teran_handle: null,
              personas: [],
            });
          }

          const totalMs = Date.now() - t0;
          console.log(`[perf] /api/accounts/me`, JSON.stringify({ rid: request_id, auth_ms: tAuth - t0, acct_ms: acctMs, acct_src: acctSrc, parallel_ms: parMs, total_ms: totalMs, claimed: true }));

          return ok(req, env, request_id, {
            claimed: !!account.teran_handle,
            account_id: account.id,
            teran_handle: account.teran_handle || null,
            personas: (personas || []).map((p: any) => ({
              author_id: p.persona_author_id,
              name: p.persona_name,
              avatar: p.persona_avatar,
            })),
          });
        }

        // POST /api/accounts/check-handle — check if a Teran ID is available
        if (path === "/api/accounts/check-handle" && req.method === "POST") {
          const body = await req.json() as any;
          const handle = String(body?.handle || "").toLowerCase().trim();

          if (!handle) {
            return fail(req, env, request_id, 400, "missing_handle", "Handle is required");
          }
          if (!isValidHandle(handle)) {
            return ok(req, env, request_id, {
              available: false,
              reason: "Handle must be 3–30 characters, lowercase letters/numbers/periods/underscores, start and end with a letter or number.",
            });
          }

          const { data: existing } = await sb(env)
            .from("accounts")
            .select("id")
            .eq("teran_handle", handle)
            .maybeSingle();

          return ok(req, env, request_id, {
            available: !existing,
            reason: existing ? "This Teran ID is already taken." : null,
          });
        }

        // POST /api/accounts/claim — claim current guest session with Teran ID + password
        //
        // Migration approach: COMPATIBILITY MAPPING BRIDGE
        // - Creates account + binds device + stores handle/password
        // - Does NOT rewrite device_id in rooms/posts/membership tables
        // - JWT sub remains device_id (no token re-issue)
        // - All existing features continue using device_id unchanged
        // - Account tables serve as metadata for future cross-device login
        if (path === "/api/accounts/claim" && req.method === "POST") {
          const user_id = await requireAuth(req, env);
          const body = await req.json() as any;

          const handle = String(body?.teran_handle || "").toLowerCase().trim();
          const password = String(body?.password || "");

          // Validate handle
          if (!handle) {
            return fail(req, env, request_id, 400, "missing_handle", "Teran ID is required");
          }
          if (!isValidHandle(handle)) {
            return fail(req, env, request_id, 400, "invalid_handle",
              "Teran ID must be 3–30 characters, lowercase letters/numbers/periods/underscores, start and end with a letter or number.");
          }

          // Validate password
          if (!password || password.length < 8) {
            return fail(req, env, request_id, 400, "weak_password", "Password must be at least 8 characters");
          }
          if (password.length > 128) {
            return fail(req, env, request_id, 400, "password_too_long", "Password must be at most 128 characters");
          }

          // ── STEP 0: Validate & normalize personas BEFORE any DB writes ──
          const rawPersonas: Array<{ author_id?: string; name?: string; avatar?: string }> =
            body?.personas || [];

          // Normalize: dedupe by author_id, filter invalid entries
          const seenIds = new Set<string>();
          const validPersonas = rawPersonas.filter(p => {
            if (!p.author_id || typeof p.author_id !== "string" || p.author_id.trim().length === 0) return false;
            const aid = p.author_id.trim();
            if (seenIds.has(aid)) return false;
            seenIds.add(aid);
            return true;
          });

          const invalidCount = rawPersonas.length - validPersonas.length;
          console.log(`[AccountsClaimFix] claim request`, {
            rid: request_id, teran_handle: handle,
            rawPersonasCount: rawPersonas.length,
          });
          console.log(`[AccountsClaimFix] normalized personas`, {
            rid: request_id, rawCount: rawPersonas.length, validCount: validPersonas.length, invalidCount,
          });

          // Reject immediately if no valid personas — prevents half-claimed accounts
          if (validPersonas.length === 0) {
            console.warn(`[AccountsClaimFix] claim rejected`, {
              rid: request_id, reason: "no-valid-personas",
              teran_handle: handle, rawCount: rawPersonas.length,
            });
            return fail(req, env, request_id, 400, "no_personas",
              "This account could not be claimed because no valid personas were available to link. Please create a persona first.");
          }

          // Check if device is already claimed
          const { data: existingBinding } = await sb(env)
            .from("account_devices")
            .select("account_id")
            .eq("device_id", user_id)
            .maybeSingle();

          if (existingBinding) {
            // Check if that account already has a handle (already claimed)
            const { data: existingAccount } = await sb(env)
              .from("accounts")
              .select("teran_handle")
              .eq("id", existingBinding.account_id)
              .single();

            if (existingAccount?.teran_handle) {
              return fail(req, env, request_id, 409, "already_claimed",
                "This device is already linked to a claimed account.");
            }
          }

          // Check handle uniqueness
          const { data: handleTaken } = await sb(env)
            .from("accounts")
            .select("id")
            .eq("teran_handle", handle)
            .maybeSingle();

          if (handleTaken) {
            return fail(req, env, request_id, 409, "handle_taken", "This Teran ID is already taken.");
          }

          // Hash password
          const password_hash = await hashPassword(password);

          // ── STEP 1: Create account ──
          const account_id = crypto.randomUUID();
          const now = new Date().toISOString();

          const { error: accountErr } = await sb(env)
            .from("accounts")
            .insert({
              id: account_id,
              teran_handle: handle,
              password_hash,
              created_at: now,
              updated_at: now,
            } as any);

          if (accountErr) {
            // Handle race condition on unique handle
            if (accountErr.code === "23505") {
              return fail(req, env, request_id, 409, "handle_taken", "This Teran ID is already taken.");
            }
            console.error(`[AccountsClaimFix] account insert failed`, { rid: request_id, error: accountErr.message });
            return fail(req, env, request_id, 500, "internal", "Failed to create account");
          }

          // ── STEP 2: Bind current device ──
          const { error: deviceErr } = await sb(env)
            .from("account_devices")
            .upsert({
              account_id,
              device_id: user_id,
              created_at: now,
            } as any, { onConflict: "device_id" });

          if (deviceErr) {
            console.error(`[AccountsClaimFix] device bind failed, compensating`, {
              rid: request_id, error: deviceErr.message, account_id,
            });
            // Compensation: remove orphaned account
            await sb(env).from("accounts").delete().eq("id", account_id);
            return fail(req, env, request_id, 500, "internal", "Failed to bind device");
          }

          // ── Eagerly overwrite KV cache so POST /api/posts resolves the new account immediately ──
          // Without this, the stale "__null__" KV entry (from pre-claim browsing) would block
          // posting for up to 300s after successful claim.
          ctx.waitUntil(
            env.PROFILE_KV.put(`acct:dev:${user_id}`, account_id, { expirationTtl: 300 })
              .catch((e: any) => console.warn("[claim] KV acct cache invalidation failed", { rid: request_id, error: String(e) }))
          );

          // ── STEP 3: Insert persona rows (REQUIRED — already validated above) ──
          const personaRows = validPersonas.map(p => ({
            account_id,
            persona_author_id: p.author_id!.trim(),
            persona_name: p.name || null,
            persona_avatar: p.avatar || null,
            created_at: now,
          }));

          const { error: personaErr } = await sb(env)
            .from("account_personas")
            .upsert(personaRows as any, { onConflict: "account_id,persona_author_id" });

          if (personaErr) {
            console.error(`[AccountsClaimFix] persona upsert FAILED, compensating`, {
              rid: request_id, error: personaErr.message, code: personaErr.code,
              account_id, personaRowCount: personaRows.length,
            });
            // Compensation: remove account + device binding to avoid half-claimed state
            const { error: delDeviceErr } = await sb(env).from("account_devices").delete().eq("account_id", account_id);
            const { error: delAccountErr } = await sb(env).from("accounts").delete().eq("id", account_id);
            if (delDeviceErr || delAccountErr) {
              console.error(`[AccountsClaimFix] compensation delete failed`, {
                rid: request_id, account_id,
                deviceDeleteErr: delDeviceErr?.message || null,
                accountDeleteErr: delAccountErr?.message || null,
              });
            } else {
              console.log(`[AccountsClaimFix] compensation delete success`, {
                rid: request_id, account_id,
              });
            }
            return fail(req, env, request_id, 500, "persona_bind_failed",
              "Account was created but personas could not be linked. The account has been rolled back. Please try again.");
          }

          console.log(`[AccountsClaimFix] persona upsert success`, {
            rid: request_id, count: personaRows.length,
          });

          // ── STEP 4: Bridge teran_handle → user_profiles.teran_id ──
          // The UI reads teran_id from user_profiles keyed by author_id (NOT device_id).
          // Write teran_id into each bound persona's user_profiles row.
          try {
            const profileRows = personaRows.map(p => ({
              user_id: p.persona_author_id,
              teran_id: handle,
              updated_at: now,
            }));
            await sb(env)
              .from("user_profiles")
              .upsert(profileRows as any, { onConflict: "user_id" });

            // Invalidate profile KV cache for each persona so GET /api/profile returns fresh teran_id
            for (const p of personaRows) {
              ctx.waitUntil(
                env.PROFILE_KV.delete(`profile:${p.persona_author_id}`)
                  .catch((e: any) => console.error("[claim] KV delete failed", { rid: request_id, author_id: p.persona_author_id, error: String(e) }))
              );
            }
            console.log(`[AccountsClaimFix] bridged teran_id to user_profiles`, {
              rid: request_id, author_ids: personaRows.map(p => p.persona_author_id), teran_id: handle,
            });
          } catch (bridgeErr: any) {
            // Non-fatal: account is claimed, syncToBackend from frontend will also write
            console.warn(`[AccountsClaimFix] bridge write failed (non-fatal)`, {
              rid: request_id, error: bridgeErr?.message,
            });
          }

          console.log(`[AccountsClaimFix] claim completed`, {
            rid: request_id, account_id, teran_handle: handle,
            personasCount: personaRows.length,
          });

          // Return claimed account state
          return ok(req, env, request_id, {
            claimed: true,
            account_id,
            teran_handle: handle,
            personas: personaRows.map(p => ({
              author_id: p.persona_author_id,
              name: p.persona_name,
              avatar: p.persona_avatar,
            })),
          });
        }

        // POST /api/accounts/login — authenticate with Teran ID + password from a new device
        //
        // Public endpoint (no auth required — user has no token yet on a new device).
        // Reads or creates device_id from cookie, binds device to account, issues JWT.
        if (path === "/api/accounts/login" && req.method === "POST") {
          const body = await req.json() as any;
          const handle = String(body?.teran_handle || "").toLowerCase().trim();
          const password = String(body?.password || "");

          if (!handle) {
            return fail(req, env, request_id, 400, "missing_handle", "Teran ID is required");
          }
          if (!password) {
            return fail(req, env, request_id, 400, "missing_password", "Password is required");
          }

          // Look up account by handle
          const { data: account } = await sb(env)
            .from("accounts")
            .select("id, teran_handle, password_hash, created_at")
            .eq("teran_handle", handle)
            .maybeSingle();

          if (!account || !account.password_hash) {
            return fail(req, env, request_id, 401, "invalid_credentials", "Invalid Teran ID or password");
          }

          // Verify password
          const passwordOk = await verifyPassword(password, account.password_hash);
          if (!passwordOk) {
            return fail(req, env, request_id, 401, "invalid_credentials", "Invalid Teran ID or password");
          }

          // Resolve device_id: prefer existing cookie, else generate new
          let device_id = readDeviceIdFromCookie(req);
          const had_cookie = !!device_id;
          if (!device_id) device_id = crypto.randomUUID();

          // Bind device to account (upsert — safe for re-login on same device)
          const now = new Date().toISOString();
          const { error: bindErr } = await sb(env)
            .from("account_devices")
            .upsert({
              account_id: account.id,
              device_id,
              created_at: now,
            } as any, { onConflict: "device_id" });

          if (bindErr) {
            console.error(`[login] device bind failed:`, bindErr);
            return fail(req, env, request_id, 500, "internal", "Failed to bind device");
          }

          // Issue JWT with sub = device_id (same semantics as POST /api/identity)
          const nowSec = Math.floor(Date.now() / 1000);
          const token = await jwtSign(env, {
            sub: device_id,
            iat: nowSec,
            exp: nowSec + 60 * 60 * 24 * 365, // 1 year
          });

          // Fetch linked personas for client-side restore
          const { data: personas } = await sb(env)
            .from("account_personas")
            .select("persona_author_id, persona_name, persona_avatar, created_at")
            .eq("account_id", account.id)
            .order("created_at", { ascending: true });

          // Overlay latest identity from user_profiles (source of truth for name/avatar)
          const personaAuthorIds = (personas || []).map((p: any) => p.persona_author_id).filter(Boolean);
          let profileMap: Record<string, { display_name?: string; avatar?: string }> = {};
          if (personaAuthorIds.length > 0) {
            const { data: profiles } = await sb(env)
              .from("user_profiles")
              .select("user_id, display_name, avatar")
              .in("user_id", personaAuthorIds);
            for (const prof of (profiles || [])) {
              profileMap[(prof as any).user_id] = prof as any;
            }
          }

          // Fetch room memberships for client-side room list restore
          const { data: memberships } = await sb(env)
            .from("room_members")
            .select(`
              role,
              rooms:room_id (
                id, name, room_key, icon_key, emoji, visibility,
                thread_card_style, social_reply_mode,
                card_bg_color, card_text_color,
                card_glass_enabled, card_glass_style,
                card_bg_image_key, card_bg_image_opacity,
                like_color, like_visible, list_icon_shape, list_show_icons,
                room_bg_color, room_bg_image_key, room_bg_image_opacity
              )
            `)
            .eq("user_id", device_id);

          // Also fetch memberships under any other device_ids bound to this account
          // (rooms joined from a different device)
          const { data: otherDevices } = await sb(env)
            .from("account_devices")
            .select("device_id")
            .eq("account_id", account.id)
            .neq("device_id", device_id);

          let allRoomMemberships = (memberships || [])
            .filter((m: any) => m.rooms)
            .map((m: any) => ({ ...m.rooms, my_role: m.role }));

          // Merge memberships from other devices bound to same account
          // AND migrate them to the new device_id so subsequent queries work.
          if (otherDevices && otherDevices.length > 0) {
            const otherDeviceIds = otherDevices.map((d: any) => d.device_id);
            const { data: otherMemberships } = await sb(env)
              .from("room_members")
              .select(`
                room_id, role,
                rooms:room_id (
                  id, name, room_key, icon_key, emoji, visibility,
                  thread_card_style, social_reply_mode,
                  card_bg_color, card_text_color,
                  card_glass_enabled, card_glass_style,
                  card_bg_image_key, card_bg_image_opacity,
                  like_color, like_visible, list_icon_shape, list_show_icons,
                  room_bg_color, room_bg_image_key, room_bg_image_opacity
                )
              `)
              .in("user_id", otherDeviceIds);

            const existingRoomIds = new Set(allRoomMemberships.map((r: any) => r.id));
            // Collect sibling memberships to migrate to new device_id
            const toMigrate: { room_id: string; role: string }[] = [];
            for (const m of (otherMemberships || [])) {
              if ((m as any).rooms && !existingRoomIds.has((m as any).rooms.id)) {
                allRoomMemberships.push({ ...(m as any).rooms, my_role: (m as any).role });
                existingRoomIds.add((m as any).rooms.id);
                toMigrate.push({ room_id: (m as any).room_id, role: (m as any).role });
              }
            }

            // ── Durable migration: copy missing room_members to new device_id ──
            // Uses upsert on (room_id, user_id) to prevent duplicates.
            if (toMigrate.length > 0) {
              const rows = toMigrate.map(({ room_id, role }) => ({
                room_id,
                user_id: device_id,
                role,
                joined_at: now,
              }));
              const { error: migrateErr } = await sb(env)
                .from("room_members")
                .upsert(rows as any, { onConflict: "room_id,user_id", ignoreDuplicates: true });
              if (migrateErr) {
                console.warn(`[login] room_members migration failed:`, migrateErr.message);
              } else {
                console.log(`[login] migrated ${rows.length} room_members to device ${device_id}`);
              }
            }

            // ── Durable migration: reassign rooms.owner_id to new device_id ──
            // Rooms owned by any sibling device should now show under owner_id=me.
            const { error: ownerErr } = await sb(env)
              .from("rooms")
              .update({ owner_id: device_id } as any)
              .in("owner_id", otherDeviceIds);
            if (ownerErr) {
              console.warn(`[login] rooms.owner_id reassignment failed:`, ownerErr.message);
            } else {
              console.log(`[login] reassigned rooms.owner_id from sibling devices to ${device_id}`);
            }

            // ── Durable migration: copy echoes (follows) to new device_id ──
            // Echoes rows use (user_id, echoed_user_id) as the unique constraint.
            const { data: oldEchoes } = await sb(env)
              .from("echoes")
              .select("echoed_user_id, created_at")
              .in("user_id", otherDeviceIds);

            if (oldEchoes && oldEchoes.length > 0) {
              // Dedupe: keep earliest created_at per echoed_user_id
              const seen = new Map<string, string>();
              for (const e of oldEchoes) {
                const target = (e as any).echoed_user_id;
                const ts = (e as any).created_at;
                if (!seen.has(target) || ts < seen.get(target)!) {
                  seen.set(target, ts);
                }
              }
              const echoRows = [...seen.entries()]
                .filter(([target]) => target !== device_id) // never echo yourself
                .map(([target, ts]) => ({
                  user_id: device_id,
                  echoed_user_id: target,
                  created_at: ts,
                }));
              if (echoRows.length > 0) {
                const { error: echoErr } = await sb(env)
                  .from("echoes")
                  .upsert(echoRows as any, { onConflict: "user_id,echoed_user_id", ignoreDuplicates: true });
                if (echoErr) {
                  console.warn(`[login] echoes migration failed:`, echoErr.message);
                } else {
                  console.log(`[login] migrated ${echoRows.length} echoes to device ${device_id}`);
                }
              }
            }
          }

          console.log(`[AccountsLoginFix] login success`, {
            rid: request_id, teran_handle: handle, account_id: account.id,
            device_id, had_cookie, personasCount: (personas || []).length,
            roomsCount: allRoomMemberships.length, tokenIssued: true,
          });

          if ((personas || []).length === 0) {
            console.warn(`[AccountsLoginFix] login missing personas`, {
              rid: request_id, teran_handle: handle, account_id: account.id,
              personasCount: 0,
            });
          }

          const resp = ok(req, env, request_id, {
            claimed: true,
            account_id: account.id,
            teran_handle: account.teran_handle,
            token,
            personas: (personas || []).map((p: any) => {
              const prof = profileMap[p.persona_author_id];
              return {
                author_id: p.persona_author_id,
                name: (prof?.display_name || p.persona_name || "User"),
                avatar: (prof?.avatar || p.persona_avatar || null),
              };
            }),
            rooms: allRoomMemberships,
          });

          // Set/refresh the device cookie
          const origin = req.headers.get("Origin") || "";
          resp.headers.append("Set-Cookie", setDeviceIdCookie(origin, device_id));
          resp.headers.set("Cache-Control", "no-store");
          resp.headers.set("Pragma", "no-cache");
          return resp;
        }


        // ANALYTICS HEARTBEAT
        // =====================================================

        if (path === "/api/analytics/heartbeat" && req.method === "POST") {
          const user_id = await optionalAuth(req, env);
          if (!user_id) return new Response(null, { status: 204, headers: corsHeaders(req, env) });

          let is_pwa = false;
          let session_s = 0;
          try {
            const body = await req.json() as any;
            is_pwa = body?.is_pwa === true;
            session_s = Math.max(0, Math.min(Number(body?.session_s) || 0, 3600));
          } catch { /* malformed body — use defaults */ }

          ctx.waitUntil((async () => {
            try {
              // Dedup heartbeat
              await sb(env).from("analytics_heartbeats").upsert(
                { date: new Date().toISOString().slice(0, 10), user_id, is_pwa, session_s },
                { onConflict: "date,user_id" }
              );
              // Update daily aggregate
              await sb(env).rpc("upsert_daily_analytics", {
                p_date: new Date().toISOString().slice(0, 10),
                p_is_pwa: is_pwa,
                p_session_s: session_s,
              });
            } catch (e) {
              console.error("[analytics] heartbeat failed", String(e));
            }
          })());

          return new Response(null, { status: 204, headers: corsHeaders(req, env) });
        }

        // =====================================================
        // FEED CONFIG API
        // =====================================================

        const FEED_CONFIG_DEFAULTS = {
          recency_weight: 0.2,
          comment_weight: 5,
          like_weight: 1,
          echo_weight: 50,
          persona_weight: 15,
        };

        if (path === "/api/feed-config" && req.method === "GET") {
          const kvKey = "feed_config:v1";
          try {
            // KV cache (300s TTL)
            const cached = await env.PROFILE_KV.get(kvKey, "json");
            if (cached) return ok(req, env, request_id, cached);

            const { data, error } = await sb(env)
              .from("feed_config")
              .select("recency_weight, comment_weight, like_weight, echo_weight, persona_weight")
              .eq("id", 1)
              .maybeSingle();

            const result = data && !error ? data : FEED_CONFIG_DEFAULTS;

            ctx.waitUntil(
              env.PROFILE_KV.put(kvKey, JSON.stringify(result), { expirationTtl: 300 })
                .catch(() => { })
            );
            return ok(req, env, request_id, result);
          } catch {
            return ok(req, env, request_id, FEED_CONFIG_DEFAULTS);
          }
        }

        // =====================================================
        // USER PROFILE API (Stage 1: READ-ONLY)
        // =====================================================

        // Allowed persona_tags values: Mood IDs (new) + legacy genre IDs (backwards compat)
        const ALLOWED_PERSONA_TAG_IDS = new Set([
          // Mood IDs (primary — used by Mode+Mood filter system)
          'Happy', 'Laughing', 'Curious', 'Meh', 'Sad',
          'Anxious', 'Angry', 'Frustrated', 'Tired',
          // Legacy genre IDs (kept for existing stored values)
          'Chat', 'Learn', 'Tech', 'Work', 'Health',
          'Relationships', 'Society', 'Create', 'Sports',
        ]);

        // GET /api/profile?user_id=...
        if (path === "/api/profile" && req.method === "GET") {
          const tProfile = performance.now();
          const user_id = url.searchParams.get("user_id");
          const caller = req.headers.get("x-teran-caller") || "unknown";
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const PROFILE_CACHE_TTL = 300; // 5 minutes
          const kvKey = `profile:${user_id}`;

          // KV cache check — get as text first so we can measure parse separately
          const tKvGet = performance.now();
          let kvRaw: string | null = null;
          let kvMissReason: string = "null";
          try {
            kvRaw = await env.PROFILE_KV.get(kvKey, "text");
          } catch (e) {
            kvMissReason = "error:" + String(e).slice(0, 60);
          }
          const kvGetMs = performance.now() - tKvGet;

          // KV parse
          const tKvParse = performance.now();
          let cached: any = null;
          if (kvRaw) {
            try { cached = JSON.parse(kvRaw); } catch (_) { kvMissReason = "parse_error"; }
          } else if (kvMissReason === "null") {
            kvMissReason = "key_not_found";
          }
          const kvParseMs = performance.now() - tKvParse;

          if (cached) {
            const tTransform = performance.now();
            const result = { ...cached, persona_tags: cached.persona_tags ?? [] };
            const transformMs = performance.now() - tTransform;
            const totalMs = performance.now() - tProfile;
            console.log(`[perf] /api/profile`, JSON.stringify({ rid: request_id, user_id, cache: "HIT", kv_ms: +kvGetMs.toFixed(1), total_ms: +totalMs.toFixed(1), caller }));
            if (totalMs >= 300) {
              console.log(`[perf] /api/profile breakdown2`, JSON.stringify({
                rid: request_id, user_id, caller, cache: "HIT",
                kv_key_prefix: "profile:",
                kv_get_ms: +kvGetMs.toFixed(1),
                kv_parse_ms: +kvParseMs.toFixed(1),
                db_select_ms: 0, db_transform_ms: +transformMs.toFixed(1),
                kv_put_mode: "none", kv_put_ms: 0,
                total_ms: +totalMs.toFixed(1),
              }));
            }
            return ok(req, env, request_id, result);
          }

          // KV MISS — DB fallback
          const tDb = performance.now();
          const { data, error } = await sb(env)
            .from("user_profiles")
            .select("user_id, display_name, bio, avatar, persona_tags, teran_id")
            .eq("user_id", user_id)
            .maybeSingle();
          const dbMs = performance.now() - tDb;

          if (error) throw error;

          const tTransform = performance.now();
          const totalMs = performance.now() - tProfile;

          // Return empty profile if not found (don't throw)
          if (!data) {
            console.log(`[perf] /api/profile`, JSON.stringify({ rid: request_id, user_id, cache: "MISS", kv_ms: +kvGetMs.toFixed(1), db_ms: +dbMs.toFixed(1), total_ms: +totalMs.toFixed(1), found: false, caller }));
            if (totalMs >= 300) {
              console.log(`[perf] /api/profile breakdown2`, JSON.stringify({
                rid: request_id, user_id, caller, cache: "MISS",
                kv_miss_reason: kvMissReason, kv_key_prefix: "profile:",
                kv_get_ms: +kvGetMs.toFixed(1), kv_parse_ms: +kvParseMs.toFixed(1),
                db_select_ms: +dbMs.toFixed(1), db_transform_ms: 0,
                kv_put_mode: "none", kv_put_ms: 0,
                total_ms: +totalMs.toFixed(1),
              }));
            }
            return ok(req, env, request_id, {
              user_id,
              display_name: null,
              bio: null,
              avatar: null,
              persona_tags: [],
              teran_id: null,
            });
          }

          // KV set (fire-and-forget)
          const tKvPut = performance.now();
          ctx.waitUntil(
            env.PROFILE_KV.put(kvKey, JSON.stringify(data), { expirationTtl: PROFILE_CACHE_TTL })
              .catch((e: any) => console.error("[profile] KV put failed", { rid: request_id, user_id, error: String(e) }))
          );
          const kvPutEnqueueMs = performance.now() - tKvPut;
          const transformMs = performance.now() - tTransform;

          console.log(`[perf] /api/profile`, JSON.stringify({ rid: request_id, user_id, cache: "MISS", kv_ms: +kvGetMs.toFixed(1), db_ms: +dbMs.toFixed(1), total_ms: +totalMs.toFixed(1), found: true, caller }));
          if (totalMs >= 300) {
            console.log(`[perf] /api/profile breakdown2`, JSON.stringify({
              rid: request_id, user_id, caller, cache: "MISS",
              kv_miss_reason: kvMissReason, kv_key_prefix: "profile:",
              kv_get_ms: +kvGetMs.toFixed(1), kv_parse_ms: +kvParseMs.toFixed(1),
              db_select_ms: +dbMs.toFixed(1), db_transform_ms: +transformMs.toFixed(1),
              kv_put_mode: "async", kv_put_enqueue_ms: +kvPutEnqueueMs.toFixed(1),
              total_ms: +totalMs.toFixed(1),
            }));
          }
          return ok(req, env, request_id, {
            ...data,
            persona_tags: data.persona_tags ?? [],
          });
        }

        // PUT /api/profile (sync persona — DB-only, no KV)
        if (path === "/api/profile" && req.method === "PUT") {
          const p0 = performance.now();

          // AUTH GATE: require valid JWT. The JWT sub is the device_id.
          const jwt_device_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          // SECURITY: body user_id is the persona's author_id — do NOT trust it
          // for authorization. It must be validated against the caller's identity.
          const user_id = body?.user_id;

          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const trimmedUserId = user_id.trim();

          // OWNERSHIP CHECK: verify the caller is allowed to update this persona.
          // If trimmedUserId matches the JWT device_id, allow (self-profile).
          // Otherwise, check if the device is bound to an account that owns this persona.
          if (trimmedUserId !== jwt_device_id) {
            // Look up account binding for this device
            const { data: deviceBinding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", jwt_device_id)
              .maybeSingle();

            if (!deviceBinding?.account_id) {
              // Unclaimed device trying to update a persona that isn't its own device_id
              console.warn(`[profile-auth] REJECTED: unclaimed device ${jwt_device_id} tried to update persona ${trimmedUserId}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this profile");
            }

            // Claimed account: verify persona belongs to the same account
            const { data: personaBinding } = await sb(env)
              .from("account_personas")
              .select("persona_author_id")
              .eq("account_id", deviceBinding.account_id)
              .eq("persona_author_id", trimmedUserId)
              .maybeSingle();

            if (!personaBinding) {
              console.warn(`[profile-auth] REJECTED: device ${jwt_device_id} account ${deviceBinding.account_id} does not own persona ${trimmedUserId}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this profile");
            }
          }
          const incoming: Record<string, any> = {
            display_name: typeof body?.display_name === "string" ? body.display_name : "Anonymous",
            bio: typeof body?.bio === "string" ? body.bio : null,
            avatar: typeof body?.avatar === "string" ? body.avatar : null,
          };
          // Reject data URIs — avatar must be an R2 key or icon ID
          if (incoming.avatar && incoming.avatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "avatar must be a URL or key, not a data URI");
          }

          // ── teran_id validation ──
          if (body?.teran_id !== undefined) {
            if (body.teran_id === null || body.teran_id === "") {
              incoming.teran_id = null;
            } else if (typeof body.teran_id === "string") {
              const tid = body.teran_id.toLowerCase().trim();
              if (!/^[a-z0-9_]{3,20}$/.test(tid)) {
                throw new HttpError(422, "VALIDATION_ERROR", "teran_id must be 3-20 characters, lowercase letters, digits, and underscores only");
              }
              incoming.teran_id = tid;
            }
          }

          // ── Persona text length limits (must match frontend LIMITS constants) ──
          const LIMIT_PERSONA_NAME = 20;
          const LIMIT_PERSONA_BIO = 160;
          if (incoming.display_name && incoming.display_name.length > LIMIT_PERSONA_NAME) {
            throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_PERSONA_NAME} characters for name`);
          }
          if (incoming.bio && incoming.bio.length > LIMIT_PERSONA_BIO) {
            throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_PERSONA_BIO} characters for bio`);
          }

          // Validate persona_tags (optional field)
          if (body?.persona_tags !== undefined) {
            if (!Array.isArray(body.persona_tags)) {
              throw new HttpError(422, "VALIDATION_ERROR", "persona_tags must be an array");
            }
            const cleaned = [...new Set(
              body.persona_tags.map((x: any) => String(x).trim()).filter(Boolean)
            )].slice(0, 3);
            for (const t of cleaned) {
              if (!ALLOWED_PERSONA_TAG_IDS.has(t)) {
                throw new HttpError(422, "VALIDATION_ERROR", `invalid persona tag: ${t}`);
              }
            }
            incoming.persona_tags = cleaned;
          }
          const p1 = performance.now();

          console.log(`[profile-sync] incoming rid=${request_id} user=${trimmedUserId} dn=${incoming.display_name} avatar=${incoming.avatar?.slice(0, 30) ?? "null"}`);

          // ── DB read: minimal columns ──
          const { data: current, error: readErr } = await sb(env)
            .from("user_profiles")
            .select("display_name, bio, avatar, persona_tags, teran_id")
            .eq("user_id", trimmedUserId)
            .maybeSingle();
          const p2 = performance.now();

          if (readErr) throw readErr;

          // ── Compare: skip write if nothing changed ──
          const tagsMatch = incoming.persona_tags === undefined ||
            (current && JSON.stringify(current.persona_tags ?? []) === JSON.stringify(incoming.persona_tags));
          const teranIdMatch = incoming.teran_id === undefined ||
            (current && (current.teran_id ?? null) === (incoming.teran_id ?? null));
          if (
            current &&
            current.display_name === incoming.display_name &&
            (current.bio ?? null) === (incoming.bio ?? null) &&
            (current.avatar ?? null) === (incoming.avatar ?? null) &&
            tagsMatch &&
            teranIdMatch
          ) {
            console.log(`[profile-sync] skip rid=${request_id} reason=DB_MATCH user=${trimmedUserId}`);
            console.log(`[perf] profile breakdown rid=${request_id} parse=${(p1 - p0).toFixed(1)} db_read=${(p2 - p1).toFixed(1)} total=${(p2 - p0).toFixed(1)} decision=SKIP_WRITE`);
            return ok(req, env, request_id, { ok: true, changed: false });
          }

          // ── Changed or new user — upsert ──
          const { error: writeErr } = await sb(env)
            .from("user_profiles")
            .upsert(
              {
                user_id: trimmedUserId,
                ...incoming,
                updated_at: new Date().toISOString(),
              },
              { onConflict: "user_id" }
            );
          const p3 = performance.now();

          if (writeErr) {
            // Handle unique constraint violation on teran_id
            if ((writeErr as any)?.code === "23505" && String((writeErr as any)?.message ?? "").includes("teran_id")) {
              throw new HttpError(409, "CONFLICT", "teran_id is already taken");
            }
            throw writeErr;
          }

          // Invalidate profile KV cache after write
          ctx.waitUntil(
            env.PROFILE_KV.delete(`profile:${trimmedUserId}`)
              .catch((e: any) => console.error("[profile] KV delete failed", { rid: request_id, user_id: trimmedUserId, error: String(e) }))
          );

          // ── Keep account_personas snapshot in sync (fire-and-forget) ──
          // This prevents stale name/avatar from being returned by POST /api/accounts/login
          // when the user clears cache and re-logs in with their teran ID.
          ctx.waitUntil((async () => {
            try {
              const update: Record<string, any> = {};
              if (incoming.display_name) update.persona_name = incoming.display_name;
              if (incoming.avatar) update.persona_avatar = incoming.avatar;
              if (Object.keys(update).length === 0) return;

              await sb(env)
                .from("account_personas")
                .update(update as any)
                .eq("persona_author_id", trimmedUserId);
            } catch (e: any) {
              console.warn(`[profile-sync] account_personas sync failed (non-fatal)`, {
                rid: request_id, user_id: trimmedUserId, error: e?.message,
              });
            }
          })());

          console.log(`[profile-sync] write rid=${request_id} user=${trimmedUserId} dn=${incoming.display_name}`);
          console.log(`[perf] profile breakdown rid=${request_id} parse=${(p1 - p0).toFixed(1)} db_read=${(p2 - p1).toFixed(1)} db_write=${(p3 - p2).toFixed(1)} total=${(p3 - p0).toFixed(1)} decision=WRITE`);
          return ok(req, env, request_id, { ok: true, changed: true });
        }

        // =====================================================
        // USER DISCOVERY API (search + recommended)
        // =====================================================

        // Helper: clamp and validate limit param
        const clampLimit = (raw: string | null, defaultVal = 20, max = 50): number => {
          if (!raw) return defaultVal;
          const n = parseInt(raw, 10);
          if (isNaN(n) || n < 1) return defaultVal;
          return Math.min(n, max);
        };

        // Minimal safe field list for user discovery
        const USER_DISCOVERY_FIELDS = "user_id, display_name, avatar, persona_tags";

        // GET /api/users/search?q=...&limit=...
        if (path === "/api/users/search" && req.method === "GET") {
          const p0 = performance.now();
          const rawQ = url.searchParams.get("q");
          const q = typeof rawQ === "string" ? rawQ.trim() : "";

          if (q.length < 1 || q.length > 50) {
            throw new HttpError(400, "BAD_REQUEST", "q is required (1-50 chars)");
          }

          const lim = clampLimit(url.searchParams.get("limit"));

          // Sanitize wildcards in user input for ILIKE
          const safeQ = q.replace(/%/g, "\\%").replace(/_/g, "\\_");

          // 1) Prefix matches (display_name starts with q)
          const { data: prefixData, error: prefixErr } = await sb(env)
            .from("user_profiles")
            .select(USER_DISCOVERY_FIELDS)
            .ilike("display_name", `${safeQ}%`)
            .order("display_name", { ascending: true })
            .limit(lim);

          if (prefixErr) throw prefixErr;

          const p1 = performance.now();

          // 2) Contains matches (display_name contains q, excludes prefix dupes)
          const prefixIds = new Set((prefixData || []).map((u: any) => u.user_id));
          let containsData: any[] = [];

          if ((prefixData || []).length < lim) {
            const remaining = lim - (prefixData || []).length;
            const { data: cData, error: cErr } = await sb(env)
              .from("user_profiles")
              .select(USER_DISCOVERY_FIELDS)
              .ilike("display_name", `%${safeQ}%`)
              .order("display_name", { ascending: true })
              .limit(remaining + (prefixData || []).length); // fetch extra to filter dupes

            if (cErr) throw cErr;
            containsData = (cData || []).filter((u: any) => !prefixIds.has(u.user_id)).slice(0, remaining);
          }

          const p2 = performance.now();

          const users = [...(prefixData || []), ...containsData].map((u: any) => ({
            user_id: u.user_id,
            display_name: u.display_name,
            avatar: u.avatar,
            persona_tags: u.persona_tags ?? [],
          }));

          console.log(`[users/search] rid=${request_id} q="${q}" prefix=${(prefixData || []).length} contains=${containsData.length} total=${users.length} t_prefix=${(p1 - p0).toFixed(1)} t_contains=${(p2 - p1).toFixed(1)}`);
          return ok(req, env, request_id, { users });
        }

        // GET /api/users/recommended?limit=...
        if (path === "/api/users/recommended" && req.method === "GET") {
          const p0 = performance.now();
          const lim = clampLimit(url.searchParams.get("limit"));

          const { data, error } = await sb(env)
            .from("user_profiles")
            .select(USER_DISCOVERY_FIELDS)
            .order("created_at", { ascending: false })
            .limit(lim);

          if (error) throw error;

          const p1 = performance.now();

          const users = (data || []).map((u: any) => ({
            user_id: u.user_id,
            display_name: u.display_name,
            avatar: u.avatar,
            persona_tags: u.persona_tags ?? [],
          }));

          console.log(`[users/recommended] rid=${request_id} count=${users.length} t=${(p1 - p0).toFixed(1)}`);
          return ok(req, env, request_id, { users });
        }

        // =====================================================
        // PROFILE SETTINGS (tab visibility) API
        // =====================================================

        // GET /api/profile-settings?user_id=... — public, returns tab visibility flags
        if (path === "/api/profile-settings" && req.method === "GET") {
          const user_id = url.searchParams.get("user_id");
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const { data, error } = await sb(env)
            .from("profile_settings")
            .select("posts_public, threads_public, rooms_public")
            .eq("user_id", user_id.trim())
            .maybeSingle();

          if (error) throw error;

          // Return defaults if no row exists
          const settings = data ?? {
            posts_public: true,
            threads_public: true,
            rooms_public: true,
          };

          return ok(req, env, request_id, { settings });
        }

        // PUT /api/profile-settings — auth required, upsert own settings
        if (path === "/api/profile-settings" && req.method === "PUT") {
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const settings = {
            user_id,
            posts_public: typeof body?.posts_public === "boolean" ? body.posts_public : true,
            threads_public: typeof body?.threads_public === "boolean" ? body.threads_public : true,
            rooms_public: typeof body?.rooms_public === "boolean" ? body.rooms_public : true,
            saved_public: false, // always private
            updated_at: new Date().toISOString(),
          };

          const { error } = await sb(env)
            .from("profile_settings")
            .upsert(settings, { onConflict: "user_id" });

          if (error) throw error;

          console.log(`[profile-settings] upsert rid=${request_id} user=${user_id} posts=${settings.posts_public} threads=${settings.threads_public} rooms=${settings.rooms_public}`);

          return ok(req, env, request_id, {
            settings: {
              posts_public: settings.posts_public,
              threads_public: settings.threads_public,
              rooms_public: settings.rooms_public,
            },
          });
        }

        // =====================================================
        // PROFILE GALLERY API
        // =====================================================

        // GET /api/profile-gallery?user_id=...
        if (path === "/api/profile-gallery" && req.method === "GET") {
          const user_id = url.searchParams.get("user_id");
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const { data: row, error } = await sb(env)
            .from("profile_gallery")
            .select("user_id, slots")
            .eq("user_id", user_id)
            .single();

          // If no row exists, return empty slots
          if (error && error.code === "PGRST116") {
            return ok(req, env, request_id, { user_id, slots: [] });
          }
          if (error) throw error;

          return ok(req, env, request_id, {
            user_id: row.user_id,
            slots: row.slots ?? [],
          });
        }

        // PUT /api/profile-gallery
        if (path === "/api/profile-gallery" && req.method === "PUT") {
          // AUTH GATE: require valid JWT. The JWT sub is the device_id.
          const jwt_device_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          // SECURITY: body user_id is the persona's author_id — do NOT trust it
          // for authorization. It must be validated against the caller's identity.
          const user_id = body?.user_id;
          const slots = body?.slots;

          // Validate user_id
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const galleryUserId = user_id.trim();

          // OWNERSHIP CHECK: same logic as PUT /api/profile.
          if (galleryUserId !== jwt_device_id) {
            const { data: deviceBinding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", jwt_device_id)
              .maybeSingle();

            if (!deviceBinding?.account_id) {
              console.warn(`[gallery-auth] REJECTED: unclaimed device ${jwt_device_id} tried to update gallery for ${galleryUserId}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this gallery");
            }

            const { data: personaBinding } = await sb(env)
              .from("account_personas")
              .select("persona_author_id")
              .eq("account_id", deviceBinding.account_id)
              .eq("persona_author_id", galleryUserId)
              .maybeSingle();

            if (!personaBinding) {
              console.warn(`[gallery-auth] REJECTED: device ${jwt_device_id} account ${deviceBinding.account_id} does not own persona ${galleryUserId}`);
              throw new HttpError(403, "FORBIDDEN", "You do not own this gallery");
            }
          }

          // Validate slots
          if (!Array.isArray(slots)) {
            throw new HttpError(422, "VALIDATION_ERROR", "slots must be an array");
          }
          if (slots.length > 6) {
            throw new HttpError(422, "VALIDATION_ERROR", "slots cannot exceed 6 items");
          }
          for (const s of slots) {
            if (typeof s !== "string" || s.trim() === "") {
              throw new HttpError(422, "VALIDATION_ERROR", "Each slot must be a non-empty string");
            }
          }

          // Upsert: insert or update
          const { error } = await sb(env)
            .from("profile_gallery")
            .upsert(
              { user_id, slots, updated_at: new Date().toISOString() },
              { onConflict: "user_id" }
            );
          if (error) throw error;

          return ok(req, env, request_id, { user_id, slots });
        }

        // ============================================================
        // NEWS COMMENTS ENDPOINTS
        // ============================================================

        // GET /api/news/comments?news_id=<id>&limit=20&cursor=<ts>:<id>
        if (path === "/api/news/comments" && req.method === "GET") {
          const news_id = url.searchParams.get("news_id");
          if (!news_id || typeof news_id !== "string" || news_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "news_id query parameter is required");
          }

          // Pagination params
          const limit = clampPaginationLimit(url.searchParams.get("limit"), 20, 200);
          const cursor = parseCursor(url.searchParams.get("cursor"));

          // Try to get current user for liked_by_me
          let current_user_id: string | null = null;
          try {
            const auth = req.headers.get("Authorization") || "";
            const m = auth.match(/^Bearer\s+(.+)$/i);
            if (m) {
              const payload = await jwtVerify(env, m[1]);
              if (payload?.sub) current_user_id = payload.sub;
            }
          } catch { /* ignore auth errors for GET */ }

          // Fetch comments with keyset pagination
          let commentsQuery = sb(env)
            .from("news_comments")
            .select("*")
            .eq("news_id", news_id.trim());
          if (cursor) {
            commentsQuery = commentsQuery.or(
              `created_at.lt.${cursor.created_at},and(created_at.eq.${cursor.created_at},id.lt.${cursor.id})`
            );
          }
          const { data: comments, error } = await commentsQuery
            .order("created_at", { ascending: false })
            .order("id", { ascending: false })
            .limit(limit);
          if (error) throw error;

          const commentList = comments ?? [];
          if (commentList.length === 0) {
            return ok(req, env, request_id, { items: [], next_cursor: null });
          }

          // Get like counts, liked_by_me, and media in parallel
          const commentIds = commentList.map((c: any) => c.id);
          const [likesResult, userLikesResult, mediaResult] = await Promise.all([
            sb(env)
              .from("news_comment_likes")
              .select("comment_id")
              .in("comment_id", commentIds),
            current_user_id
              ? sb(env)
                .from("news_comment_likes")
                .select("comment_id")
                .in("comment_id", commentIds)
                .eq("user_id", current_user_id)
              : Promise.resolve({ data: [] }),
            sb(env)
              .from("media")
              .select("id, news_comment_id, type, key, thumb_key, width, height, bytes, duration_ms")
              .in("news_comment_id", commentIds),
          ]);

          const likeCounts: Record<number, number> = {};
          for (const like of likesResult.data ?? []) {
            likeCounts[like.comment_id] = (likeCounts[like.comment_id] || 0) + 1;
          }

          const likedByMe: Set<number> = new Set();
          for (const like of userLikesResult.data ?? []) {
            likedByMe.add(like.comment_id);
          }

          const mediaByComment: Record<number, any[]> = {};
          for (const m of mediaResult.data ?? []) {
            if (!mediaByComment[m.news_comment_id]) mediaByComment[m.news_comment_id] = [];
            mediaByComment[m.news_comment_id].push(m);
          }

          // Batch-fetch live profiles for identity overlay
          const newsCommentAuthorIds = [...new Set(commentList.map((c: any) => c.author_id).filter(Boolean))];
          let newsCommentProfileMap: Record<string, { display_name?: string; avatar?: string }> = {};
          if (newsCommentAuthorIds.length > 0) {
            const { data: profRows } = await sb(env)
              .from("user_profiles")
              .select("user_id, display_name, avatar")
              .in("user_id", newsCommentAuthorIds);
            for (const row of (profRows ?? []) as any[]) {
              newsCommentProfileMap[row.user_id] = { display_name: row.display_name, avatar: row.avatar };
            }
          }

          // Enrich comments with likes, media, and live identity overlay
          const enrichedComments = commentList.map((c: any) => {
            const prof = newsCommentProfileMap[c.author_id];
            return {
              ...c,
              author_name: prof?.display_name || c.author_name,
              author_avatar: prof?.avatar || c.author_avatar,
              like_count: likeCounts[c.id] || 0,
              liked_by_me: likedByMe.has(c.id),
              media: mediaByComment[c.id] || [],
            };
          });

          const next_cursor = buildNextCursor(commentList, limit);
          return ok(req, env, request_id, { items: enrichedComments, next_cursor });
        }

        // POST /api/news/comments - create a news comment
        if (path === "/api/news/comments" && req.method === "POST") {
          console.log("[NEWS COMMENT CREATE] hit");
          const user_id = await requireAuth(req, env);


          const body = (await req.json().catch(() => null)) as any;
          console.log("[NEWS COMMENT CREATE] body:", JSON.stringify(body));

          const news_url = typeof body?.news_url === "string" ? body.news_url.trim() : "";
          const content = typeof body?.content === "string" ? body.content.trim() : "";
          console.log("[DEBUG parent_comment_id RAW]", {
            raw: body?.parent_comment_id,
            raw_type: typeof body?.parent_comment_id,
            number_cast: Number(body?.parent_comment_id),
            is_null: body?.parent_comment_id === null,
            is_undefined: body?.parent_comment_id === undefined,
          });
          const parent_comment_id =
            body?.parent_comment_id != null ? Number(body.parent_comment_id) || null : null;
          const author_name = typeof body?.author_name === "string" ? body.author_name : null;
          const rawNewsAuthorAvatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;
          // Reject data URIs to prevent storing MB-sized base64 in DB
          if (rawNewsAuthorAvatar && rawNewsAuthorAvatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "author_avatar must be a URL, not a data URI");
          }
          const author_avatar = rawNewsAuthorAvatar;



          if (!news_url) {
            throw new HttpError(400, "BAD_REQUEST", "news_url is required");
          }
          // Allow content to be empty if media is provided (media-only comment)
          const mediaInput = Array.isArray(body?.media) ? body.media : [];
          if (!content && mediaInput.length === 0) {
            throw new HttpError(400, "BAD_REQUEST", "content or media is required");
          }

          // ── Text length limit (must match frontend LIMITS.COMMENT) ──
          const LIMIT_NEWS_COMMENT = 600;
          if (content.length > LIMIT_NEWS_COMMENT) {
            throw new HttpError(400, "TEXT_TOO_LONG", `Max ${LIMIT_NEWS_COMMENT} characters`);
          }

          // Validate media items (same rules as post media)
          const MAX_NC_IMAGES = 4;
          const MAX_NC_VIDEOS = 1;
          const validatedMedia: Array<{
            type: "image" | "video";
            key: string;
            thumb_key?: string | null;
            width?: number | null;
            height?: number | null;
            bytes?: number | null;
            duration_ms?: number | null;
          }> = [];

          let ncImageCount = 0;
          let ncVideoCount = 0;
          for (const m of mediaInput) {
            const mType = m?.type;
            const mKey = m?.key;
            const mThumbKey = m?.thumb_key;
            if (!mType || !mKey || typeof mKey !== "string" || !mKey.trim()) {
              throw new HttpError(422, "VALIDATION_ERROR", "Each media item must have type and key");
            }
            if (mType === "image") {
              ncImageCount++;
              if (ncImageCount > MAX_NC_IMAGES) {
                throw new HttpError(422, "VALIDATION_ERROR", `Maximum ${MAX_NC_IMAGES} images allowed`);
              }
              if (!mThumbKey || typeof mThumbKey !== "string" || !mThumbKey.trim()) {
                throw new HttpError(422, "VALIDATION_ERROR", "thumb_key is required for images");
              }
              validatedMedia.push({
                type: "image",
                key: mKey.trim(),
                thumb_key: mThumbKey.trim(),
                width: typeof m?.width === "number" ? m.width : null,
                height: typeof m?.height === "number" ? m.height : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
              });
            } else if (mType === "video") {
              ncVideoCount++;
              if (ncVideoCount > MAX_NC_VIDEOS) {
                throw new HttpError(422, "VALIDATION_ERROR", `Maximum ${MAX_NC_VIDEOS} video allowed`);
              }
              validatedMedia.push({
                type: "video",
                key: mKey.trim(),
                thumb_key: mThumbKey ? mThumbKey.trim() : null,
                bytes: typeof m?.bytes === "number" ? m.bytes : null,
                duration_ms: typeof m?.duration_ms === "number" ? m.duration_ms : null,
              });
            } else {
              throw new HttpError(422, "VALIDATION_ERROR", "Media type must be 'image' or 'video'");
            }
          }

          // Normalize URL and compute news_id
          const canonicalUrl = normalizeUrl(news_url);
          console.log("[NEWS COMMENT CREATE] canonicalUrl:", canonicalUrl);
          if (!canonicalUrl) {
            throw new HttpError(400, "BAD_REQUEST", "Invalid news_url (must be http/https)");
          }
          const news_id = await sha256Hex(canonicalUrl);
          console.log("[NEWS COMMENT CREATE] news_id:", news_id);

          // Insert comment
          const insertPayload = {
            news_id,
            news_url: canonicalUrl,
            user_id,
            author_id: user_id,
            author_name,
            author_avatar,
            content: content || "",
            parent_comment_id,
          };
          console.log("[NEWS COMMENT CREATE] insertPayload:", JSON.stringify(insertPayload));

          const { data, error } = await sb(env)
            .from("news_comments")
            .insert(insertPayload)
            .select("*")
            .single();

          if (error) {
            console.error("[NEWS COMMENT CREATE] Supabase error:", error.message, error.code, error.details, error.hint);
            throw error;
          }

          console.log("[NEWS COMMENT CREATE] success, id:", data?.id);

          // Insert media rows into unified 'media' table with news_comment_id
          let mediaRows: any[] = [];
          if (validatedMedia.length > 0) {
            const newsCommentId = data.id;
            const mediaInsert = validatedMedia.map((m) => ({
              news_comment_id: newsCommentId,
              type: m.type,
              key: m.key,
              thumb_key: m.thumb_key,
              width: m.width ?? null,
              height: m.height ?? null,
              bytes: m.bytes ?? null,
              duration_ms: m.duration_ms ?? null,
            }));
            const { data: insertedMedia, error: mediaError } = await sb(env)
              .from("media")
              .insert(mediaInsert)
              .select("*");
            if (mediaError) {
              console.error("[NEWS COMMENT CREATE] media insert error:", mediaError.message);
              throw mediaError;
            }
            mediaRows = insertedMedia ?? [];
            console.log("[NEWS COMMENT CREATE] media inserted:", mediaRows.length);
          }

          // ── Non-blocking notification for news_comment_reply ──
          if (parent_comment_id) {
            // Identity context available in reply handler scope
            const cookieHeader_reply = req.headers.get("cookie") ?? "";
            const deviceIdMatch_reply = cookieHeader_reply.match(/device_id=([^;]+)/);
            const deviceId_reply = deviceIdMatch_reply ? deviceIdMatch_reply[1] : null;

            console.log(`[news-notif:create][${request_id}] REPLY NOTIF BLOCK ENTERED`, {
              parent_comment_id,
              new_reply_id: data?.id,
              actor_user_id: user_id,
              jwtSub: user_id,
              deviceId: deviceId_reply,
              author_id: user_id,
              author_name,
            });
            try {
              const news_image_url_reply = typeof body?.news_image_url === "string" ? body.news_image_url : null;
              console.log(`[news-notif:create][${request_id}] news_image_url_reply:`, news_image_url_reply);
              const { data: parentComment, error: parentErr } = await sb(env)
                .from("news_comments")
                .select("user_id")
                .eq("id", parent_comment_id)
                .single();
              console.log(`[news-notif:create][${request_id}] parent lookup result:`, {
                parentComment,
                parentErr: parentErr ? { code: parentErr.code, message: parentErr.message } : null,
                recipientSource: 'news_comments.user_id WHERE id = parent_comment_id',
                resolvedRecipientId: parentComment?.user_id ?? null,
                resolvedRecipientIdType: typeof parentComment?.user_id,
                resolvedRecipientIdLength: parentComment?.user_id?.length,
              });
              if (parentComment && parentComment.user_id) {
                console.log(`[news-notif:create][${request_id}] REPLY identity comparison`, {
                  actorId: user_id,
                  recipientId: parentComment.user_id,
                  areSame: user_id === parentComment.user_id,
                  actorIdType: typeof user_id,
                  recipientIdType: typeof parentComment.user_id,
                });
                const notifPayload = {
                  recipient_user_id: parentComment.user_id,
                  actor_user_id: user_id,
                  actor_name: author_name,
                  actor_avatar: author_avatar,
                  type: "news_comment_reply" as const,
                  comment_id: data.id,
                  parent_comment_id,
                  news_id,
                  news_url: canonicalUrl,
                  news_image_url: news_image_url_reply,
                  group_key: `ncr:${parent_comment_id}`,
                  snippet: content ? content.slice(0, 80) : null,
                };
                console.log(`[news-notif:create][${request_id}] reply deep-link`, { type: 'news_comment_reply', comment_id: data.id, news_id, news_url: canonicalUrl });
                console.log(`[news-notif:create][${request_id}] calling createNotification for reply`, JSON.stringify(notifPayload));
                await createNotification(env, notifPayload, request_id);
                console.log(`[news-notif:create][${request_id}] ✓ createNotification returned for reply`);
              } else {
                console.log(`[news-notif:create][${request_id}] ✗ SKIPPED reply notif: no parentComment or user_id`);
              }
            } catch (notifErr: any) {
              console.error(`[news-notif:create][${request_id}] ✗ news_comment_reply notification THREW`, {
                message: notifErr?.message,
                stack: notifErr?.stack,
              });
            }
          }

          return ok(req, env, request_id, {
            comment: { ...data, like_count: 0, liked_by_me: false, media: mediaRows }
          }, 201);
        }

        // DELETE /api/news/comments/:id
        {
          const m = path.match(/^\/api\/news\/comments\/(\d+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const commentId = Number(m[1]);

            // Check ownership
            const { data: existing, error: fetchError } = await sb(env)
              .from("news_comments")
              .select("id, user_id")
              .eq("id", commentId)
              .single();

            if (fetchError || !existing) {
              throw new HttpError(404, "NOT_FOUND", "Comment not found");
            }
            if (existing.user_id !== user_id) {
              throw new HttpError(403, "FORBIDDEN", "You can only delete your own comments");
            }

            // Delete
            const { error } = await sb(env)
              .from("news_comments")
              .delete()
              .eq("id", commentId);
            if (error) throw error;

            return new Response(null, { status: 204, headers: corsHeaders(req, env) });
          }
        }

        // POST /api/news/comments/:id/like (toggle like)
        {
          const m = path.match(/^\/api\/news\/comments\/(\d+)\/like$/);
          if (m && req.method === "POST") {
            const user_id = await requireAuth(req, env);
            const comment_id = Number(m[1]);

            // Parse optional body for actor identity & news thumbnail
            const likeBody = (await req.json().catch(() => null)) as any;
            const news_image_url = typeof likeBody?.news_image_url === "string" ? likeBody.news_image_url : null;

            if (!Number.isFinite(comment_id)) {
              throw new HttpError(400, "BAD_REQUEST", "Invalid comment_id");
            }

            // Toggle: try insert, if already exists then delete (unlike)
            const { error: insertError } = await sb(env)
              .from("news_comment_likes")
              .insert({ comment_id, user_id });

            if (insertError && insertError.code === "23505") {
              // Already liked, so unlike
              const { error: deleteError } = await sb(env)
                .from("news_comment_likes")
                .delete()
                .eq("comment_id", comment_id)
                .eq("user_id", user_id);
              if (deleteError) throw deleteError;
              return ok(req, env, request_id, { liked: false });
            }

            if (insertError) throw insertError;

            // ── Non-blocking notification for news_comment_like ──
            // Identity context available in like handler scope
            const cookieHeader_like = req.headers.get("cookie") ?? "";
            const deviceIdMatch_like = cookieHeader_like.match(/device_id=([^;]+)/);
            const deviceId_like = deviceIdMatch_like ? deviceIdMatch_like[1] : null;

            console.log(`[news-notif:create][${request_id}] LIKE NOTIF BLOCK ENTERED`, {
              comment_id,
              actor_user_id: user_id,
              jwtSub: user_id,
              deviceId: deviceId_like,
              news_image_url,
            });
            try {
              const { data: commentData, error: commentErr } = await sb(env)
                .from("news_comments")
                .select("user_id, news_id, news_url, content")
                .eq("id", comment_id)
                .single();
              console.log(`[news-notif:create][${request_id}] comment lookup result:`, {
                commentData: commentData ? { user_id: commentData.user_id, news_id: commentData.news_id } : null,
                commentErr: commentErr ? { code: commentErr.code, message: commentErr.message } : null,
                recipientSource: 'news_comments.user_id WHERE id = comment_id',
                resolvedRecipientId: commentData?.user_id ?? null,
                resolvedRecipientIdType: typeof commentData?.user_id,
                resolvedRecipientIdLength: commentData?.user_id?.length,
              });
              if (commentData && commentData.user_id) {
                console.log(`[news-notif:create][${request_id}] LIKE identity comparison`, {
                  actorId: user_id,
                  recipientId: commentData.user_id,
                  areSame: user_id === commentData.user_id,
                  actorIdType: typeof user_id,
                  recipientIdType: typeof commentData.user_id,
                });
                // Resolve actor identity: body (primary) → user_profiles (fallback)
                const bodyActorName = typeof likeBody?.author_name === "string" ? likeBody.author_name : null;
                const bodyActorAvatar = typeof likeBody?.author_avatar === "string" ? likeBody.author_avatar : null;

                let actorName: string | null = bodyActorName;
                let actorAvatar: string | null = bodyActorAvatar;
                let actorSource = "request_body";

                if (!actorName && !actorAvatar) {
                  // Fallback: lookup user_profiles
                  const { data: profile, error: profileErr } = await sb(env)
                    .from("user_profiles")
                    .select("display_name, avatar")
                    .eq("user_id", user_id)
                    .single();
                  console.log(`[news-notif:create][${request_id}] profile fallback lookup:`, {
                    profile: profile ? { display_name: profile.display_name } : null,
                    profileErr: profileErr ? { code: profileErr.code, message: profileErr.message } : null,
                  });
                  if (profile) {
                    actorName = profile.display_name ?? null;
                    actorAvatar = profile.avatar ?? null;
                    actorSource = "user_profiles";
                  } else {
                    actorSource = "none";
                  }
                }

                console.log(`[news-notif:create][${request_id}] LIKE actor identity resolved`, {
                  actorId: user_id,
                  actorName,
                  actorAvatar,
                  actorSource,
                });

                const notifPayload = {
                  recipient_user_id: commentData.user_id,
                  actor_user_id: user_id,
                  actor_name: actorName,
                  actor_avatar: actorAvatar,
                  type: "news_comment_like" as const,
                  comment_id,
                  news_id: commentData.news_id,
                  news_url: commentData.news_url,
                  news_image_url,
                  group_key: `ncl:${comment_id}`,
                };
                console.log(`[news-notif:create][${request_id}] like deep-link`, { type: 'news_comment_like', comment_id, news_id: commentData.news_id, news_url: commentData.news_url });
                console.log(`[news-notif:create][${request_id}] calling createNotification for like`, JSON.stringify(notifPayload));
                await createNotification(env, notifPayload, request_id);
                console.log(`[news-notif:create][${request_id}] createNotification returned for like`);
              } else {
                console.log(`[news-notif:create][${request_id}] SKIPPED like notif: no commentData or user_id`);
              }
            } catch (notifErr: any) {
              console.error(`[news-notif:create][${request_id}] news_comment_like notification THREW`, {
                message: notifErr?.message,
                stack: notifErr?.stack,
              });
            }

            return ok(req, env, request_id, { liked: true }, 201);
          }
        }

        // DELETE /api/news/comments/:id/like (unlike)
        {
          const m = path.match(/^\/api\/news\/comments\/(\d+)\/like$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const comment_id = Number(m[1]);

            const { error } = await sb(env)
              .from("news_comment_likes")
              .delete()
              .eq("comment_id", comment_id)
              .eq("user_id", user_id);
            if (error) throw error;

            return ok(req, env, request_id, { ok: true });
          }
        }

        // GET /api/news/comments/counts?news_ids=id1,id2,...  (Cache API, 60s TTL)
        if (path === "/api/news/comments/counts" && req.method === "GET") {
          const NEWS_CACHE_TTL = 60; // seconds
          const t0 = Date.now();
          const rid = request_id;
          let idsCount = 0;
          try {
            const newsIdsParam = url.searchParams.get("news_ids") || "";
            const newsIds = newsIdsParam
              .split(",")
              .map(s => s.trim())
              .filter(s => s.length > 0)
              .slice(0, 200);
            idsCount = newsIds.length;

            if (newsIds.length === 0) {
              console.log(`[perf] news/comments/counts rid=${rid} cache=SKIP total=${Date.now() - t0}ms ids=0 error=0`);
              return ok(req, env, request_id, { counts: {} });
            }

            // Stable cache key: sorted IDs
            const sortedKey = [...newsIds].sort().join(",");
            const cacheKey = new Request(`https://cache.internal/news/comments/counts?ids=${sortedKey}`, { method: "GET" });
            const cache = caches.default;
            const cached = await cache.match(cacheKey);
            const tCache = Date.now();

            if (cached) {
              const hitBody = await cached.text();
              console.log(`[perf] news/comments/counts rid=${rid} cache=HIT total=${Date.now() - t0}ms ids=${idsCount} payloadBytes=${hitBody.length}`);
              return new Response(hitBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "HIT",
                  ...corsHeaders(req, env),
                },
              });
            }

            // Cache MISS — query DB
            const tDb0 = Date.now();
            const { data: rows, error } = await sb(env)
              .from("news_comments")
              .select("news_id")
              .in("news_id", newsIds);
            const tDb1 = Date.now();
            if (error) throw error;

            const countMap: Record<string, number> = {};
            for (const row of rows ?? []) {
              countMap[row.news_id] = (countMap[row.news_id] || 0) + 1;
            }

            const counts: Record<string, number> = {};
            for (const id of newsIds) {
              counts[id] = countMap[id] || 0;
            }
            const tEnd = Date.now();

            const responseBody = { counts, request_id };
            const body = JSON.stringify(responseBody);

            // Store in edge cache (fire-and-forget)
            ctx.waitUntil(
              cache.put(cacheKey, new Response(body, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": `public, max-age=${NEWS_CACHE_TTL}`,
                },
              }))
                .then(() => console.log(`[cache] news/comments/counts put ok rid=${rid} ids=${idsCount}`))
                .catch((err) => console.error(`[cache] news/comments/counts put fail rid=${rid}`, err))
            );

            console.log(`[perf] news/comments/counts rid=${rid} cache=MISS cacheCheck=${tCache - t0}ms db=${tDb1 - tDb0}ms transform=${tEnd - tDb1}ms total=${tEnd - t0}ms payloadBytes=${body.length} ids=${idsCount} error=0`);
            return new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "MISS",
                ...corsHeaders(req, env),
              },
            });
          } catch (err: any) {
            console.log(`[perf] news/comments/counts rid=${rid} total=${Date.now() - t0}ms ids=${idsCount} error=1 msg=${err?.message?.slice(0, 100)}`);
            throw err;
          }
        }

        // GET /api/news/comments/recent?news_ids=id1,id2,...&limit=10  (Cache API, 60s TTL)
        if (path === "/api/news/comments/recent" && req.method === "GET") {
          const NEWS_CACHE_TTL = 60; // seconds
          const t0 = Date.now();
          const rid = request_id;
          let idsCount = 0;
          let limitUsed = 10;
          try {
            const newsIdsParam = url.searchParams.get("news_ids") || "";
            const newsIds = newsIdsParam
              .split(",")
              .map(s => s.trim())
              .filter(s => s.length > 0)
              .slice(0, 100);
            idsCount = newsIds.length;

            const limitParam = url.searchParams.get("limit");
            let limit = 10;
            if (limitParam) {
              const parsed = Number(limitParam);
              if (Number.isFinite(parsed) && parsed > 0) {
                limit = Math.min(parsed, 50);
              }
            }
            limitUsed = limit;

            if (newsIds.length === 0) {
              console.log(`[perf] news/comments/recent rid=${rid} cache=SKIP total=${Date.now() - t0}ms ids=0 limit=${limitUsed} error=0`);
              return ok(req, env, request_id, { recent: {} });
            }

            // Stable cache key: sorted IDs + limit
            const sortedKey = [...newsIds].sort().join(",");
            const cacheKey = new Request(`https://cache.internal/news/comments/recent?ids=${sortedKey}&limit=${limit}`, { method: "GET" });
            const cache = caches.default;
            const cached = await cache.match(cacheKey);
            const tCache = Date.now();

            if (cached) {
              const hitBody = await cached.text();
              console.log(`[perf] news/comments/recent rid=${rid} cache=HIT total=${Date.now() - t0}ms ids=${idsCount} limit=${limitUsed} payloadBytes=${hitBody.length}`);
              return new Response(hitBody, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  "X-Cache": "HIT",
                  ...corsHeaders(req, env),
                },
              });
            }

            // Cache MISS — query DB
            const fetchLimit = newsIds.length * limit * 2;
            const tDb0 = Date.now();
            const { data: allComments, error } = await sb(env)
              .from("news_comments")
              .select("id, news_id, content, created_at")
              .in("news_id", newsIds)
              .order("created_at", { ascending: false })
              .limit(fetchLimit);
            const tDb1 = Date.now();
            if (error) throw error;

            const recent: Record<string, Array<{ id: number; content: string; created_at: string }>> = {};
            for (const id of newsIds) {
              recent[id] = [];
            }
            for (const c of allComments ?? []) {
              if (recent[c.news_id] && recent[c.news_id].length < limit) {
                recent[c.news_id].push({
                  id: c.id,
                  content: c.content,
                  created_at: c.created_at,
                });
              }
            }
            const tEnd = Date.now();

            const responseBody = { recent, request_id };
            const body = JSON.stringify(responseBody);

            // Store in edge cache (fire-and-forget)
            ctx.waitUntil(
              cache.put(cacheKey, new Response(body, {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": `public, max-age=${NEWS_CACHE_TTL}`,
                },
              }))
                .then(() => console.log(`[cache] news/comments/recent put ok rid=${rid} ids=${idsCount} limit=${limitUsed}`))
                .catch((err) => console.error(`[cache] news/comments/recent put fail rid=${rid}`, err))
            );

            console.log(`[perf] news/comments/recent rid=${rid} cache=MISS cacheCheck=${tCache - t0}ms db=${tDb1 - tDb0}ms transform=${tEnd - tDb1}ms total=${tEnd - t0}ms payloadBytes=${body.length} ids=${idsCount} limit=${limitUsed} rows=${(allComments ?? []).length} error=0`);
            return new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "MISS",
                ...corsHeaders(req, env),
              },
            });
          } catch (err: any) {
            console.log(`[perf] news/comments/recent rid=${rid} total=${Date.now() - t0}ms ids=${idsCount} limit=${limitUsed} error=1 msg=${err?.message?.slice(0, 100)}`);
            throw err;
          }
        }

        // --------- BBC RSS Proxy (Cache API, 120s TTL) ----------
        // GET /api/rss?category=<category>
        // Returns news articles in NewsData.io-compatible format from BBC RSS feeds
        if (path === "/api/rss" && req.method === "GET") {
          const RSS_CACHE_TTL = 120; // seconds
          const t0 = Date.now();

          // Category -> BBC RSS URL mapping (allowlist)
          const RSS_FEEDS: Record<string, string> = {
            technology: "http://feeds.bbci.co.uk/news/technology/rss.xml",
            world: "http://feeds.bbci.co.uk/news/world/rss.xml",
            business: "http://feeds.bbci.co.uk/news/business/rss.xml",
            science: "http://feeds.bbci.co.uk/news/science_and_environment/rss.xml",
            entertainment: "http://feeds.bbci.co.uk/news/entertainment_and_arts/rss.xml",
            sports: "http://feeds.bbci.co.uk/sport/rss.xml",
            health: "http://feeds.bbci.co.uk/news/health/rss.xml",
          };

          const category = url.searchParams.get("category")?.toLowerCase()?.trim() || "";

          // Validate category is in allowlist
          if (!category || !RSS_FEEDS[category]) {
            return new Response(JSON.stringify({
              status: "error",
              message: "Invalid category. Allowed: " + Object.keys(RSS_FEEDS).join(", "),
              request_id,
            }), {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                ...corsHeaders(req, env),
              },
            });
          }

          // ── Cache API: check edge cache first ──
          const cacheUrl = new URL("https://cache.internal/rss");
          cacheUrl.searchParams.set("category", category);
          const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
          const cache = caches.default;
          const cached = await cache.match(cacheKey);
          const tCache = Date.now();
          const colo = (req as any).cf?.colo || "unknown";

          if (cached) {
            const hitBody = await cached.text();
            console.log(`[perf] rss rid=${request_id} cache=HIT total=${Date.now() - t0}ms category=${category} payloadBytes=${hitBody.length} colo=${colo} key=${cacheKey.url}`);
            return new Response(hitBody, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "HIT",
                "X-Category": category,
                "Cache-Control": `public, max-age=${RSS_CACHE_TTL}`,
                ...corsHeaders(req, env),
              },
            });
          }

          // ── Cache MISS: fetch + parse upstream RSS ──
          const rssUrl = RSS_FEEDS[category];

          try {
            // Fetch RSS feed (with timeout)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

            const rssResponse = await fetch(rssUrl, {
              signal: controller.signal,
              headers: {
                "User-Agent": "Teran-News-Aggregator/1.0",
                "Accept": "application/rss+xml, application/xml, text/xml",
              },
            });
            clearTimeout(timeoutId);
            const tFetch = Date.now();

            if (!rssResponse.ok) {
              console.error(`[RSS] Fetch failed: ${rssUrl} -> ${rssResponse.status}`);
              return new Response(JSON.stringify({
                status: "error",
                message: "RSS fetch failed",
                request_id,
              }), {
                status: 502,
                headers: {
                  "Content-Type": "application/json",
                  "X-Request-Id": request_id,
                  ...corsHeaders(req, env),
                },
              });
            }

            const xmlText = await rssResponse.text();

            // Parse RSS XML (simple regex-based parser for RSS 2.0)
            const items: Array<{
              article_id: string;
              title: string;
              description: string;
              image_url: string | null;
              link: string;
              source_id: string;
              pubDate: string;
            }> = [];

            // Extract items from RSS
            const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
            let itemMatch;
            while ((itemMatch = itemRegex.exec(xmlText)) !== null && items.length < 50) {
              const itemXml = itemMatch[1];

              // Extract title
              const titleMatch = itemXml.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
              const title = titleMatch ? titleMatch[1].trim().replace(/<!\[CDATA\[|\]\]>/g, "") : "";

              // Extract description
              const descMatch = itemXml.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i);
              const description = descMatch ? descMatch[1].trim().replace(/<!\[CDATA\[|\]\]>/g, "") : "";

              // Extract link
              const linkMatch = itemXml.match(/<link>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i);
              const link = linkMatch ? linkMatch[1].trim().replace(/<!\[CDATA\[|\]\]>/g, "") : "";

              // Extract guid (fallback to link hash)
              const guidMatch = itemXml.match(/<guid[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/guid>/i);
              let article_id = guidMatch ? guidMatch[1].trim().replace(/<!\[CDATA\[|\]\]>/g, "") : "";
              if (!article_id && link) {
                // Generate hash from link
                const encoder = new TextEncoder();
                const data = encoder.encode(link);
                const hashBuffer = await crypto.subtle.digest("SHA-256", data);
                const hashArray = new Uint8Array(hashBuffer);
                article_id = Array.from(hashArray.slice(0, 8))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");
              }

              // Extract pubDate
              const pubDateMatch = itemXml.match(/<pubDate>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/pubDate>/i);
              let pubDate = "";
              if (pubDateMatch) {
                try {
                  const parsed = new Date(pubDateMatch[1].trim());
                  if (!isNaN(parsed.getTime())) {
                    pubDate = parsed.toISOString();
                  }
                } catch { /* ignore parse errors */ }
              }

              // Extract image from media:thumbnail or media:content
              let image_url: string | null = null;
              const mediaThumbnailMatch = itemXml.match(/<media:thumbnail[^>]*url=["']([^"']+)["'][^>]*\/?>/i);
              if (mediaThumbnailMatch) {
                image_url = mediaThumbnailMatch[1];
              } else {
                const mediaContentMatch = itemXml.match(/<media:content[^>]*url=["']([^"']+)["'][^>]*\/?>/i);
                if (mediaContentMatch) {
                  image_url = mediaContentMatch[1];
                }
              }

              // Skip items without title or link
              if (!title || !link) continue;

              items.push({
                article_id,
                title,
                description,
                image_url,
                link,
                source_id: "bbc",
                pubDate,
              });
            }

            // Sort by pubDate descending (newest first)
            items.sort((a, b) => {
              if (!a.pubDate && !b.pubDate) return 0;
              if (!a.pubDate) return 1;
              if (!b.pubDate) return -1;
              return new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime();
            });
            const tParse = Date.now();

            // DEBUG: log first parsed item to verify description extraction
            if (items.length > 0) {
              console.log(`[rss] PARSED_ITEM_0 rid=${request_id}`, JSON.stringify({
                title: items[0].title,
                description: items[0].description?.slice(0, 120),
                link: items[0].link,
                pubDate: items[0].pubDate,
              }));
            }

            // Build response body
            const body = JSON.stringify({
              status: "success",
              results: items,
              request_id,
            });

            // Store in Cache API (await to ensure entry is written before next request)
            const cacheResponse = new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "Cache-Control": `public, max-age=${RSS_CACHE_TTL}`,
              },
            });
            try {
              await cache.put(cacheKey, cacheResponse);
              console.log(`[cache] rss put ok category=${category} rid=${request_id} key=${cacheKey.url} colo=${colo}`);
            } catch (putErr: any) {
              console.error(`[cache] rss put fail category=${category} rid=${request_id}`, putErr);
            }

            const tEnd = Date.now();
            console.log(`[perf] rss rid=${request_id} cache=MISS category=${category} cacheCheck=${tCache - t0}ms fetch=${tFetch - tCache}ms parse=${tParse - tFetch}ms total=${tEnd - t0}ms payloadBytes=${body.length} items=${items.length} colo=${colo} key=${cacheKey.url}`);

            // Build response
            const response = new Response(body, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "MISS",
                "Cache-Control": `public, max-age=${RSS_CACHE_TTL}`,
                "X-Category": category,
                ...corsHeaders(req, env),
              },
            });

            return response;
          } catch (e: any) {
            console.error(`[RSS] Error for category=${category}:`, e?.message);
            return new Response(JSON.stringify({
              status: "error",
              message: "RSS fetch failed",
              request_id,
            }), {
              status: 502,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                ...corsHeaders(req, env),
              },
            });
          }
        }

        // ═══════════════════════════════════════════
        // ROOMS API
        // ═══════════════════════════════════════════

        const ROOM_CATEGORY_KEYS = new Set([
          'lounge', 'anime_manga', 'games', 'music', 'sports', 'creation',
          'tech_gadgets', 'local_region', 'work_career', 'politics', 'spiritual'
        ]);

        // GET /api/rooms — list public rooms, or rooms by owner_id
        if (path === "/api/rooms" && req.method === "GET") {
          const tListTotal = performance.now();
          const owner_id_param = url.searchParams.get("owner_id")?.trim() || null;

          let q = sb(env)
            .from("rooms")
            .select("id,room_key,name,description,emoji,icon_key,owner_id,visibility,read_policy,post_policy,category,created_at,header_bg_color,header_text_color,room_bg_color,card_bg_color,card_text_color,like_visible,header_font_size,header_font_family,room_type,thread_card_style,social_reply_mode,detail_bg_color,detail_card_bg_color,detail_card_text_color,detail_comment_bg_color,detail_comment_text_color,detail_accent_color,detail_comment_input_bg_color,detail_comment_input_text_color,detail_comment_bar_bg_color,detail_show_icons,list_show_icons,list_icon_shape,detail_icon_shape,header_bg_image_key,header_text_enabled,header_height,header_glass_enabled,header_glass_style,room_bg_image_key,room_bg_image_opacity,card_bg_image_key,card_bg_image_opacity,card_glass_enabled,card_glass_style,detail_bg_image_key,detail_bg_image_opacity,detail_card_bg_image_key,detail_card_bg_image_opacity,detail_card_glass_enabled,detail_card_glass_style,detail_comment_bg_image_key,detail_comment_bg_image_opacity,detail_comment_glass_enabled,detail_comment_glass_style,detail_comment_input_bg_image_key,detail_comment_input_bg_image_opacity,detail_comment_input_glass_enabled,detail_comment_input_glass_style,detail_comment_bar_bg_image_key,detail_comment_bar_bg_image_opacity,detail_comment_bar_glass_enabled,detail_comment_bar_glass_style,detail_like_visible,detail_like_color,detail_reply_icon_color,detail_reply_badge_bg_color,detail_reply_badge_glass_enabled");

          if (owner_id_param) {
            // Support "me" alias: resolve to the authenticated caller's user_id
            let resolvedOwnerId = owner_id_param;
            const callerId = await optionalAuth(req, env);
            if (owner_id_param === "me") {
              if (!callerId) throw new HttpError(401, "UNAUTHORIZED", "Auth required for owner_id=me");
              resolvedOwnerId = callerId;
            }

            q = q.eq("owner_id", resolvedOwnerId);

            // Owner sees all visibility levels; non-owners see only public
            const isOwner = !!callerId && callerId === resolvedOwnerId;
            if (!isOwner) {
              q = q.eq("visibility", "public");
            }
          } else {
            // Default: list all public rooms
            q = q.eq("visibility", "public");
          }

          // Optional category filter
          const categoryParam = url.searchParams.get("category")?.trim() || null;
          if (categoryParam) {
            if (!ROOM_CATEGORY_KEYS.has(categoryParam)) {
              throw new HttpError(400, "BAD_REQUEST", "Invalid category");
            }
            q = q.eq("category", categoryParam);
          }

          const paramsMs = performance.now() - tListTotal;

          const tDbRooms = performance.now();
          const { data, error } = await q
            .order("created_at", { ascending: false })
            .limit(100);
          const dbRoomsMs = performance.now() - tDbRooms;
          if (error) throw new Error(error.message);

          // Attach member_count per room via PostgREST HEAD count (zero rows transferred)
          const roomIds = (data || []).map((r: any) => r.id);
          let countMap: Record<string, number> = {};
          let dbCountsMs = 0;
          if (roomIds.length > 0) {
            const tDbCounts = performance.now();
            // Batch count: fetch just room_id column and count in JS
            // Use select + count approach with minimal payload
            const { data: memberRows } = await sb(env)
              .from("room_members")
              .select("room_id", { count: "exact", head: false })
              .in("room_id", roomIds);
            dbCountsMs = performance.now() - tDbCounts;
            if (memberRows) {
              for (const c of memberRows as any[]) {
                countMap[c.room_id] = (countMap[c.room_id] || 0) + 1;
              }
            }
          }

          const tTransform = performance.now();
          const rooms = (data || []).map((r: any) => ({
            ...r,
            member_count: countMap[r.id] || 0,
          }));
          const transformMs = performance.now() - tTransform;
          const totalMs = performance.now() - tListTotal;

          console.log(`[perf] /api/rooms(list) breakdown`, JSON.stringify({ rid: request_id, owner_id: owner_id_param || "none", category: categoryParam || "none", visibility_filter: owner_id_param ? "all" : "public", params_ms: +paramsMs.toFixed(1), db_rooms_ms: +dbRoomsMs.toFixed(1), db_counts_ms: +dbCountsMs.toFixed(1), transform_ms: +transformMs.toFixed(1), total_ms: +totalMs.toFixed(1), rows: rooms.length }));

          return ok(req, env, request_id, { rooms });
        }

        // GET /api/rooms/lookup — find room by room_key (unlisted discovery)
        if (path === "/api/rooms/lookup" && req.method === "GET") {
          console.log("[ROOM_LOOKUP] hit", { request_id, method: req.method, path, url: url.toString() });
          const key = url.searchParams.get("key")?.trim();
          console.log("[ROOM_LOOKUP] key:", key);
          if (!key) throw new HttpError(400, "VALIDATION_ERROR", "key is required");
          const { data, error } = await sb(env)
            .from("rooms")
            .select("id,room_key,name,description,icon_key")
            .eq("room_key", key)
            .maybeSingle();
          if (error) {
            console.log("[ROOM_LOOKUP] error", { key, message: error.message });
            throw new Error(error.message);
          }
          if (!data) {
            console.log("[ROOM_LOOKUP] not_found", { key });
            throw new HttpError(404, "NOT_FOUND", "Room not found");
          }
          console.log("[ROOM_LOOKUP] found", { id: (data as any).id, room_key: (data as any).room_key, name: (data as any).name });
          return ok(req, env, request_id, { room: data });
        }

        // GET /api/rooms/mine — authenticated user's joined/owned rooms
        if (path === "/api/rooms/mine" && req.method === "GET") {
          const user_id = await requireAuth(req, env);

          // Query room_members for this user, join rooms table for metadata
          const { data: memberships, error } = await sb(env)
            .from("room_members")
            .select(`
              role,
              rooms:room_id (
                id, name, room_key, icon_key, emoji, visibility,
                card_bg_color, card_text_color,
                thread_card_style, social_reply_mode,
                card_glass_enabled, card_glass_style,
                card_bg_image_key, card_bg_image_opacity,
                like_color, like_visible, list_icon_shape, list_show_icons,
                room_bg_color, room_bg_image_key, room_bg_image_opacity
              )
            `)
            .eq("user_id", user_id);

          if (error) throw new Error(error.message);

          // Flatten: each row has { role, rooms: { id, name, ... } }
          // Filter out rows where the room was deleted (rooms == null)
          const rooms = (memberships || [])
            .filter((m: any) => m.rooms)
            .map((m: any) => ({
              ...m.rooms,
              my_role: m.role,
            }));

          return ok(req, env, request_id, { rooms });
        }

        // GET /api/rooms/:id — room detail
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)$/);
          if (m && req.method === "GET") {
            const tTotal = performance.now();
            const roomId = m[1];
            const caller = req.headers.get("x-teran-caller") || "unknown";

            // 1) DB: fetch room (sequential — needed for visibility gate)
            const tDbRoom = performance.now();
            const { data: room, error } = await sb(env)
              .from("rooms")
              .select("*")
              .eq("id", roomId)
              .maybeSingle();
            const dbRoomMs = performance.now() - tDbRoom;
            if (error) throw new Error(error.message);
            if (!room) {
              const totalMs = performance.now() - tTotal;
              console.log(`[perf] /api/rooms/:id breakdown`, JSON.stringify({ rid: request_id, room_id: roomId, cache: "NONE", db_room_ms: +dbRoomMs.toFixed(1), db_counts_ms: 0, db_membership_ms: 0, transform_ms: 0, total_ms: +totalMs.toFixed(1), rows_room: 0, caller }));
              throw new HttpError(404, "NOT_FOUND", "Room not found");
            }

            // Private rooms: only members can see details (must check before parallel)
            if ((room as any).visibility === "private_invite_only") {
              const privCaller = await optionalAuth(req, env);
              if (!privCaller) throw new HttpError(404, "NOT_FOUND", "Room not found");
              const privRole = await checkRoomMembership(env, roomId, privCaller);
              if (!privRole) throw new HttpError(404, "NOT_FOUND", "Room not found");
            }

            // 2) Enrichment: fetch my_role only (member_count removed — unused by frontend)
            // my_role is needed for canPost (composer) on ALL room types
            const tEnrich = performance.now();
            const uid = await optionalAuth(req, env);
            const my_role: string | null = uid ? await checkRoomMembership(env, roomId, uid) : null;
            const enrichMs = performance.now() - tEnrich;

            const payload = {
              room: { ...(room as any) },
              my_role,
            };
            const payloadBytes = JSON.stringify(payload).length;
            const totalMs = performance.now() - tTotal;

            console.log(`[perf] /api/rooms/:id breakdown`, JSON.stringify({ rid: request_id, room_id: roomId, cache: "NONE", db_room_ms: +dbRoomMs.toFixed(1), enrich_ms: +enrichMs.toFixed(1), total_ms: +totalMs.toFixed(1), rows_room: 1, payload_bytes: payloadBytes, caller }));

            return ok(req, env, request_id, payload);
          }
        }

        // POST /api/rooms — create room
        if (path === "/api/rooms" && req.method === "POST") {
          const tCreateTotal = performance.now();
          const user_id = await requireAuth(req, env);
          const tAuth = performance.now();

          // ── Teran ID gate: only claimed accounts can create rooms ──
          const { data: roomCreateDeviceBinding } = await sb(env)
            .from("account_devices")
            .select("account_id")
            .eq("device_id", user_id)
            .maybeSingle();
          if (!roomCreateDeviceBinding?.account_id) {
            throw new HttpError(403, "TERAN_ID_REQUIRED", "Create a Teran ID to make rooms");
          }

          const body = (await req.json().catch(() => null)) as any;
          const tBodyParse = performance.now();

          const name = typeof body?.name === "string" ? body.name.trim() : "";
          if (!name) throw new HttpError(422, "VALIDATION_ERROR", "name is required");
          if (name.length > 80) throw new HttpError(422, "VALIDATION_ERROR", "name max 80 chars");

          const description = typeof body?.description === "string" ? body.description.trim().slice(0, 500) : null;
          const icon_key = typeof body?.icon_key === "string" ? body.icon_key.trim() : null;
          if (icon_key && icon_key.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "icon_key must not be a data URI");
          }

          // Visibility: 'public' (default) | 'private'
          const ALLOWED_VISIBILITY = new Set(["public", "private"]);
          const visibility = typeof body?.visibility === "string" && ALLOWED_VISIBILITY.has(body.visibility)
            ? body.visibility
            : "public";

          // Category: required for public rooms, omitted for private
          const rawCategory = typeof body?.category === "string" ? body.category.trim() : null;
          let category: string | null = null;
          if (visibility === "public") {
            if (!rawCategory || !ROOM_CATEGORY_KEYS.has(rawCategory)) {
              throw new HttpError(422, "VALIDATION_ERROR", "category is required for public rooms and must be one of: " + [...ROOM_CATEGORY_KEYS].join(", "));
            }
            category = rawCategory;
          }
          // ── Design fields (optional, from Step 2) ──
          const design = (body?.design && typeof body.design === "object") ? body.design : {};
          const header_bg_color = typeof design.headerBgColor === "string" ? design.headerBgColor.slice(0, 20) : null;
          const header_text_color = typeof design.headerTextColor === "string" ? design.headerTextColor.slice(0, 20) : null;
          const room_bg_color = typeof design.roomBgColor === "string" ? design.roomBgColor.slice(0, 20) : null;
          const card_bg_color = typeof design.cardBgColor === "string" ? design.cardBgColor.slice(0, 20) : null;
          const card_text_color = typeof design.cardTextColor === "string" ? design.cardTextColor.slice(0, 20) : null;
          const like_visible = typeof design.likeVisible === "boolean" ? design.likeVisible : null;
          const like_color = typeof design.likeColor === "string" ? design.likeColor.slice(0, 20) : null;
          const header_font_size = typeof design.headerFontSize === "string" ? design.headerFontSize.slice(0, 10) : null;
          const header_font_family = typeof design.headerFontFamily === "string" ? design.headerFontFamily.slice(0, 60) : null;

          // ── Detail-page design fields (optional, for inside-thread customisation) ──
          const detail_bg_color = typeof design.detailBgColor === "string" ? design.detailBgColor.slice(0, 20) : null;
          const detail_card_bg_color = typeof design.detailCardBgColor === "string" ? design.detailCardBgColor.slice(0, 20) : null;
          const detail_card_text_color = typeof design.detailCardTextColor === "string" ? design.detailCardTextColor.slice(0, 20) : null;
          const detail_comment_bg_color = typeof design.detailCommentBgColor === "string" ? design.detailCommentBgColor.slice(0, 20) : null;
          const detail_comment_text_color = typeof design.detailCommentTextColor === "string" ? design.detailCommentTextColor.slice(0, 20) : null;
          const detail_accent_color = typeof design.detailAccentColor === "string" ? design.detailAccentColor.slice(0, 20) : null;
          const detail_comment_input_bg_color = typeof design.detailCommentInputBgColor === "string" ? design.detailCommentInputBgColor.slice(0, 20) : null;
          const detail_comment_input_text_color = typeof design.detailCommentInputTextColor === "string" ? design.detailCommentInputTextColor.slice(0, 20) : null;
          const detail_comment_bar_bg_color = typeof design.detailCommentBarBgColor === "string" ? design.detailCommentBarBgColor.slice(0, 20) : null;
          const detail_show_icons = typeof design.detailShowIcons === "boolean" ? design.detailShowIcons : null;
          const list_show_icons = typeof design.listShowIcons === "boolean" ? design.listShowIcons : null;
          const VALID_ICON_SHAPES = ["circle", "roundedSquare", "square", "hexagon", "squircle"];
          const list_icon_shape = typeof design.listIconShape === "string" && VALID_ICON_SHAPES.includes(design.listIconShape) ? design.listIconShape : null;
          const detail_icon_shape = typeof design.detailIconShape === "string" && VALID_ICON_SHAPES.includes(design.detailIconShape) ? design.detailIconShape : null;
          const header_bg_image_key = typeof design.headerBgImageKey === "string" && design.headerBgImageKey.length > 0 && design.headerBgImageKey.length <= 300 ? design.headerBgImageKey : null;
          const header_text_enabled = typeof design.headerTextEnabled === "boolean" ? design.headerTextEnabled : null;
          const VALID_HEADER_HEIGHTS = ["small", "medium", "large"];
          const header_height = typeof design.headerHeight === "string" && VALID_HEADER_HEIGHTS.includes(design.headerHeight) ? design.headerHeight : null;
          const room_bg_image_key = typeof design.roomBgImageKey === "string" && design.roomBgImageKey.length > 0 && design.roomBgImageKey.length <= 300 ? design.roomBgImageKey : null;
          const room_bg_image_opacity = room_bg_image_key && typeof design.roomBgImageOpacity === "number" && design.roomBgImageOpacity >= 0 && design.roomBgImageOpacity <= 1 ? design.roomBgImageOpacity : null;
          const card_bg_image_key = typeof design.cardBgImageKey === "string" && design.cardBgImageKey.length > 0 && design.cardBgImageKey.length <= 300 ? design.cardBgImageKey : null;
          const card_bg_image_opacity = card_bg_image_key && typeof design.cardBgImageOpacity === "number" && design.cardBgImageOpacity >= 0 && design.cardBgImageOpacity <= 1 ? design.cardBgImageOpacity : null;
          const card_glass_enabled = typeof design.cardGlassEnabled === "boolean" ? design.cardGlassEnabled : null;
          const VALID_GLASS_STYLES = ["frosted", "clear", "tinted"];
          const card_glass_style = typeof design.cardGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.cardGlassStyle) ? design.cardGlassStyle : null;
          const header_glass_enabled = typeof design.headerGlassEnabled === "boolean" ? design.headerGlassEnabled : null;
          const header_glass_style = typeof design.headerGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.headerGlassStyle) ? design.headerGlassStyle : null;

          // ── Step 3 detail image + glass fields ──
          const detail_bg_image_key = typeof design.detailBgImageKey === "string" && design.detailBgImageKey.length > 0 && design.detailBgImageKey.length <= 300 ? design.detailBgImageKey : null;
          const detail_bg_image_opacity = detail_bg_image_key && typeof design.detailBgImageOpacity === "number" && design.detailBgImageOpacity >= 0 && design.detailBgImageOpacity <= 1 ? design.detailBgImageOpacity : null;
          const detail_card_bg_image_key = typeof design.detailCardBgImageKey === "string" && design.detailCardBgImageKey.length > 0 && design.detailCardBgImageKey.length <= 300 ? design.detailCardBgImageKey : null;
          const detail_card_bg_image_opacity = detail_card_bg_image_key && typeof design.detailCardBgImageOpacity === "number" && design.detailCardBgImageOpacity >= 0 && design.detailCardBgImageOpacity <= 1 ? design.detailCardBgImageOpacity : null;
          const detail_card_glass_enabled = typeof design.detailCardGlassEnabled === "boolean" ? design.detailCardGlassEnabled : null;
          const detail_card_glass_style = typeof design.detailCardGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.detailCardGlassStyle) ? design.detailCardGlassStyle : null;
          const detail_comment_bg_image_key = typeof design.detailCommentBgImageKey === "string" && design.detailCommentBgImageKey.length > 0 && design.detailCommentBgImageKey.length <= 300 ? design.detailCommentBgImageKey : null;
          const detail_comment_bg_image_opacity = detail_comment_bg_image_key && typeof design.detailCommentBgImageOpacity === "number" && design.detailCommentBgImageOpacity >= 0 && design.detailCommentBgImageOpacity <= 1 ? design.detailCommentBgImageOpacity : null;
          const detail_comment_glass_enabled = typeof design.detailCommentGlassEnabled === "boolean" ? design.detailCommentGlassEnabled : null;
          const detail_comment_glass_style = typeof design.detailCommentGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.detailCommentGlassStyle) ? design.detailCommentGlassStyle : null;
          const detail_comment_input_bg_image_key = typeof design.detailCommentInputBgImageKey === "string" && design.detailCommentInputBgImageKey.length > 0 && design.detailCommentInputBgImageKey.length <= 300 ? design.detailCommentInputBgImageKey : null;
          const detail_comment_input_bg_image_opacity = detail_comment_input_bg_image_key && typeof design.detailCommentInputBgImageOpacity === "number" && design.detailCommentInputBgImageOpacity >= 0 && design.detailCommentInputBgImageOpacity <= 1 ? design.detailCommentInputBgImageOpacity : null;
          const detail_comment_input_glass_enabled = typeof design.detailCommentInputGlassEnabled === "boolean" ? design.detailCommentInputGlassEnabled : null;
          const detail_comment_input_glass_style = typeof design.detailCommentInputGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.detailCommentInputGlassStyle) ? design.detailCommentInputGlassStyle : null;
          const detail_comment_bar_bg_image_key = typeof design.detailCommentBarBgImageKey === "string" && design.detailCommentBarBgImageKey.length > 0 && design.detailCommentBarBgImageKey.length <= 300 ? design.detailCommentBarBgImageKey : null;
          const detail_comment_bar_bg_image_opacity = detail_comment_bar_bg_image_key && typeof design.detailCommentBarBgImageOpacity === "number" && design.detailCommentBarBgImageOpacity >= 0 && design.detailCommentBarBgImageOpacity <= 1 ? design.detailCommentBarBgImageOpacity : null;
          const detail_comment_bar_glass_enabled = typeof design.detailCommentBarGlassEnabled === "boolean" ? design.detailCommentBarGlassEnabled : null;
          const detail_comment_bar_glass_style = typeof design.detailCommentBarGlassStyle === "string" && VALID_GLASS_STYLES.includes(design.detailCommentBarGlassStyle) ? design.detailCommentBarGlassStyle : null;

          // ── Step 3 detail comment interaction fields ──
          const detail_like_visible = typeof design.detailLikeVisible === "boolean" ? design.detailLikeVisible : null;
          const detail_like_color = typeof design.detailLikeColor === "string" ? design.detailLikeColor.slice(0, 20) : null;
          const detail_reply_icon_color = typeof design.detailReplyIconColor === "string" ? design.detailReplyIconColor.slice(0, 20) : null;
          const detail_reply_badge_bg_color = typeof design.detailReplyBadgeBgColor === "string" ? design.detailReplyBadgeBgColor.slice(0, 20) : null;
          const detail_reply_badge_glass_enabled = typeof design.detailReplyBadgeGlassEnabled === "boolean" ? design.detailReplyBadgeGlassEnabled : null;

          // ── Room content type (top-level, not inside design) ──
          const VALID_ROOM_TYPES = ["post", "thread"];
          const VALID_CARD_STYLES = ["standard", "teran", "social"];
          const VALID_SOCIAL_REPLY_MODES = ["x", "reddit"];
          const room_type = typeof body?.room_type === "string" && VALID_ROOM_TYPES.includes(body.room_type) ? body.room_type : "post";
          const thread_card_style = typeof body?.thread_card_style === "string" && VALID_CARD_STYLES.includes(body.thread_card_style) ? body.thread_card_style : null;
          const social_reply_mode = typeof body?.social_reply_mode === "string" && VALID_SOCIAL_REPLY_MODES.includes(body.social_reply_mode) ? body.social_reply_mode : null;

          const tValidate = performance.now();

          // Generate random room_key (16 hex chars)
          const room_key = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
          const tKeygen = performance.now();

          const tDbInsertRoom = performance.now();
          const insertObj: Record<string, any> = {
            name, description, icon_key, category, room_key,
            owner_id: user_id,
            visibility, read_policy: "public", post_policy: "members_only",
          };
          // Only include design fields if they were provided
          if (header_bg_color !== null) insertObj.header_bg_color = header_bg_color;
          if (header_text_color !== null) insertObj.header_text_color = header_text_color;
          if (room_bg_color !== null) insertObj.room_bg_color = room_bg_color;
          if (card_bg_color !== null) insertObj.card_bg_color = card_bg_color;
          if (card_text_color !== null) insertObj.card_text_color = card_text_color;
          if (like_visible !== null) insertObj.like_visible = like_visible;
          if (like_color !== null) insertObj.like_color = like_color;
          if (header_font_size !== null) insertObj.header_font_size = header_font_size;
          if (header_font_family !== null) insertObj.header_font_family = header_font_family;
          if (detail_bg_color !== null) insertObj.detail_bg_color = detail_bg_color;
          if (detail_card_bg_color !== null) insertObj.detail_card_bg_color = detail_card_bg_color;
          if (detail_card_text_color !== null) insertObj.detail_card_text_color = detail_card_text_color;
          if (detail_comment_bg_color !== null) insertObj.detail_comment_bg_color = detail_comment_bg_color;
          if (detail_comment_text_color !== null) insertObj.detail_comment_text_color = detail_comment_text_color;
          if (detail_accent_color !== null) insertObj.detail_accent_color = detail_accent_color;
          if (detail_comment_input_bg_color !== null) insertObj.detail_comment_input_bg_color = detail_comment_input_bg_color;
          if (detail_comment_input_text_color !== null) insertObj.detail_comment_input_text_color = detail_comment_input_text_color;
          if (detail_comment_bar_bg_color !== null) insertObj.detail_comment_bar_bg_color = detail_comment_bar_bg_color;
          if (detail_show_icons !== null) insertObj.detail_show_icons = detail_show_icons;
          if (list_show_icons !== null) insertObj.list_show_icons = list_show_icons;
          if (list_icon_shape !== null) insertObj.list_icon_shape = list_icon_shape;
          if (detail_icon_shape !== null) insertObj.detail_icon_shape = detail_icon_shape;
          if (header_bg_image_key !== null) insertObj.header_bg_image_key = header_bg_image_key;
          if (header_text_enabled !== null) insertObj.header_text_enabled = header_text_enabled;
          if (header_height !== null) insertObj.header_height = header_height;
          if (room_bg_image_key !== null) insertObj.room_bg_image_key = room_bg_image_key;
          if (room_bg_image_opacity !== null) insertObj.room_bg_image_opacity = room_bg_image_opacity;
          if (card_bg_image_key !== null) insertObj.card_bg_image_key = card_bg_image_key;
          if (card_bg_image_opacity !== null) insertObj.card_bg_image_opacity = card_bg_image_opacity;
          if (card_glass_enabled !== null) insertObj.card_glass_enabled = card_glass_enabled;
          if (card_glass_style !== null) insertObj.card_glass_style = card_glass_style;
          if (header_glass_enabled !== null) insertObj.header_glass_enabled = header_glass_enabled;
          if (header_glass_style !== null) insertObj.header_glass_style = header_glass_style;
          if (detail_bg_image_key !== null) insertObj.detail_bg_image_key = detail_bg_image_key;
          if (detail_bg_image_opacity !== null) insertObj.detail_bg_image_opacity = detail_bg_image_opacity;
          if (detail_card_bg_image_key !== null) insertObj.detail_card_bg_image_key = detail_card_bg_image_key;
          if (detail_card_bg_image_opacity !== null) insertObj.detail_card_bg_image_opacity = detail_card_bg_image_opacity;
          if (detail_card_glass_enabled !== null) insertObj.detail_card_glass_enabled = detail_card_glass_enabled;
          if (detail_card_glass_style !== null) insertObj.detail_card_glass_style = detail_card_glass_style;
          if (detail_comment_bg_image_key !== null) insertObj.detail_comment_bg_image_key = detail_comment_bg_image_key;
          if (detail_comment_bg_image_opacity !== null) insertObj.detail_comment_bg_image_opacity = detail_comment_bg_image_opacity;
          if (detail_comment_glass_enabled !== null) insertObj.detail_comment_glass_enabled = detail_comment_glass_enabled;
          if (detail_comment_glass_style !== null) insertObj.detail_comment_glass_style = detail_comment_glass_style;
          if (detail_comment_input_bg_image_key !== null) insertObj.detail_comment_input_bg_image_key = detail_comment_input_bg_image_key;
          if (detail_comment_input_bg_image_opacity !== null) insertObj.detail_comment_input_bg_image_opacity = detail_comment_input_bg_image_opacity;
          if (detail_comment_input_glass_enabled !== null) insertObj.detail_comment_input_glass_enabled = detail_comment_input_glass_enabled;
          if (detail_comment_input_glass_style !== null) insertObj.detail_comment_input_glass_style = detail_comment_input_glass_style;
          if (detail_comment_bar_bg_image_key !== null) insertObj.detail_comment_bar_bg_image_key = detail_comment_bar_bg_image_key;
          if (detail_comment_bar_bg_image_opacity !== null) insertObj.detail_comment_bar_bg_image_opacity = detail_comment_bar_bg_image_opacity;
          if (detail_comment_bar_glass_enabled !== null) insertObj.detail_comment_bar_glass_enabled = detail_comment_bar_glass_enabled;
          if (detail_comment_bar_glass_style !== null) insertObj.detail_comment_bar_glass_style = detail_comment_bar_glass_style;
          if (detail_like_visible !== null) insertObj.detail_like_visible = detail_like_visible;
          if (detail_like_color !== null) insertObj.detail_like_color = detail_like_color;
          if (detail_reply_icon_color !== null) insertObj.detail_reply_icon_color = detail_reply_icon_color;
          if (detail_reply_badge_bg_color !== null) insertObj.detail_reply_badge_bg_color = detail_reply_badge_bg_color;
          if (detail_reply_badge_glass_enabled !== null) insertObj.detail_reply_badge_glass_enabled = detail_reply_badge_glass_enabled;
          insertObj.room_type = room_type;
          if (thread_card_style !== null) insertObj.thread_card_style = thread_card_style;
          if (social_reply_mode !== null) insertObj.social_reply_mode = social_reply_mode;

          const { data: room, error } = await sb(env)
            .from("rooms")
            .insert(insertObj)
            .select()
            .single();
          const dbInsertRoomMs = performance.now() - tDbInsertRoom;
          if (error) {
            console.log(`[perf] /api/rooms(create) error`, JSON.stringify({ rid: request_id, step: "db_room_insert", code: (error as any).code, message: error.message }));
            throw new Error(error.message);
          }

          // Auto-add owner as member (background — not blocking response)
          const tBgStart = performance.now();
          ctx.waitUntil(
            Promise.resolve(sb(env).from("room_members")
              .insert({ room_id: (room as any).id, user_id, role: "owner" }))
              .then(({ error: memErr }) => {
                if (memErr) console.error("[room_create] membership insert failed", { rid: request_id, room_id: (room as any).id, error: memErr.message });
                else console.log("[room_create] membership insert ok", { rid: request_id, room_id: (room as any).id, bg_ms: +(performance.now() - tBgStart).toFixed(1) });
              })
          );
          const bgEnqueueMs = performance.now() - tBgStart;

          const tResponse = performance.now();
          const totalMs = performance.now() - tCreateTotal;
          console.log(`[perf] /api/rooms(create) breakdown`, JSON.stringify({ rid: request_id, room_key, visibility, params_ms: +(tValidate - tCreateTotal).toFixed(1), db_insert_room_ms: +dbInsertRoomMs.toFixed(1), membership: "deferred", total_ms: +totalMs.toFixed(1) }));

          // Breakdown2: detailed spans (only when slow)
          if (totalMs >= 300) {
            console.log(`[perf] /api/rooms(create) breakdown2`, JSON.stringify({
              rid: request_id, me: user_id, room_key, visibility,
              auth_ms: +(tAuth - tCreateTotal).toFixed(1),
              body_parse_ms: +(tBodyParse - tAuth).toFixed(1),
              validate_ms: +(tValidate - tBodyParse).toFixed(1),
              keygen_ms: +(tKeygen - tValidate).toFixed(1),
              db_room_insert_ms: +dbInsertRoomMs.toFixed(1),
              membership_mode: "deferred",
              bg_enqueue_ms: +bgEnqueueMs.toFixed(1),
              response_ms: +(performance.now() - tResponse).toFixed(1),
              total_ms: +totalMs.toFixed(1),
            }));
          }

          // Enriched response: includes member_count + my_role so client can skip room-detail fetch
          return ok(req, env, request_id, { room: { ...(room as any), member_count: 1 }, my_role: "owner" }, 201);
        }

        // PATCH /api/rooms/:id — owner update
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)$/);
          if (m && req.method === "PATCH") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            // Verify ownership
            const ownerRole = await checkRoomMembership(env, roomId, user_id);
            if (ownerRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can update");

            const body = (await req.json().catch(() => null)) as any;
            const updates: Record<string, any> = {};

            if (typeof body?.name === "string") {
              const n = body.name.trim();
              if (!n) throw new HttpError(422, "VALIDATION_ERROR", "name cannot be empty");
              if (n.length > 80) throw new HttpError(422, "VALIDATION_ERROR", "name max 80 chars");
              updates.name = n;
            }
            if (body?.description !== undefined) {
              updates.description = typeof body.description === "string" ? body.description.trim().slice(0, 500) : null;
            }
            if (body?.emoji !== undefined) {
              updates.emoji = typeof body.emoji === "string" ? body.emoji.trim().slice(0, 8) : null;
            }
            if (body?.icon_key !== undefined) {
              const ik = typeof body.icon_key === "string" ? body.icon_key.trim() : null;
              if (ik && ik.startsWith("data:")) {
                throw new HttpError(422, "VALIDATION_ERROR", "icon_key must not be a data URI");
              }
              updates.icon_key = ik;
            }
            if (typeof body?.visibility === "string") {
              if (!["public", "private_invite_only"].includes(body.visibility)) {
                throw new HttpError(422, "VALIDATION_ERROR", "Invalid visibility value");
              }
              updates.visibility = body.visibility;
            }
            if (typeof body?.read_policy === "string") {
              if (!["public", "members_only"].includes(body.read_policy)) {
                throw new HttpError(422, "VALIDATION_ERROR", "Invalid read_policy value");
              }
              updates.read_policy = body.read_policy;
            }
            if (typeof body?.post_policy === "string") {
              if (!["public", "members_only"].includes(body.post_policy)) {
                throw new HttpError(422, "VALIDATION_ERROR", "Invalid post_policy value");
              }
              updates.post_policy = body.post_policy;
            }
            if (typeof body?.category === "string") {
              const cat = body.category.trim();
              if (!ROOM_CATEGORY_KEYS.has(cat)) {
                throw new HttpError(422, "VALIDATION_ERROR", "Invalid category");
              }
              updates.category = cat;
            }

            // ── Design fields ──
            const design = (body?.design && typeof body.design === "object") ? body.design : body;
            if (typeof design?.headerBgColor === "string" || typeof design?.header_bg_color === "string")
              updates.header_bg_color = (design.headerBgColor ?? design.header_bg_color).slice(0, 20);
            if (typeof design?.headerTextColor === "string" || typeof design?.header_text_color === "string")
              updates.header_text_color = (design.headerTextColor ?? design.header_text_color).slice(0, 20);
            if (typeof design?.roomBgColor === "string" || typeof design?.room_bg_color === "string")
              updates.room_bg_color = (design.roomBgColor ?? design.room_bg_color).slice(0, 20);
            if (typeof design?.cardBgColor === "string" || typeof design?.card_bg_color === "string")
              updates.card_bg_color = (design.cardBgColor ?? design.card_bg_color).slice(0, 20);
            if (typeof design?.cardTextColor === "string" || typeof design?.card_text_color === "string")
              updates.card_text_color = (design.cardTextColor ?? design.card_text_color).slice(0, 20);
            if (typeof design?.likeVisible === "boolean" || typeof design?.like_visible === "boolean")
              updates.like_visible = design.likeVisible ?? design.like_visible;
            if (typeof design?.likeColor === "string" || typeof design?.like_color === "string")
              updates.like_color = (design.likeColor ?? design.like_color).slice(0, 20);
            if (typeof design?.headerFontSize === "string" || typeof design?.header_font_size === "string")
              updates.header_font_size = (design.headerFontSize ?? design.header_font_size).slice(0, 10);
            if (typeof design?.headerFontFamily === "string" || typeof design?.header_font_family === "string")
              updates.header_font_family = (design.headerFontFamily ?? design.header_font_family).slice(0, 60);

            // ── Detail-page design fields ──
            if (typeof design?.detailBgColor === "string" || typeof design?.detail_bg_color === "string")
              updates.detail_bg_color = (design.detailBgColor ?? design.detail_bg_color).slice(0, 20);
            if (typeof design?.detailCardBgColor === "string" || typeof design?.detail_card_bg_color === "string")
              updates.detail_card_bg_color = (design.detailCardBgColor ?? design.detail_card_bg_color).slice(0, 20);
            if (typeof design?.detailCardTextColor === "string" || typeof design?.detail_card_text_color === "string")
              updates.detail_card_text_color = (design.detailCardTextColor ?? design.detail_card_text_color).slice(0, 20);
            if (typeof design?.detailCommentBgColor === "string" || typeof design?.detail_comment_bg_color === "string")
              updates.detail_comment_bg_color = (design.detailCommentBgColor ?? design.detail_comment_bg_color).slice(0, 20);
            if (typeof design?.detailCommentTextColor === "string" || typeof design?.detail_comment_text_color === "string")
              updates.detail_comment_text_color = (design.detailCommentTextColor ?? design.detail_comment_text_color).slice(0, 20);
            if (typeof design?.detailAccentColor === "string" || typeof design?.detail_accent_color === "string")
              updates.detail_accent_color = (design.detailAccentColor ?? design.detail_accent_color).slice(0, 20);
            if (typeof design?.detailCommentInputBgColor === "string" || typeof design?.detail_comment_input_bg_color === "string")
              updates.detail_comment_input_bg_color = (design.detailCommentInputBgColor ?? design.detail_comment_input_bg_color).slice(0, 20);
            if (typeof design?.detailCommentInputTextColor === "string" || typeof design?.detail_comment_input_text_color === "string")
              updates.detail_comment_input_text_color = (design.detailCommentInputTextColor ?? design.detail_comment_input_text_color).slice(0, 20);
            if (typeof design?.detailCommentBarBgColor === "string" || typeof design?.detail_comment_bar_bg_color === "string")
              updates.detail_comment_bar_bg_color = (design.detailCommentBarBgColor ?? design.detail_comment_bar_bg_color).slice(0, 20);
            if (typeof design?.detailShowIcons === "boolean" || typeof design?.detail_show_icons === "boolean")
              updates.detail_show_icons = design.detailShowIcons ?? design.detail_show_icons;
            if (typeof design?.listShowIcons === "boolean" || typeof design?.list_show_icons === "boolean")
              updates.list_show_icons = design.listShowIcons ?? design.list_show_icons;
            const VALID_ICON_SHAPES = ["circle", "roundedSquare", "square", "hexagon", "squircle"];
            if (typeof design?.listIconShape === "string" && VALID_ICON_SHAPES.includes(design.listIconShape))
              updates.list_icon_shape = design.listIconShape;
            else if (typeof design?.list_icon_shape === "string" && VALID_ICON_SHAPES.includes(design.list_icon_shape))
              updates.list_icon_shape = design.list_icon_shape;
            if (typeof design?.detailIconShape === "string" && VALID_ICON_SHAPES.includes(design.detailIconShape))
              updates.detail_icon_shape = design.detailIconShape;
            else if (typeof design?.detail_icon_shape === "string" && VALID_ICON_SHAPES.includes(design.detail_icon_shape))
              updates.detail_icon_shape = design.detail_icon_shape;
            // Header background image key (string or null to clear)
            if (typeof design?.headerBgImageKey === "string")
              updates.header_bg_image_key = design.headerBgImageKey.length > 0 && design.headerBgImageKey.length <= 300 ? design.headerBgImageKey : null;
            else if (typeof design?.header_bg_image_key === "string")
              updates.header_bg_image_key = design.header_bg_image_key.length > 0 && design.header_bg_image_key.length <= 300 ? design.header_bg_image_key : null;
            else if (design?.headerBgImageKey === null || design?.header_bg_image_key === null)
              updates.header_bg_image_key = null;
            // Header text visibility toggle
            if (typeof design?.headerTextEnabled === "boolean" || typeof design?.header_text_enabled === "boolean")
              updates.header_text_enabled = design.headerTextEnabled ?? design.header_text_enabled;
            // Header area height preset
            const VALID_HEADER_HEIGHTS = ["small", "medium", "large"];
            if (typeof design?.headerHeight === "string" && VALID_HEADER_HEIGHTS.includes(design.headerHeight))
              updates.header_height = design.headerHeight;
            else if (typeof design?.header_height === "string" && VALID_HEADER_HEIGHTS.includes(design.header_height))
              updates.header_height = design.header_height;
            // Room background image
            if (typeof design?.roomBgImageKey === "string" && design.roomBgImageKey.length > 0 && design.roomBgImageKey.length <= 300)
              updates.room_bg_image_key = design.roomBgImageKey;
            else if (typeof design?.room_bg_image_key === "string" && design.room_bg_image_key.length > 0)
              updates.room_bg_image_key = design.room_bg_image_key;
            else if (design?.roomBgImageKey === null || design?.room_bg_image_key === null)
              updates.room_bg_image_key = null;
            // Room background image opacity (only when image key is being set)
            if (updates.room_bg_image_key && typeof design?.roomBgImageOpacity === "number" && design.roomBgImageOpacity >= 0 && design.roomBgImageOpacity <= 1)
              updates.room_bg_image_opacity = design.roomBgImageOpacity;
            else if (updates.room_bg_image_key && typeof design?.room_bg_image_opacity === "number" && design.room_bg_image_opacity >= 0 && design.room_bg_image_opacity <= 1)
              updates.room_bg_image_opacity = design.room_bg_image_opacity;
            // Card background image
            if (typeof design?.cardBgImageKey === "string" && design.cardBgImageKey.length > 0 && design.cardBgImageKey.length <= 300)
              updates.card_bg_image_key = design.cardBgImageKey;
            else if (typeof design?.card_bg_image_key === "string" && design.card_bg_image_key.length > 0)
              updates.card_bg_image_key = design.card_bg_image_key;
            else if (design?.cardBgImageKey === null || design?.card_bg_image_key === null)
              updates.card_bg_image_key = null;
            // Card background image opacity (only when image key is being set)
            if (updates.card_bg_image_key && typeof design?.cardBgImageOpacity === "number" && design.cardBgImageOpacity >= 0 && design.cardBgImageOpacity <= 1)
              updates.card_bg_image_opacity = design.cardBgImageOpacity;
            else if (updates.card_bg_image_key && typeof design?.card_bg_image_opacity === "number" && design.card_bg_image_opacity >= 0 && design.card_bg_image_opacity <= 1)
              updates.card_bg_image_opacity = design.card_bg_image_opacity;
            // Card glass mode
            if (typeof design?.cardGlassEnabled === "boolean")
              updates.card_glass_enabled = design.cardGlassEnabled;
            else if (typeof design?.card_glass_enabled === "boolean")
              updates.card_glass_enabled = design.card_glass_enabled;
            // Card glass style
            const VALID_GLASS_STYLES_U = ["frosted", "clear", "tinted"];
            if (typeof design?.cardGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.cardGlassStyle))
              updates.card_glass_style = design.cardGlassStyle;
            else if (typeof design?.card_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.card_glass_style))
              updates.card_glass_style = design.card_glass_style;
            // Header glass mode
            if (typeof design?.headerGlassEnabled === "boolean")
              updates.header_glass_enabled = design.headerGlassEnabled;
            else if (typeof design?.header_glass_enabled === "boolean")
              updates.header_glass_enabled = design.header_glass_enabled;
            // Header glass style
            if (typeof design?.headerGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.headerGlassStyle))
              updates.header_glass_style = design.headerGlassStyle;
            else if (typeof design?.header_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.header_glass_style))
              updates.header_glass_style = design.header_glass_style;

            // ── Step 3 detail image + glass fields ──
            // Detail page background image
            if (typeof design?.detailBgImageKey === "string" && design.detailBgImageKey.length > 0 && design.detailBgImageKey.length <= 300)
              updates.detail_bg_image_key = design.detailBgImageKey;
            else if (typeof design?.detail_bg_image_key === "string" && design.detail_bg_image_key.length > 0)
              updates.detail_bg_image_key = design.detail_bg_image_key;
            else if (design?.detailBgImageKey === null || design?.detail_bg_image_key === null)
              updates.detail_bg_image_key = null;
            if (typeof design?.detailBgImageOpacity === "number" && design.detailBgImageOpacity >= 0 && design.detailBgImageOpacity <= 1)
              updates.detail_bg_image_opacity = design.detailBgImageOpacity;
            else if (typeof design?.detail_bg_image_opacity === "number" && design.detail_bg_image_opacity >= 0 && design.detail_bg_image_opacity <= 1)
              updates.detail_bg_image_opacity = design.detail_bg_image_opacity;
            // Detail card background image
            if (typeof design?.detailCardBgImageKey === "string" && design.detailCardBgImageKey.length > 0 && design.detailCardBgImageKey.length <= 300)
              updates.detail_card_bg_image_key = design.detailCardBgImageKey;
            else if (typeof design?.detail_card_bg_image_key === "string" && design.detail_card_bg_image_key.length > 0)
              updates.detail_card_bg_image_key = design.detail_card_bg_image_key;
            else if (design?.detailCardBgImageKey === null || design?.detail_card_bg_image_key === null)
              updates.detail_card_bg_image_key = null;
            if (typeof design?.detailCardBgImageOpacity === "number" && design.detailCardBgImageOpacity >= 0 && design.detailCardBgImageOpacity <= 1)
              updates.detail_card_bg_image_opacity = design.detailCardBgImageOpacity;
            else if (typeof design?.detail_card_bg_image_opacity === "number" && design.detail_card_bg_image_opacity >= 0 && design.detail_card_bg_image_opacity <= 1)
              updates.detail_card_bg_image_opacity = design.detail_card_bg_image_opacity;
            // Detail card glass
            if (typeof design?.detailCardGlassEnabled === "boolean")
              updates.detail_card_glass_enabled = design.detailCardGlassEnabled;
            else if (typeof design?.detail_card_glass_enabled === "boolean")
              updates.detail_card_glass_enabled = design.detail_card_glass_enabled;
            if (typeof design?.detailCardGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.detailCardGlassStyle))
              updates.detail_card_glass_style = design.detailCardGlassStyle;
            else if (typeof design?.detail_card_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.detail_card_glass_style))
              updates.detail_card_glass_style = design.detail_card_glass_style;
            // Comment background image
            if (typeof design?.detailCommentBgImageKey === "string" && design.detailCommentBgImageKey.length > 0 && design.detailCommentBgImageKey.length <= 300)
              updates.detail_comment_bg_image_key = design.detailCommentBgImageKey;
            else if (typeof design?.detail_comment_bg_image_key === "string" && design.detail_comment_bg_image_key.length > 0)
              updates.detail_comment_bg_image_key = design.detail_comment_bg_image_key;
            else if (design?.detailCommentBgImageKey === null || design?.detail_comment_bg_image_key === null)
              updates.detail_comment_bg_image_key = null;
            if (typeof design?.detailCommentBgImageOpacity === "number" && design.detailCommentBgImageOpacity >= 0 && design.detailCommentBgImageOpacity <= 1)
              updates.detail_comment_bg_image_opacity = design.detailCommentBgImageOpacity;
            else if (typeof design?.detail_comment_bg_image_opacity === "number" && design.detail_comment_bg_image_opacity >= 0 && design.detail_comment_bg_image_opacity <= 1)
              updates.detail_comment_bg_image_opacity = design.detail_comment_bg_image_opacity;
            // Comment glass
            if (typeof design?.detailCommentGlassEnabled === "boolean")
              updates.detail_comment_glass_enabled = design.detailCommentGlassEnabled;
            else if (typeof design?.detail_comment_glass_enabled === "boolean")
              updates.detail_comment_glass_enabled = design.detail_comment_glass_enabled;
            if (typeof design?.detailCommentGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.detailCommentGlassStyle))
              updates.detail_comment_glass_style = design.detailCommentGlassStyle;
            else if (typeof design?.detail_comment_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.detail_comment_glass_style))
              updates.detail_comment_glass_style = design.detail_comment_glass_style;
            // Input box background image
            if (typeof design?.detailCommentInputBgImageKey === "string" && design.detailCommentInputBgImageKey.length > 0 && design.detailCommentInputBgImageKey.length <= 300)
              updates.detail_comment_input_bg_image_key = design.detailCommentInputBgImageKey;
            else if (typeof design?.detail_comment_input_bg_image_key === "string" && design.detail_comment_input_bg_image_key.length > 0)
              updates.detail_comment_input_bg_image_key = design.detail_comment_input_bg_image_key;
            else if (design?.detailCommentInputBgImageKey === null || design?.detail_comment_input_bg_image_key === null)
              updates.detail_comment_input_bg_image_key = null;
            if (typeof design?.detailCommentInputBgImageOpacity === "number" && design.detailCommentInputBgImageOpacity >= 0 && design.detailCommentInputBgImageOpacity <= 1)
              updates.detail_comment_input_bg_image_opacity = design.detailCommentInputBgImageOpacity;
            else if (typeof design?.detail_comment_input_bg_image_opacity === "number" && design.detail_comment_input_bg_image_opacity >= 0 && design.detail_comment_input_bg_image_opacity <= 1)
              updates.detail_comment_input_bg_image_opacity = design.detail_comment_input_bg_image_opacity;
            // Input box glass
            if (typeof design?.detailCommentInputGlassEnabled === "boolean")
              updates.detail_comment_input_glass_enabled = design.detailCommentInputGlassEnabled;
            else if (typeof design?.detail_comment_input_glass_enabled === "boolean")
              updates.detail_comment_input_glass_enabled = design.detail_comment_input_glass_enabled;
            if (typeof design?.detailCommentInputGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.detailCommentInputGlassStyle))
              updates.detail_comment_input_glass_style = design.detailCommentInputGlassStyle;
            else if (typeof design?.detail_comment_input_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.detail_comment_input_glass_style))
              updates.detail_comment_input_glass_style = design.detail_comment_input_glass_style;
            // Input bar background image
            if (typeof design?.detailCommentBarBgImageKey === "string" && design.detailCommentBarBgImageKey.length > 0 && design.detailCommentBarBgImageKey.length <= 300)
              updates.detail_comment_bar_bg_image_key = design.detailCommentBarBgImageKey;
            else if (typeof design?.detail_comment_bar_bg_image_key === "string" && design.detail_comment_bar_bg_image_key.length > 0)
              updates.detail_comment_bar_bg_image_key = design.detail_comment_bar_bg_image_key;
            else if (design?.detailCommentBarBgImageKey === null || design?.detail_comment_bar_bg_image_key === null)
              updates.detail_comment_bar_bg_image_key = null;
            if (typeof design?.detailCommentBarBgImageOpacity === "number" && design.detailCommentBarBgImageOpacity >= 0 && design.detailCommentBarBgImageOpacity <= 1)
              updates.detail_comment_bar_bg_image_opacity = design.detailCommentBarBgImageOpacity;
            else if (typeof design?.detail_comment_bar_bg_image_opacity === "number" && design.detail_comment_bar_bg_image_opacity >= 0 && design.detail_comment_bar_bg_image_opacity <= 1)
              updates.detail_comment_bar_bg_image_opacity = design.detail_comment_bar_bg_image_opacity;
            // Input bar glass
            if (typeof design?.detailCommentBarGlassEnabled === "boolean")
              updates.detail_comment_bar_glass_enabled = design.detailCommentBarGlassEnabled;
            else if (typeof design?.detail_comment_bar_glass_enabled === "boolean")
              updates.detail_comment_bar_glass_enabled = design.detail_comment_bar_glass_enabled;
            if (typeof design?.detailCommentBarGlassStyle === "string" && VALID_GLASS_STYLES_U.includes(design.detailCommentBarGlassStyle))
              updates.detail_comment_bar_glass_style = design.detailCommentBarGlassStyle;
            else if (typeof design?.detail_comment_bar_glass_style === "string" && VALID_GLASS_STYLES_U.includes(design.detail_comment_bar_glass_style))
              updates.detail_comment_bar_glass_style = design.detail_comment_bar_glass_style;
            // Detail comment interaction fields
            if (typeof design?.detailLikeVisible === "boolean")
              updates.detail_like_visible = design.detailLikeVisible;
            else if (typeof design?.detail_like_visible === "boolean")
              updates.detail_like_visible = design.detail_like_visible;
            if (typeof design?.detailLikeColor === "string")
              updates.detail_like_color = design.detailLikeColor.slice(0, 20);
            else if (typeof design?.detail_like_color === "string")
              updates.detail_like_color = design.detail_like_color.slice(0, 20);
            if (typeof design?.detailReplyIconColor === "string")
              updates.detail_reply_icon_color = design.detailReplyIconColor.slice(0, 20);
            else if (typeof design?.detail_reply_icon_color === "string")
              updates.detail_reply_icon_color = design.detail_reply_icon_color.slice(0, 20);
            if (typeof design?.detailReplyBadgeBgColor === "string")
              updates.detail_reply_badge_bg_color = design.detailReplyBadgeBgColor.slice(0, 20);
            else if (typeof design?.detail_reply_badge_bg_color === "string")
              updates.detail_reply_badge_bg_color = design.detail_reply_badge_bg_color.slice(0, 20);
            if (typeof design?.detailReplyBadgeGlassEnabled === "boolean")
              updates.detail_reply_badge_glass_enabled = design.detailReplyBadgeGlassEnabled;
            else if (typeof design?.detail_reply_badge_glass_enabled === "boolean")
              updates.detail_reply_badge_glass_enabled = design.detail_reply_badge_glass_enabled;

            // ── Room content type (top-level fields) ──
            const VALID_ROOM_TYPES = ["post", "thread"];
            const VALID_CARD_STYLES = ["standard", "teran", "social"];
            const VALID_SOCIAL_REPLY_MODES = ["x", "reddit"];
            if (typeof body?.room_type === "string" && VALID_ROOM_TYPES.includes(body.room_type))
              updates.room_type = body.room_type;
            if (typeof body?.thread_card_style === "string" && VALID_CARD_STYLES.includes(body.thread_card_style))
              updates.thread_card_style = body.thread_card_style;
            if (typeof body?.social_reply_mode === "string" && VALID_SOCIAL_REPLY_MODES.includes(body.social_reply_mode))
              updates.social_reply_mode = body.social_reply_mode;
            else if (body?.social_reply_mode === null)
              updates.social_reply_mode = null;

            if (Object.keys(updates).length === 0) {
              throw new HttpError(422, "VALIDATION_ERROR", "No fields to update");
            }
            updates.updated_at = new Date().toISOString();

            const { data: room, error } = await sb(env)
              .from("rooms")
              .update(updates)
              .eq("id", roomId)
              .select()
              .single();
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { room });
          }
        }

        // DELETE /api/rooms/:id — owner-only hard delete (room + all content)
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)$/);
          if (m && req.method === "DELETE") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            // Verify ownership
            const ownerRole = await checkRoomMembership(env, roomId, user_id);
            if (ownerRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can delete");

            // Verify room exists
            const { data: room, error: roomErr } = await sb(env)
              .from("rooms")
              .select("id")
              .eq("id", roomId)
              .maybeSingle();
            if (roomErr) throw roomErr;
            if (!room) throw new HttpError(404, "NOT_FOUND", "Room not found");

            // Step 1: Collect all post IDs in this room
            const { data: roomPosts } = await sb(env)
              .from("posts")
              .select("id")
              .eq("room_id", roomId);
            const postIds = (roomPosts ?? []).map((p: any) => p.id);

            if (postIds.length > 0) {
              // Step 2: Delete notifications referencing these posts
              await sb(env)
                .from("notifications")
                .delete()
                .in("post_id", postIds);

              // Step 3: Delete post_likes (no FK cascade)
              await sb(env)
                .from("post_likes")
                .delete()
                .in("post_id", postIds);

              // Step 4: Delete comments on these posts
              await sb(env)
                .from("comments")
                .delete()
                .in("post_id", postIds);

              // Step 5: Hard-delete posts (media rows cascade via FK ON DELETE CASCADE)
              await sb(env)
                .from("posts")
                .delete()
                .eq("room_id", roomId);
            }

            // Step 6: Delete room row (room_members + room_invites cascade via FK)
            const { error: delErr } = await sb(env)
              .from("rooms")
              .delete()
              .eq("id", roomId);
            if (delErr) throw delErr;

            console.log(`[DELETE room] id=${roomId} owner=${user_id} posts_deleted=${postIds.length}`);
            return ok(req, env, request_id, { ok: true, posts_deleted: postIds.length });
          }
        }

        // ══════════════════════════════════════════════════════════════
        // Room Design Templates — DB-backed template CRUD
        // ══════════════════════════════════════════════════════════════

        // POST /api/room-design-templates — create a new template
        if (path === "/api/room-design-templates" && req.method === "POST") {
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const name = typeof body?.name === "string" ? body.name.trim() : "";
          if (!name || name.length > 120) throw new HttpError(422, "VALIDATION_ERROR", "name is required (max 120 chars)");

          const VALID_STEPS = ["step2", "step3", "full"];
          const step = typeof body?.step === "string" && VALID_STEPS.includes(body.step) ? body.step : "step2";

          const VALID_CARD_STYLES_T = ["standard", "teran", "social"];
          const card_styles = Array.isArray(body?.card_styles)
            ? body.card_styles.filter((s: any) => typeof s === "string" && VALID_CARD_STYLES_T.includes(s))
            : [];

          // Design JSONB — accept only safe primitives
          const rawDesign = (body?.design && typeof body.design === "object" && !Array.isArray(body.design)) ? body.design : {};
          const design: Record<string, any> = {};
          for (const [k, v] of Object.entries(rawDesign)) {
            if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
              design[k] = v;
            }
          }

          // ImageKeys JSONB — accept only string values (R2 keys)
          const rawImageKeys = (body?.image_keys && typeof body.image_keys === "object" && !Array.isArray(body.image_keys)) ? body.image_keys : {};
          const image_keys: Record<string, any> = {};
          for (const [k, v] of Object.entries(rawImageKeys)) {
            if (typeof v === "string" && v.length > 0 && v.length <= 300) {
              image_keys[k] = v;
            }
          }

          const VALID_VISIBILITY = ["private", "public"];
          const visibility = typeof body?.visibility === "string" && VALID_VISIBILITY.includes(body.visibility) ? body.visibility : "private";

          const based_on_id = typeof body?.based_on_id === "string" && body.based_on_id.length > 0 ? body.based_on_id : null;

          const insertObj: Record<string, any> = {
            name,
            step,
            card_styles,
            created_by: user_id,
            visibility,
            design,
            image_keys,
          };
          if (based_on_id) insertObj.based_on_id = based_on_id;

          const { data: template, error } = await sb(env)
            .from("room_design_templates")
            .insert(insertObj)
            .select()
            .single();
          if (error) throw new Error(error.message);

          console.log(`[room-design-templates] create id=${(template as any).id} name=${name} step=${step} visibility=${visibility} user=${user_id}`);
          return ok(req, env, request_id, { template }, 201);
        }

        // GET /api/room-design-templates — list templates (filtered)
        if (path === "/api/room-design-templates" && req.method === "GET") {
          const uid = await optionalAuth(req, env);
          const url = new URL(req.url);
          const stepFilter = url.searchParams.get("step");
          const visibilityFilter = url.searchParams.get("visibility");
          const mine = url.searchParams.get("mine") === "true";

          let query = sb(env)
            .from("room_design_templates")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(100);

          if (stepFilter && ["step2", "step3", "full"].includes(stepFilter)) {
            query = query.eq("step", stepFilter);
          }

          if (mine && uid) {
            // Fetch caller's own templates (any visibility)
            // Account-aware: check sibling device_ids
            const deviceIds = [uid];
            const { data: binding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", uid)
              .maybeSingle();
            if (binding?.account_id) {
              const { data: siblings } = await sb(env)
                .from("account_devices")
                .select("device_id")
                .eq("account_id", binding.account_id);
              if (siblings) {
                for (const s of siblings) {
                  if ((s as any).device_id && !deviceIds.includes((s as any).device_id)) {
                    deviceIds.push((s as any).device_id);
                  }
                }
              }
            }
            query = query.in("created_by", deviceIds);
          } else if (visibilityFilter && ["public", "official"].includes(visibilityFilter)) {
            query = query.eq("visibility", visibilityFilter);
          } else {
            // Default: show public + official + own private
            if (uid) {
              const deviceIds = [uid];
              const { data: binding } = await sb(env)
                .from("account_devices")
                .select("account_id")
                .eq("device_id", uid)
                .maybeSingle();
              if (binding?.account_id) {
                const { data: siblings } = await sb(env)
                  .from("account_devices")
                  .select("device_id")
                  .eq("account_id", binding.account_id);
                if (siblings) {
                  for (const s of siblings) {
                    if ((s as any).device_id && !deviceIds.includes((s as any).device_id)) {
                      deviceIds.push((s as any).device_id);
                    }
                  }
                }
              }
              query = query.or(`visibility.in.(public,official),created_by.in.(${deviceIds.join(",")})`);
            } else {
              query = query.in("visibility", ["public", "official"]);
            }
          }

          const { data: templates, error } = await query;
          if (error) throw new Error(error.message);

          return ok(req, env, request_id, { templates: templates ?? [] });
        }

        // GET /api/room-design-templates/:id — single template
        {
          const m = path.match(/^\/api\/room-design-templates\/([^/]+)$/);
          if (m && req.method === "GET") {
            const templateId = m[1];

            const { data: template, error } = await sb(env)
              .from("room_design_templates")
              .select("*")
              .eq("id", templateId)
              .maybeSingle();
            if (error) throw new Error(error.message);
            if (!template) throw new HttpError(404, "NOT_FOUND", "Template not found");

            // Visibility check: private templates only visible to creator
            const t = template as any;
            if (t.visibility === "private") {
              const uid = await optionalAuth(req, env);
              if (!uid) throw new HttpError(404, "NOT_FOUND", "Template not found");
              // Account-aware ownership check
              const deviceIds = [uid];
              const { data: binding } = await sb(env)
                .from("account_devices")
                .select("account_id")
                .eq("device_id", uid)
                .maybeSingle();
              if (binding?.account_id) {
                const { data: siblings } = await sb(env)
                  .from("account_devices")
                  .select("device_id")
                  .eq("account_id", binding.account_id);
                if (siblings) {
                  for (const s of siblings) {
                    if ((s as any).device_id && !deviceIds.includes((s as any).device_id)) {
                      deviceIds.push((s as any).device_id);
                    }
                  }
                }
              }
              if (!deviceIds.includes(t.created_by)) {
                throw new HttpError(404, "NOT_FOUND", "Template not found");
              }
            }

            return ok(req, env, request_id, { template });
          }
        }

        // PATCH /api/room-design-templates/:id — owner update
        {
          const m = path.match(/^\/api\/room-design-templates\/([^/]+)$/);
          if (m && req.method === "PATCH") {
            const templateId = m[1];
            const user_id = await requireAuth(req, env);

            // Fetch template + verify ownership (account-aware)
            const { data: existing, error: fetchErr } = await sb(env)
              .from("room_design_templates")
              .select("*")
              .eq("id", templateId)
              .maybeSingle();
            if (fetchErr) throw new Error(fetchErr.message);
            if (!existing) throw new HttpError(404, "NOT_FOUND", "Template not found");

            const t = existing as any;
            const deviceIds = [user_id];
            const { data: binding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", user_id)
              .maybeSingle();
            if (binding?.account_id) {
              const { data: siblings } = await sb(env)
                .from("account_devices")
                .select("device_id")
                .eq("account_id", binding.account_id);
              if (siblings) {
                for (const s of siblings) {
                  if ((s as any).device_id && !deviceIds.includes((s as any).device_id)) {
                    deviceIds.push((s as any).device_id);
                  }
                }
              }
            }
            if (!deviceIds.includes(t.created_by)) {
              throw new HttpError(403, "FORBIDDEN", "Only template creator can update");
            }

            const body = (await req.json().catch(() => null)) as any;
            const updates: Record<string, any> = {};

            if (typeof body?.name === "string") {
              const n = body.name.trim();
              if (!n || n.length > 120) throw new HttpError(422, "VALIDATION_ERROR", "name max 120 chars");
              updates.name = n;
            }

            if (body?.design && typeof body.design === "object" && !Array.isArray(body.design)) {
              const d: Record<string, any> = {};
              for (const [k, v] of Object.entries(body.design)) {
                if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") d[k] = v;
              }
              updates.design = d;
            }

            if (body?.image_keys && typeof body.image_keys === "object" && !Array.isArray(body.image_keys)) {
              const ik: Record<string, any> = {};
              for (const [k, v] of Object.entries(body.image_keys)) {
                if (typeof v === "string" && v.length > 0 && v.length <= 300) ik[k] = v;
              }
              updates.image_keys = ik;
            }

            const VALID_VISIBILITY_U = ["private", "public"];
            if (typeof body?.visibility === "string" && VALID_VISIBILITY_U.includes(body.visibility)) {
              updates.visibility = body.visibility;
            }

            if (Array.isArray(body?.card_styles)) {
              const VALID_CS = ["standard", "teran", "social"];
              updates.card_styles = body.card_styles.filter((s: any) => typeof s === "string" && VALID_CS.includes(s));
            }

            if (Object.keys(updates).length === 0) {
              throw new HttpError(422, "VALIDATION_ERROR", "No fields to update");
            }
            updates.updated_at = new Date().toISOString();

            const { data: template, error } = await sb(env)
              .from("room_design_templates")
              .update(updates)
              .eq("id", templateId)
              .select()
              .single();
            if (error) throw new Error(error.message);

            console.log(`[room-design-templates] update id=${templateId} user=${user_id} fields=${Object.keys(updates).join(",")}`);
            return ok(req, env, request_id, { template });
          }
        }

        // DELETE /api/room-design-templates/:id — owner delete
        {
          const m = path.match(/^\/api\/room-design-templates\/([^/]+)$/);
          if (m && req.method === "DELETE") {
            const templateId = m[1];
            const user_id = await requireAuth(req, env);

            // Fetch template + verify ownership (account-aware)
            const { data: existing, error: fetchErr } = await sb(env)
              .from("room_design_templates")
              .select("id,created_by")
              .eq("id", templateId)
              .maybeSingle();
            if (fetchErr) throw new Error(fetchErr.message);
            if (!existing) throw new HttpError(404, "NOT_FOUND", "Template not found");

            const t = existing as any;
            const deviceIds = [user_id];
            const { data: binding } = await sb(env)
              .from("account_devices")
              .select("account_id")
              .eq("device_id", user_id)
              .maybeSingle();
            if (binding?.account_id) {
              const { data: siblings } = await sb(env)
                .from("account_devices")
                .select("device_id")
                .eq("account_id", binding.account_id);
              if (siblings) {
                for (const s of siblings) {
                  if ((s as any).device_id && !deviceIds.includes((s as any).device_id)) {
                    deviceIds.push((s as any).device_id);
                  }
                }
              }
            }
            if (!deviceIds.includes(t.created_by)) {
              throw new HttpError(403, "FORBIDDEN", "Only template creator can delete");
            }

            const { error } = await sb(env)
              .from("room_design_templates")
              .delete()
              .eq("id", templateId);
            if (error) throw new Error(error.message);

            console.log(`[room-design-templates] delete id=${templateId} user=${user_id}`);
            return ok(req, env, request_id, { ok: true });
          }
        }

        // POST /api/rooms/:id/join — join public room
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/join$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const { data: room } = await sb(env).from("rooms").select("visibility").eq("id", roomId).maybeSingle();
            if (!room) throw new HttpError(404, "NOT_FOUND", "Room not found");
            if ((room as any).visibility === "private_invite_only" || (room as any).visibility === "private") {
              throw new HttpError(403, "FORBIDDEN", "Private room. Join via invite link.");
            }

            // Upsert membership
            const existing = await checkRoomMembership(env, roomId, user_id);
            if (!existing) {
              const { error } = await sb(env)
                .from("room_members")
                .insert({ room_id: roomId, user_id, role: "member" });
              if (error) throw new Error(error.message);
            }

            return ok(req, env, request_id, { joined: true });
          }
        }

        // POST /api/rooms/:id/leave — leave room
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/leave$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const role = await checkRoomMembership(env, roomId, user_id);
            if (!role) throw new HttpError(400, "BAD_REQUEST", "You are not a member of this room");
            if (role === "owner") throw new HttpError(400, "BAD_REQUEST", "Owner cannot leave the room");

            const { error } = await sb(env)
              .from("room_members")
              .delete()
              .eq("room_id", roomId)
              .eq("user_id", user_id);
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { left: true });
          }
        }

        // GET /api/rooms/:id/members — owner-only members list
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/members$/);
          if (m && req.method === "GET") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const myRole = await checkRoomMembership(env, roomId, user_id);
            if (myRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can view members");

            const { data, error } = await sb(env)
              .from("room_members")
              .select("user_id,role,created_at")
              .eq("room_id", roomId)
              .order("created_at", { ascending: true });
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { members: data || [] });
          }
        }

        // POST /api/rooms/:id/kick — owner-only kick
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/kick$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const myRole = await checkRoomMembership(env, roomId, user_id);
            if (myRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can kick members");

            const body = (await req.json().catch(() => null)) as any;
            const targetUserId = typeof body?.user_id === "string" ? body.user_id : null;
            if (!targetUserId) throw new HttpError(422, "VALIDATION_ERROR", "user_id is required");

            const targetRole = await checkRoomMembership(env, roomId, targetUserId);
            if (!targetRole) throw new HttpError(400, "BAD_REQUEST", "User is not a member");
            if (targetRole === "owner") throw new HttpError(400, "BAD_REQUEST", "Cannot kick the owner");

            const { error } = await sb(env)
              .from("room_members")
              .delete()
              .eq("room_id", roomId)
              .eq("user_id", targetUserId);
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { kicked: true });
          }
        }

        // GET /api/rooms/:id/invite — owner fetches current active invite token
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/invite$/);
          if (m && req.method === "GET") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const myRole = await checkRoomMembership(env, roomId, user_id);
            if (myRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can view invites");

            const { data: invite } = await sb(env)
              .from("room_invites")
              .select("id,room_id,token,created_at")
              .eq("room_id", roomId)
              .eq("revoked", false)
              .order("created_at", { ascending: false })
              .limit(1)
              .maybeSingle();

            return ok(req, env, request_id, { invite: invite || null });
          }
        }

        // POST /api/rooms/:id/invite/new — owner generates invite token
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/invite\/new$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const myRole = await checkRoomMembership(env, roomId, user_id);
            if (myRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can create invites");

            // Revoke existing tokens for this room
            await sb(env)
              .from("room_invites")
              .update({ revoked: true })
              .eq("room_id", roomId)
              .eq("revoked", false);

            // Create new token
            const token = generateInviteToken();
            const { data, error } = await sb(env)
              .from("room_invites")
              .insert({ room_id: roomId, token, revoked: false })
              .select()
              .single();
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { invite: data });
          }
        }

        // POST /api/rooms/:id/invite/revoke — owner revokes invite
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/invite\/revoke$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const myRole = await checkRoomMembership(env, roomId, user_id);
            if (myRole !== "owner") throw new HttpError(403, "FORBIDDEN", "Only room owner can revoke invites");

            const { error } = await sb(env)
              .from("room_invites")
              .update({ revoked: true })
              .eq("room_id", roomId)
              .eq("revoked", false);
            if (error) throw new Error(error.message);

            return ok(req, env, request_id, { revoked: true });
          }
        }

        // POST /api/rooms/:id/join_by_invite — join via invite token
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/join_by_invite$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const body = (await req.json().catch(() => null)) as any;
            const token = typeof body?.token === "string" ? body.token.trim() : "";
            if (!token) throw new HttpError(422, "VALIDATION_ERROR", "token is required");

            // Validate invite
            const { data: invite } = await sb(env)
              .from("room_invites")
              .select("id,room_id,revoked")
              .eq("room_id", roomId)
              .eq("token", token)
              .maybeSingle();

            if (!invite) throw new HttpError(403, "FORBIDDEN", "Invalid invite token");
            if ((invite as any).revoked) throw new HttpError(403, "FORBIDDEN", "This invite has been revoked");

            // Insert membership if not already a member
            const existing = await checkRoomMembership(env, roomId, user_id);
            if (!existing) {
              const { error } = await sb(env)
                .from("room_members")
                .insert({ room_id: roomId, user_id, role: "member" });
              if (error) throw new Error(error.message);
            }

            return ok(req, env, request_id, { joined: true });
          }
        }

        throw new HttpError(404, "NOT_FOUND", "Not found");

      } catch (e: any) {
        if (e instanceof HttpError) {
          return fail(req, env, request_id, e.status, e.code, e.message);
        }
        // Log full error for debugging
        console.error("[INTERNAL_ERROR]", request_id, e?.message, e?.stack);

        // Supabase errors: surface as 500 with debug info (TEMPORARY for debugging)
        const msg = typeof e?.message === "string" ? e.message : "Internal error";
        const debugStack = typeof e?.stack === "string" ? e.stack.slice(0, 300) : "";
        return new Response(JSON.stringify({
          error: { code: "INTERNAL_ERROR", message: msg, debug: debugStack },
          request_id
        }), {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "X-Request-Id": request_id,
            ...corsHeaders(req, env),
          },
        });
      }
    };

    let res: Response;
    try {
      res = await handleRequest();
    } catch (fatal: any) {
      outcome = "exception";
      errMsg = (typeof fatal?.message === "string" ? fatal.message : String(fatal)).slice(0, 120);
      res = new Response(
        JSON.stringify({ error: { code: "INTERNAL_ERROR", message: "unhandled" }, request_id }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders(req, env) } }
      );
    } finally {
      const ms = Date.now() - t0;
      const headers = new Headers(res!.headers);
      if (!headers.has("x-req-id")) headers.set("x-req-id", request_id);
      if (!headers.has("X-Request-Id")) headers.set("X-Request-Id", request_id);
      res = new Response(res!.body, { status: res!.status, statusText: res!.statusText, headers });

      const status = res.status;
      const diagOn = env.DIAG_LOG === "1";
      const isError = status >= 500 || outcome === "exception";
      const isSlow = ms >= 2000;
      const is429 = status === 429;

      // ── [rl] Rate limit log (always, for 429 or body containing 1027) ──
      if (is429) {
        let bodyPrefix = "";
        try { bodyPrefix = (await res.clone().text()).slice(0, 120); } catch (_) { }
        console.warn(`[rl] ${method} ${path} ${JSON.stringify({
          rid: request_id, cf_ray: cfRay, colo, status, elapsed_ms: ms,
          retry_after: res.headers.get("retry-after") || "",
          cf_ratelimit: res.headers.get("cf-ratelimit-action") || "",
          x_ratelimit: res.headers.get("x-ratelimit-remaining") || "",
          body_prefix: bodyPrefix,
        })}`);
      }

      // ── [sum] Summary log ──
      // DIAG_LOG=1: every request. DIAG_LOG=0: only 429, 5xx, exceptions, or slow (>=2s).
      if (diagOn || is429 || isError || isSlow) {
        const ua = req.headers.get("user-agent") || "";
        const caller = req.headers.get("x-teran-caller") || "";
        const sum: Record<string, any> = {
          rid: request_id, cf_ray: cfRay, colo,
          method, path, status, outcome, elapsed_ms: ms,
          ua: ua.length > 80 ? ua.slice(0, 80) : ua,
          caller: caller.length > 40 ? caller.slice(0, 40) : caller,
          auth: req.headers.has("authorization") ? "present" : "missing",
        };
        // Include error message if exception
        if (errMsg) sum.err = errMsg;
        // Include /api/posts perf breakdown if available
        if (Object.keys(reqCtx).length > 0) {
          for (const [k, v] of Object.entries(reqCtx)) sum[k] = v;
        }
        // Include rate-limit details for 429
        if (is429) {
          sum.ratelimit = {
            retry_after: res.headers.get("retry-after") || "",
            cf_ratelimit: res.headers.get("cf-ratelimit-action") || "",
            x_ratelimit: res.headers.get("x-ratelimit-remaining") || "",
          };
        }
        console.log(`[sum] ${method} ${path} ${JSON.stringify(sum)}`);
      }
    }
    return res;
  },
};
