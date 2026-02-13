// ~/Desktop/teran-api/src/index.ts
import { createClient } from "@supabase/supabase-js";

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_SECRET: string;
  CORS_ORIGIN?: string; // optional: "http://localhost:5173" etc
  R2_MEDIA: R2Bucket;    // R2 bucket for media uploads
  UNREAD_KV: KVNamespace; // KV for unread_count cache
  OPENAI_API_KEY: string;  // OpenAI API key for genre classification
}

// --------- request_id + response helpers ----------
function getReqId(): string {
  return (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`).toString();
}

function corsHeaders(req: Request, env: Env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = env.CORS_ORIGIN || origin || "*";
  return {
    "Access-Control-Allow-Origin": allowed === "null" ? "*" : allowed,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Expose-Headers": "X-Cache, X-Cache-Key, X-Request-Id, Cache-Control",
    "Access-Control-Max-Age": "86400",
  };
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
// --------- Notifications Helper ----------
async function createNotification(
  env: Env,
  payload: {
    recipient_user_id: string;
    actor_user_id: string;
    actor_name?: string | null;
    actor_avatar?: string | null;
    type: "comment_like" | "reply" | "post_comment" | "post_like" | "post_reply";
    post_id?: number;
    comment_id?: number;
    parent_comment_id?: number;
    news_id?: string;

    group_key: string;
    snippet?: string | null;
  },
  request_id?: string
) {

  // Skip self-notification
  if (payload.recipient_user_id === payload.actor_user_id) {
    console.log(`[notif][${request_id}] skipping self-notification`, {
      type: payload.type,
      actor: payload.actor_user_id,
    });
    return;
  }


  console.log(`[notif][${request_id}] inserting notification`, {
    recipient_user_id: payload.recipient_user_id,
    actor_user_id: payload.actor_user_id,
    type: payload.type,
    post_id: payload.post_id,
    comment_id: payload.comment_id,
    group_key: payload.group_key,
  });

  const insertPayload = {
    recipient_user_id: payload.recipient_user_id,
    actor_user_id: payload.actor_user_id,
    actor_name: payload.actor_name ?? null,
    actor_avatar: payload.actor_avatar ?? null,
    type: payload.type,
    post_id: payload.post_id ?? null,
    comment_id: payload.comment_id ?? null,
    parent_comment_id: payload.parent_comment_id ?? null,
    group_key: payload.group_key,
    news_id: payload.news_id ?? null,
  };


  const { data, error } = await sb(env).from("notifications").insert(insertPayload).select("id");

  if (error) {
    console.error(`[notif][${request_id}] INSERT FAILED`, {
      code: error.code,
      message: error.message,
      details: error.details,
      hint: error.hint,
      payload: insertPayload,
    });
  } else {
    console.log(`[notif][${request_id}] INSERT SUCCESS`, { data });
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
  const { data } = await sb(env)
    .from("room_members")
    .select("role")
    .eq("room_id", roomId)
    .eq("user_id", userId)
    .maybeSingle();
  return data?.role ?? null;
}

function generateInviteToken(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

// --------- routes ----------
export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const request_id = getReqId();
    const t0 = Date.now();

    // Preflight (don't log timing for OPTIONS)
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    }

    const url = new URL(req.url);
    const path = url.pathname;
    const q = url.searchParams.toString();
    const shortQ = q.length > 120 ? q.slice(0, 120) + "…" : q;
    const label = shortQ ? `${path}?${shortQ}` : path;

    const handleRequest = async (): Promise<Response> => {
      try {
        // /api/identity (POST) -> { user_id, token }
        if (path === "/api/identity" && req.method === "POST") {
          const user_id = crypto.randomUUID();
          const now = Math.floor(Date.now() / 1000);
          const token = await jwtSign(env, {
            sub: user_id,
            iat: now,
            exp: now + 60 * 60 * 24 * 365, // 1 year
          });
          return ok(req, env, request_id, { user_id, token });
        }

        // /api/posts (GET) - filter by ?id=, ?user_id=, ?author_id=, ?room_id=, ?limit=, ?actor_id=
        if (path === "/api/posts" && req.method === "GET") {
          const FEED_CACHE_TTL = 8; // seconds
          const handlerStart = Date.now();
          const p0 = performance.now();

          // Parse all query params
          const id_param = url.searchParams.get("id");
          const user_id_param = url.searchParams.get("user_id");
          const author_id_param = url.searchParams.get("author_id");
          const room_id_param = url.searchParams.get("room_id");
          const limit_param = url.searchParams.get("limit");
          const actor_id_param = url.searchParams.get("actor_id")?.trim() || null;
          const p1 = performance.now();

          // ── Edge cache: unfiltered feed only ──
          const isFeed = !id_param && !user_id_param && !author_id_param && !room_id_param;
          let feedCacheKey: Request | null = null;
          const cache = caches.default;

          if (isFeed) {
            const cacheUrl = new URL("https://cache.internal/posts/feed");
            cacheUrl.searchParams.set("limit", limit_param || "50");
            if (actor_id_param) cacheUrl.searchParams.set("actor", actor_id_param);
            feedCacheKey = new Request(cacheUrl.toString(), { method: "GET" });

            const cached = await cache.match(feedCacheKey);
            if (cached) {
              const hitBody = await cached.text();
              const pDone = performance.now();
              console.log(`[perf] /api/posts cache=HIT rid=${request_id} total=${(pDone - p0).toFixed(1)}ms limit=${limit_param || 50} actor=${actor_id_param || "none"} payloadBytes=${hitBody.length}`);
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
          }

          // Build base query with conditional select:
          // - Feed lists: lightweight select (content included for card preview)
          // - Single post by id: include full data for PostDetail
          const feedSelectFields = "id,user_id,created_at,title,content,author_id,author_name,author_avatar,room_id,parent_post_id,post_type,shared_post_id,genre";
          const selectFields = id_param ? "*" : feedSelectFields;

          let q = sb(env)
            .from("posts")
            .select(selectFields)
            .order("created_at", { ascending: false });

          // Apply filters - priority: id > user_id > author_id > default
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
            // Apply room_id filter if provided
            if (room_id_param) {
              // Room read policy enforcement (skip for 'global')
              if (room_id_param !== "global") {
                const { data: roomRow } = await sb(env).from("rooms").select("read_policy").eq("id", room_id_param).maybeSingle();
                if (roomRow && roomRow.read_policy === "members_only") {
                  const callerId = await optionalAuth(req, env);
                  if (!callerId) throw new HttpError(403, "FORBIDDEN", "This room requires membership to read");
                  const memberRole = await checkRoomMembership(env, room_id_param, callerId);
                  if (!memberRole) throw new HttpError(403, "FORBIDDEN", "This room requires membership to read");
                }
              }
              q = q.eq("room_id", room_id_param);
            }
            // Determine limit (default 50, max 200)
            let lim = 50;
            if (limit_param) {
              const parsed = parseInt(limit_param, 10);
              if (!isNaN(parsed)) {
                lim = Math.min(200, Math.max(1, parsed));
              }
            }
            q = q.limit(lim);
          }
          const p2 = performance.now();

          let t1 = Date.now();
          const { data: posts, error } = await q;
          const postsQueryMs = Date.now() - t1;
          const p3 = performance.now();

          // Granular logging + slow-query alert
          // NOTE: no { count: "exact" } is used — entire posts_query time IS select_ms, count_ms=0
          const filterDesc = id_param ? `id=${id_param}` : [user_id_param && `user_id=${user_id_param}`, author_id_param && `author_id=${author_id_param}`, room_id_param && `room_id=${room_id_param}`].filter(Boolean).join(",") || "feed";
          console.log(`[perf] /api/posts posts_query_split rid=${request_id} select_ms=${postsQueryMs} count_ms=0 filter=${filterDesc} limit=${limit_param || 50} rows=${posts?.length ?? 0}`);
          if (postsQueryMs > 400) {
            console.log(`[perf] /api/posts SLOW_QUERY rid=${request_id} select_ms=${postsQueryMs} count_ms=0 filter=${filterDesc} limit=${limit_param || 50} rows=${posts?.length ?? 0}`);
          }
          if (error) throw error;

          // Fast path: no posts => return immediately
          const postIds = (posts ?? []).map((p: any) => p.id);
          if (postIds.length === 0) {
            console.log(`[perf] /api/posts total ${Date.now() - handlerStart}ms (empty)`);
            console.log(`[perf] /api/posts breakdown rid=${request_id} params=${(p1 - p0).toFixed(1)} client=${(p2 - p1).toFixed(1)} db_posts=${(p3 - p2).toFixed(1)} transform=0 total=${(p3 - p0).toFixed(1)} rows=0`);
            return ok(req, env, request_id, { posts: [] });
          }

          // Parallel fetch: media + likes (merged likes+likedByMe into 1 query)
          const parallelStart = Date.now();
          let mediaMs = 0, likesMs = 0;

          const mediaQuery = (async () => {
            const t = Date.now();
            const { data } = await sb(env)
              .from("media")
              .select("id, post_id, type, key, thumb_key, width, height, duration_ms")
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
              .select("post_id, actor_id")
              .in("post_id", postIds);
            likesMs = Date.now() - t;
            return data ?? [];
          })();

          const [mediaRows, allLikeRows] = await Promise.all([
            mediaQuery,
            likesQuery,
          ]);
          const parallelMs = Date.now() - parallelStart;
          const p4 = performance.now();

          console.log(`[perf] /api/posts parallel_queries ${parallelMs}ms`, {
            media: mediaMs,
            likes: likesMs,
            mediaCount: mediaRows.length,
            likeRows: (allLikeRows as any[]).length,
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

          // Enrich posts with media, like_count, liked_by_me
          const enrichedPosts = (posts ?? []).map((p: any) => {
            let avatar = p.author_avatar;
            if (typeof avatar === "string" && avatar.startsWith("data:")) {
              avatar = null;
            }
            return {
              ...p,
              author_avatar: avatar,
              media: mediaByPost[p.id] || [],
              like_count: likeCounts[p.id] || 0,
              liked_by_me: likedByActorSet.has(p.id),
            };
          });
          const p5 = performance.now();

          const responseBody = JSON.stringify({ posts: enrichedPosts });
          console.log(`[perf] /api/posts total ${Date.now() - handlerStart}ms`, {
            posts_query: postsQueryMs,
            parallel: parallelMs,
            posts: enrichedPosts.length,
            payloadBytes: responseBody.length,
          });
          console.log(`[perf] /api/posts breakdown rid=${request_id} cache=MISS params=${(p1 - p0).toFixed(1)} client=${(p2 - p1).toFixed(1)} db_posts=${(p3 - p2).toFixed(1)} parallel=${(p4 - p3).toFixed(1)} transform=${(p5 - p4).toFixed(1)} total=${(p5 - p0).toFixed(1)} rows=${enrichedPosts.length}`);

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
          const user_id = await requireAuth(req, env);

          const body = (await req.json().catch(() => null)) as any;
          const content = typeof body?.content === "string" ? body.content.trim() : "";

          // Parse media early so we can validate content OR media requirement
          const mediaInput = Array.isArray(body?.media) ? body.media : [];
          if (!content && mediaInput.length === 0) {
            throw new HttpError(422, "VALIDATION_ERROR", "content or media required");
          }

          // Parse optional author fields from request
          const title = typeof body?.title === "string" ? body.title.trim() : "";
          const author_id = typeof body?.author_id === "string" ? body.author_id : null;
          const author_name = typeof body?.author_name === "string" ? body.author_name : null;
          const rawAuthorAvatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;
          // Reject data URIs to prevent storing MB-sized base64 in DB
          if (rawAuthorAvatar && rawAuthorAvatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "author_avatar must be a URL, not a data URI");
          }
          const author_avatar = rawAuthorAvatar;
          const room_id = typeof body?.room_id === "string" ? body.room_id : null;

          // Room post policy enforcement (skip for null or 'global')
          if (room_id && room_id !== "global") {
            const { data: roomRow } = await sb(env).from("rooms").select("post_policy").eq("id", room_id).maybeSingle();
            if (roomRow && roomRow.post_policy === "members_only") {
              const memberRole = await checkRoomMembership(env, room_id, user_id);
              if (!memberRole) throw new HttpError(403, "FORBIDDEN", "You must be a member to post in this room");
            }
          }

          // Parse reply/share fields with robust numeric coercion
          const rawParentPostId = body?.parent_post_id;
          const parent_post_id = rawParentPostId != null ? (Number.isFinite(Number(rawParentPostId)) ? Number(rawParentPostId) : null) : null;

          const rawPostType = body?.post_type;
          const post_type = typeof rawPostType === "string" && ["status", "share", "thread"].includes(rawPostType)
            ? rawPostType
            : "status";

          const rawSharedPostId = body?.shared_post_id;
          const shared_post_id = rawSharedPostId != null ? (Number.isFinite(Number(rawSharedPostId)) ? Number(rawSharedPostId) : null) : null;

          // Media limits
          const MAX_IMAGES = 4;
          const MAX_VIDEOS = 1;

          // Validate media items (images + video)
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
              // Require thumb_key for images
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

          const { data, error } = await sb(env)
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
              post_type,
              shared_post_id,
            })
            .select("*")
            .single();
          if (error) throw error;

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
          }

          // Create notification for replies (if this is a reply to another post)
          if (parent_post_id) {
            // Fetch the parent post owner's user_id (NOT author_id/persona)
            const { data: parentPost, error: parentFetchError } = await sb(env)
              .from("posts")
              .select("user_id, author_id")
              .eq("id", parent_post_id)
              .single();

            if (parentFetchError) {
              console.error(`[notif][${request_id}] failed to fetch parent post owner`, { parent_post_id, error: parentFetchError });
            }

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
              await createNotification(env, {
                recipient_user_id: parentPost.user_id,  // JWT sub of parent post owner
                actor_user_id: user_id,                  // JWT sub of replier
                actor_name: author_name,
                actor_avatar: author_avatar,
                type: "post_reply",
                post_id: parent_post_id, // Link to parent so notification opens the thread
                group_key: `post_reply:${parent_post_id}`,
              }, request_id);
            } else if (!parentPost?.user_id) {
              console.warn(`[notif][${request_id}] parent post user_id not found, skipping notification`, { parent_post_id });
            } else {
              console.log(`[notif][${request_id}] skipping self-reply`, { parent_post_id, user_id });
            }
          }

          // ── Async AI genre classification (threads only) ──
          // Chain: Anchors dictionary → OpenAI → Chat fallback
          if (!room_id && !parent_post_id && env.OPENAI_API_KEY) {
            const postId = data.id;
            const classifyTitle = title || "";
            const classifyContent = (content || "").slice(0, 800);
            ctx.waitUntil((async () => {
              const VALID_GENRES = new Set(["Chat", "Learn", "Tech", "Work", "Health", "Relationships", "Society", "Create", "Sports"]);
              const FALLBACK_GENRE = "Chat";
              const inputText = (classifyTitle + "\n\n" + classifyContent).toLowerCase();

              // Best-effort update helper — never throws
              const persistGenre = async (g: string) => {
                try {
                  await sb(env).from("posts").update({ genre: g }).eq("id", postId);
                } catch (ue: any) {
                  console.error(`[genre] update_error`, { postId, request_id, genre: g, message: ue?.message });
                }
              };

              // ── Anchors dictionary (priority order, first match wins) ──
              const ANCHOR_MAP: [string, string[]][] = [
                ["Relationships", [
                  "cheat", "cheating", "affair", "unfaithful", "infidelity",
                  "breakup", "break up", "divorce", "separated",
                  "dating", "tinder", "bumble", "hinge",
                  "boyfriend", "girlfriend", "fiance", "fiancée", "husband", "wife",
                  "boundary", "boundaries", "trust issues", "betrayal",
                ]],
                ["Health", [
                  "workout", "gym", "lifting", "strength training", "hypertrophy",
                  "squat", "deadlift", "bench press", "pull-up", "push-up",
                  "calories", "macros", "protein", "cut", "bulk", "body fat",
                  "sleep apnea", "insomnia", "migraine", "injury", "rehab",
                ]],
                ["Tech", [
                  "react", "react native", "expo", "vite",
                  "typescript", "javascript", "node", "npm",
                  "api", "endpoint", "webhook", "oauth", "jwt",
                  "supabase", "postgres", "sql", "rls",
                  "cloudflare", "workers", "wrangler", "pages",
                ]],
                ["Work", [
                  "salary", "compensation", "raise", "promotion",
                  "job offer", "interview", "resume", "recruiter",
                  "startup", "founder", "cofounder", "pitch deck",
                  "revenue", "profit", "burn rate", "runway",
                  "investing", "portfolio", "stocks", "crypto",
                ]],
                ["Society", [
                  "election", "voting", "parliament", "congress",
                  "policy", "regulation", "law", "bill", "amendment",
                  "tax", "inflation", "recession", "unemployment",
                  "war", "conflict", "sanctions", "geopolitics",
                  "immigration", "climate change", "inequality",
                ]],
                ["Create", [
                  "song", "beat", "lyrics", "chorus", "hook", "verse",
                  "mixing", "mastering", "bpm", "808", "hi-hat",
                  "drawing", "illustration", "painting", "sculpture",
                  "writing a novel", "screenplay", "script", "storyboard",
                  "logo", "typography", "ui design", "graphic design",
                ]],
                ["Sports", [
                  "match", "game day", "tournament", "playoffs",
                  "league", "season", "roster", "draft",
                  "coach", "team", "opponent", "halftime",
                  "fifa", "nba", "nfl", "mlb", "ufc",
                ]],
                ["Learn", [
                  "explain like i'm five", "eli5",
                  "difference between", "pros and cons", "compare",
                  "what is", "how does", "why does",
                  "beginner guide", "tutorial", "step by step",
                  "theory", "concept", "definition",
                ]],
              ];

              function genreFromAnchors(text: string): string | null {
                for (const [genre, anchors] of ANCHOR_MAP) {
                  for (const anchor of anchors) {
                    if (text.includes(anchor)) return genre;
                  }
                }
                return null;
              }

              // ── Step 1: Try anchors ──
              const dictGenre = genreFromAnchors(inputText);
              if (dictGenre) {
                console.log(`[genre] dict_match`, { postId, request_id, matched: true, finalGenre: dictGenre });
                await persistGenre(dictGenre);
                return;
              }
              console.log(`[genre] dict_match`, { postId, request_id, matched: false, finalGenre: null });

              // ── Step 2: OpenAI classifier ──
              try {
                console.log(`[genre] classify_start`, { postId, request_id });
                const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
                  },
                  body: JSON.stringify({
                    model: "gpt-4o-mini",
                    temperature: 0,
                    max_tokens: 30,
                    messages: [
                      {
                        role: "system",
                        content: [
                          `You are a strict genre classifier for short social posts. Choose exactly ONE genre from: ${[...VALID_GENRES].join(", ")}.`,
                          `Use the post's meaning and context (not just keywords). You MAY use general world knowledge for proper nouns (artists, politicians, companies, sports teams, etc.).`,
                          `Definitions + typical examples:`,
                          `1) Relationships – Interpersonal relationships: dating, cheating, breakup, marriage, family, friends, workplace relationships, trust, boundaries, conflict, reconciliation. Examples: "My partner cheated", "I fought with my brother", "How do I set boundaries with a friend?"`,
                          `2) Health – Body/mind/habits: workouts, training, nutrition, sleep, recovery, injury, stress/anxiety, routines. Examples: "3-day strength program?", "How to fix my sleep schedule", "Recovering from an injury"`,
                          `3) Tech – Software/engineering/tools: coding, bugs, APIs, deployments, databases, devices, AI tooling and development. Examples: "React re-render issue", "Supabase RLS question", "Cloudflare Workers deploy error"`,
                          `4) Work – Career/money/business: jobs, interviews, salary, workplace issues (non-relationship aspect), startups, marketing, pricing, investing/finance. Examples: "Negotiating a raise", "Should I join a startup?", "Subscription pricing strategy"`,
                          `5) Society – News/politics/systems/global issues: elections, policy, economy, institutions, geopolitics, social problems. Examples: "Election incentives online", "Tax policy impact", "Why platforms reward outrage?"`,
                          `6) Create – Creative work and culture: music/art/writing/design/filmmaking, creative projects, creative process, artists and works. Examples: "Writing lyrics", "Beat making", "Aphex Twin discussion", "Designing a logo"`,
                          `7) Sports – Sports and competition: teams, matches, leagues, training for a sport, watching sports, tactics. Examples: "NBA playoffs", "Soccer training plan", "How to improve my serve"`,
                          `8) Learn – Learning/explanations/how-to/analysis: asking for definitions, explanations, comparisons, tutorials, conceptual breakdowns. Examples: "What is X?", "Difference between A and B?", "Explain this concept step-by-step"`,
                          `9) Chat – Casual conversation, diary-like posts, jokes, reactions, small talk, quick advice when no other category clearly fits. Examples: "Random rant about notifications", "Just sharing a thought", "What do you think about this?"`,
                          `Decision rules:`,
                          `- If the post is primarily about interpersonal conflict/repair/trust/boundaries (including family) -> Relationships.`,
                          `- If it's about workouts/nutrition/sleep/mental health habits -> Health.`,
                          `- If it's about making/performing/discussing art/music/creative works or artists -> Create.`,
                          `- If it's politics/news/systems/global issues -> Society.`,
                          `- If unsure between multiple genres, choose the best fit; if still unsure, choose Chat.`,
                          `- Output MUST be strict JSON ONLY with no extra keys and no prose: {"genre":"<ONE_OF_THE_9>"}`,
                        ].join("\n"),
                      },
                      {
                        role: "user",
                        content: classifyTitle + (classifyContent ? "\n\n" + classifyContent : ""),
                      },
                    ],
                  }),
                });
                if (!aiRes.ok) {
                  const errText = await aiRes.text().catch(() => "unknown");
                  console.error(`[genre] classify_error openai_status=${aiRes.status}`, { postId, request_id, errText });
                  await persistGenre(FALLBACK_GENRE);
                  console.log(`[genre] classify_result`, { postId, request_id, returnedGenre: null, finalGenre: FALLBACK_GENRE, fallback: true });
                  return;
                }
                const aiData = await aiRes.json() as any;
                const raw = aiData?.choices?.[0]?.message?.content?.trim() || "";
                let returnedGenre: string | null = null;
                try {
                  const parsed = JSON.parse(raw);
                  const g = typeof parsed?.genre === "string" ? parsed.genre.trim() : null;
                  if (g && VALID_GENRES.has(g)) {
                    returnedGenre = g;
                  }
                } catch {
                  console.warn(`[genre] classify_parse_fail`, { postId, request_id, raw });
                }
                const finalGenre = returnedGenre || FALLBACK_GENRE;
                const fallback = !returnedGenre;
                await persistGenre(finalGenre);
                console.log(`[genre] classify_result`, { postId, request_id, returnedGenre, finalGenre, fallback });
              } catch (err: any) {
                console.error(`[genre] classify_error`, { postId, request_id, message: err?.message });
                await persistGenre(FALLBACK_GENRE);
                console.log(`[genre] classify_fallback_after_error`, { postId, request_id, finalGenre: FALLBACK_GENRE });
              }
            })());
          }

          return ok(req, env, request_id, { post: { ...data, media: mediaRows } }, 201);
        }

        // /api/posts/:id (DELETE)
        {
          const m = path.match(/^\/api\/posts\/(\d+)$/);
          if (m && req.method === "DELETE") {
            const user_id = await requireAuth(req, env);
            const postId = Number(m[1]);

            // First check if the post exists and belongs to the user
            const { data: existingPost, error: fetchError } = await sb(env)
              .from("posts")
              .select("id, user_id")
              .eq("id", postId)
              .single();

            if (fetchError || !existingPost) {
              throw new HttpError(404, "NOT_FOUND", "Post not found");
            }

            if (existingPost.user_id !== user_id) {
              throw new HttpError(403, "FORBIDDEN", "You can only delete your own posts");
            }

            // Fetch related media rows BEFORE deleting the post
            const { data: mediaRows } = await sb(env)
              .from("media")
              .select("key, thumb_key")
              .eq("post_id", postId);

            console.log("[DELETE post] id=", postId, "mediaCount=", (mediaRows ?? []).length);

            // Delete R2 objects (key + thumb_key) for each media row
            for (const row of mediaRows ?? []) {
              if (row.key) {
                try {
                  await env.R2_MEDIA.delete(row.key);
                } catch (e) {
                  console.warn("[DELETE post] R2 delete failed for key=", row.key, e);
                }
              }
              if (row.thumb_key) {
                try {
                  await env.R2_MEDIA.delete(row.thumb_key);
                } catch (e) {
                  console.warn("[DELETE post] R2 delete failed for thumb_key=", row.thumb_key, e);
                }
              }
            }

            // Delete the post (cascade deletes media rows in DB)
            const { error } = await sb(env)
              .from("posts")
              .delete()
              .eq("id", postId);
            if (error) throw error;

            return new Response(null, { status: 204, headers: corsHeaders(req, env) });
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
          const postIdsParam = url.searchParams.get("post_ids") || "";
          const postIds = postIdsParam
            .split(",")
            .map(s => parseInt(s.trim(), 10))
            .filter(n => Number.isFinite(n) && n > 0)
            .slice(0, 200); // Limit to 200

          if (postIds.length === 0) {
            return ok(req, env, request_id, { counts: {} });
          }

          // Get all comment rows for requested post_ids
          const { data: rows, error } = await sb(env)
            .from("comments")
            .select("post_id")
            .in("post_id", postIds);
          if (error) throw error;

          // Count occurrences per post_id
          const countMap: Record<number, number> = {};
          for (const row of rows ?? []) {
            countMap[row.post_id] = (countMap[row.post_id] || 0) + 1;
          }

          // Build response with 0 for posts that had no comments
          const counts: Record<string, number> = {};
          for (const id of postIds) {
            counts[String(id)] = countMap[id] || 0;
          }

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

        // /api/comments (GET) ?post_id=123 (REQUIRED)
        // Returns comments with like_count, liked_by_me, and media
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

          // Query 1: Fetch comments (select only needed fields)
          let t1 = Date.now();
          const { data: comments, error } = await sb(env)
            .from("comments")
            .select("id, post_id, user_id, content, parent_comment_id, author_id, author_name, author_avatar, created_at")
            .eq("post_id", post_id)
            .order("created_at", { ascending: false })
            .limit(200);
          console.log(`[perf] /api/comments comments_query ${Date.now() - t1}ms`, { post_id, count: comments?.length });
          if (error) throw error;

          const commentList = comments ?? [];
          if (commentList.length === 0) {
            console.log(`[perf] /api/comments total ${Date.now() - handlerStart}ms (empty)`);
            return ok(req, env, request_id, { comments: [] });
          }

          const commentIds = commentList.map((c: any) => c.id);

          // Queries 2-4: Run in parallel (like counts, user likes, media)
          t1 = Date.now();
          const [likesResult, userLikesResult, mediaResult] = await Promise.all([
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
          ]);
          console.log(`[perf] /api/comments parallel_queries ${Date.now() - t1}ms`);

          // Aggregate like counts
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

          // Enrich comments with like data and media
          const enrichedComments = commentList.map((c: any) => ({
            ...c,
            like_count: likeCounts[c.id] || 0,
            liked_by_me: likedByMe.has(c.id),
            media: mediaByComment[c.id] || [],
          }));

          console.log(`[perf] /api/comments total ${Date.now() - handlerStart}ms`, { post_id, comments: commentList.length });
          return ok(req, env, request_id, { comments: enrichedComments });
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

          const { data, error } = await sb(env)
            .from("comments")
            .insert({ post_id, user_id, content, parent_comment_id, author_id, author_name, author_avatar })
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
              .select("user_id")
              .eq("id", post_id)
              .single();
            if (postData) {
              await createNotification(env, {
                recipient_user_id: postData.user_id,
                actor_user_id: user_id,
                actor_name: author_name,
                actor_avatar: author_avatar,
                type: "post_comment",
                post_id,
                comment_id: data.id,
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
                  await createNotification(env, {
                    recipient_user_id: commentData.user_id,
                    actor_user_id: user_id,
                    actor_name,
                    actor_avatar,
                    type: "comment_like",
                    post_id: commentData.post_id,
                    comment_id,
                    parent_comment_id: commentData.parent_comment_id,
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
              const body = (await req.json().catch(() => ({}))) as any;
              const actor_id = typeof body?.actor_id === "string" ? body.actor_id.trim() : null;
              const actor_name = typeof body?.actor_name === "string" ? body.actor_name : null;
              const actor_avatar = typeof body?.actor_avatar === "string" ? body.actor_avatar : null;

              if (!actor_id) {
                throw new HttpError(400, "BAD_REQUEST", "actor_id is required");
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
                  .select("user_id, author_id")
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
                  await createNotification(env, {
                    recipient_user_id: postData.user_id,  // JWT sub of post owner
                    actor_user_id: jwt_user_id,           // JWT sub of liker
                    actor_name,
                    actor_avatar,
                    type: "post_like",
                    post_id,
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
              // Parse actor_id from query param
              const actor_id = url.searchParams.get("actor_id")?.trim() || null;

              if (!actor_id) {
                throw new HttpError(400, "BAD_REQUEST", "actor_id query param is required");
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

          const limitParam = url.searchParams.get("limit");
          const cursorParam = url.searchParams.get("cursor");

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
              comment_id: n.comment_id,
              parent_comment_id: n.parent_comment_id,
              news_id: n.news_id ?? null,
              news_url: n.news_url ?? null,
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
          const ids = Array.isArray(body?.ids) ? body.ids.filter((id: any) => typeof id === "number") : null;
          const group_key = typeof body?.group_key === "string" ? body.group_key : null;

          if (ids && ids.length > 0) {
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

        // GET /api/notifications/unread_count (KV-cached, SWR pattern, 300s TTL)
        // Fast path: serve from KV immediately, background-refresh via DB.
        // Sync DB only on true KV MISS (no cached value at all).
        if (path === "/api/notifications/unread_count" && req.method === "GET") {
          const KV_TTL = 300; // seconds (background revalidation keeps it fresh)
          const KV_TIMEOUT_MS = 60; // ms — if KV GET takes longer, treat as MISS
          const p0 = performance.now();

          const user_id = await requireAuth(req, env);
          const p1 = performance.now();

          const kvKey = `unread_count:${user_id}`;

          // ── KV lookup with timeout ──
          const KV_TIMED_OUT = Symbol("KV_TIMED_OUT");
          const kvResult = await Promise.race([
            env.UNREAD_KV.get(kvKey, "text"),
            new Promise<typeof KV_TIMED_OUT>((resolve) =>
              setTimeout(() => resolve(KV_TIMED_OUT), KV_TIMEOUT_MS)
            ),
          ]);
          const p2 = performance.now();
          const kvTimedOut = kvResult === KV_TIMED_OUT;
          const cached = kvTimedOut ? null : kvResult;

          // ── Helper: background DB refresh (fire-and-forget) ──
          const backgroundRefresh = () => {
            ctx.waitUntil(
              (async () => {
                const dbStart = performance.now();
                try {
                  const { count, error } = await sb(env)
                    .from("notifications")
                    .select("id", { count: "exact", head: true })
                    .eq("recipient_user_id", user_id)
                    .eq("is_read", false);
                  const dbEnd = performance.now();
                  if (error) {
                    console.error(`[kv] unread_count bg_refresh db_error rid=${request_id} me=${user_id}`, error);
                    return;
                  }
                  const freshCount = count ?? 0;
                  await env.UNREAD_KV.put(kvKey, String(freshCount), { expirationTtl: KV_TTL });
                  console.log(`[kv] unread_count bg_refresh ok rid=${request_id} me=${user_id} count=${freshCount} db_ms=${(dbEnd - dbStart).toFixed(1)}`);
                } catch (err) {
                  console.error(`[kv] unread_count bg_refresh fail rid=${request_id} me=${user_id}`, err);
                }
              })()
            );
          };

          if (cached !== null) {
            // ── KV HIT: serve immediately, background-refresh (SWR) ──
            backgroundRefresh();
            const pDone = performance.now();
            console.log(`[kv] unread_count SWR_SERVE rid=${request_id} me=${user_id} kv_ms=${(p2 - p1).toFixed(1)} total=${(pDone - p0).toFixed(1)}ms bg_refresh=started`);
            const responseBody = JSON.stringify({ unread_count: parseInt(cached, 10), source: "kv" });
            return new Response(responseBody, {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
                "X-Cache": "HIT",
                ...corsHeaders(req, env),
              },
            });
          }

          // ── KV MISS or TIMEOUT: sync DB query (cold start) ──
          if (kvTimedOut) {
            console.log(`[kv] unread_count TIMEOUT rid=${request_id} waited=${KV_TIMEOUT_MS}ms me=${user_id}`);
          } else {
            console.log(`[kv] unread_count MISS rid=${request_id} me=${user_id} kv_ms=${(p2 - p1).toFixed(1)}`);
          }

          const { count, error } = await sb(env)
            .from("notifications")
            .select("id", { count: "exact", head: true })
            .eq("recipient_user_id", user_id)
            .eq("is_read", false);
          const p3 = performance.now();

          if (error) throw error;

          const unreadCount = count ?? 0;

          // Fire-and-forget KV put
          ctx.waitUntil(
            env.UNREAD_KV.put(kvKey, String(unreadCount), { expirationTtl: KV_TTL })
              .then(() => console.log(`[kv] unread_count put ok=true rid=${request_id} me=${user_id} count=${unreadCount}`))
              .catch((err) => console.error(`[kv] unread_count put ok=false rid=${request_id} me=${user_id}`, err))
          );

          const kvLabel = kvTimedOut ? "timeout" : "miss";
          console.log(`[perf] unread_count breakdown rid=${request_id} auth=${(p1 - p0).toFixed(1)} kv_lookup=${(p2 - p1).toFixed(1)}(${kvLabel}) db=${(p3 - p2).toFixed(1)} total=${(p3 - p0).toFixed(1)} count=${unreadCount} kv_put=async`);

          const responseBody = JSON.stringify({ unread_count: unreadCount, source: "db" });
          return new Response(responseBody, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Request-Id": request_id,
              "X-Cache": kvTimedOut ? "TIMEOUT" : "MISS",
              ...corsHeaders(req, env),
            },
          });
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

          // Generate presigned PUT URL using R2 createMultipartUpload is not needed
          // R2 Workers binding doesn't have createPresignedUrl directly
          // Instead we create a custom signed URL scheme using a signature

          // For Workers R2, generate a custom presigned URL using our own signing
          // The client will PUT to /api/upload/{key} with a signature query param
          const expiry = 60; // 60 seconds
          const expiresAt = Math.floor(Date.now() / 1000) + expiry;
          const signPayload = `PUT:${key}:${content_type}:${expiresAt}`;
          const signature = await hmacSha256(env.JWT_SECRET, signPayload);

          // Build internal upload URL
          const baseUrl = new URL(req.url).origin;
          const uploadUrl = `${baseUrl}/api/upload/${encodeURIComponent(key)}?expires=${expiresAt}&content_type=${encodeURIComponent(content_type)}&sig=${signature}`;

          return ok(req, env, request_id, {
            key,
            uploadUrl,
            expiresAt,
          }, 201);
        }

        // PUT /api/upload/:key (presigned upload receiver)
        {
          const uploadMatch = path.match(/^\/api\/upload\/(.+)$/);
          if (uploadMatch && req.method === "PUT") {
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

            // Get body and upload to R2
            const body = await req.arrayBuffer();
            if (!body || body.byteLength === 0) {
              throw new HttpError(400, "BAD_REQUEST", "Empty body");
            }

            await env.R2_MEDIA.put(key, body, {
              httpMetadata: {
                contentType: content_type,
              },
            });

            return ok(req, env, request_id, { key, uploaded: true }, 201);
          }
        }

        // GET /api/media/:key - serve R2 objects
        {
          const mediaMatch = path.match(/^\/api\/media\/(.+)$/);
          if (mediaMatch) {
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

            const obj = r2Options
              ? await env.R2_MEDIA.get(key, r2Options)
              : await env.R2_MEDIA.get(key);

            if (!obj) {
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

            // Handle partial content response
            if (rangeHeader && rangeStart !== undefined) {
              const start = rangeStart;
              const end = rangeEnd !== undefined ? rangeEnd : obj.size - 1;
              const length = end - start + 1;
              headers["Content-Range"] = `bytes ${start}-${end}/${obj.size}`;
              headers["Content-Length"] = String(length);
              return new Response(obj.body, { status: 206, headers });
            }

            headers["Content-Length"] = String(obj.size);
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


        // =====================================================
        // USER PROFILE API (Stage 1: READ-ONLY)
        // =====================================================

        // GET /api/profile?user_id=...
        if (path === "/api/profile" && req.method === "GET") {
          const user_id = url.searchParams.get("user_id");
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const { data, error } = await sb(env)
            .from("user_profiles")
            .select("user_id, display_name, bio, avatar")
            .eq("user_id", user_id)
            .maybeSingle();

          if (error) throw error;

          // Return empty profile if not found (don't throw)
          if (!data) {
            return ok(req, env, request_id, {
              user_id,
              display_name: null,
              bio: null,
              avatar: null,
            });
          }

          return ok(req, env, request_id, data);
        }

        // PUT /api/profile (sync persona — DB-only, no KV)
        if (path === "/api/profile" && req.method === "PUT") {
          const p0 = performance.now();

          const body = (await req.json().catch(() => null)) as any;
          const user_id = body?.user_id;

          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
          }

          const trimmedUserId = user_id.trim();
          const incoming = {
            display_name: typeof body?.display_name === "string" ? body.display_name : "Anonymous",
            bio: typeof body?.bio === "string" ? body.bio : null,
            avatar: typeof body?.avatar === "string" ? body.avatar : null,
          };
          // Reject data URIs — avatar must be an R2 key or icon ID
          if (incoming.avatar && incoming.avatar.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "avatar must be a URL or key, not a data URI");
          }
          const p1 = performance.now();

          console.log(`[profile-sync] incoming rid=${request_id} user=${trimmedUserId} dn=${incoming.display_name} avatar=${incoming.avatar?.slice(0, 30) ?? "null"}`);

          // ── DB read: minimal columns ──
          const { data: current, error: readErr } = await sb(env)
            .from("user_profiles")
            .select("display_name, bio, avatar")
            .eq("user_id", trimmedUserId)
            .maybeSingle();
          const p2 = performance.now();

          if (readErr) throw readErr;

          // ── Compare: skip write if nothing changed ──
          if (
            current &&
            current.display_name === incoming.display_name &&
            (current.bio ?? null) === (incoming.bio ?? null) &&
            (current.avatar ?? null) === (incoming.avatar ?? null)
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

          if (writeErr) throw writeErr;

          console.log(`[profile-sync] write rid=${request_id} user=${trimmedUserId} dn=${incoming.display_name}`);
          console.log(`[perf] profile breakdown rid=${request_id} parse=${(p1 - p0).toFixed(1)} db_read=${(p2 - p1).toFixed(1)} db_write=${(p3 - p2).toFixed(1)} total=${(p3 - p0).toFixed(1)} decision=WRITE`);
          return ok(req, env, request_id, { ok: true, changed: true });
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
          const body = (await req.json().catch(() => null)) as any;
          const user_id = body?.user_id;
          const slots = body?.slots;

          // Validate user_id
          if (!user_id || typeof user_id !== "string" || user_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "user_id is required");
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

        // GET /api/news/comments?news_id=<id>&limit=200
        if (path === "/api/news/comments" && req.method === "GET") {
          const news_id = url.searchParams.get("news_id");
          if (!news_id || typeof news_id !== "string" || news_id.trim() === "") {
            throw new HttpError(400, "BAD_REQUEST", "news_id query parameter is required");
          }

          const limitParam = url.searchParams.get("limit");
          let limit = 200;
          if (limitParam) {
            const parsed = Number(limitParam);
            if (Number.isFinite(parsed) && parsed > 0) {
              limit = Math.min(parsed, 500);
            }
          }

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

          // Fetch comments
          const { data: comments, error } = await sb(env)
            .from("news_comments")
            .select("*")
            .eq("news_id", news_id.trim())
            .order("created_at", { ascending: false })
            .limit(limit);
          if (error) throw error;

          const commentList = comments ?? [];
          if (commentList.length === 0) {
            return ok(req, env, request_id, { comments: [] });
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

          // Enrich comments with likes + media
          const enrichedComments = commentList.map((c: any) => ({
            ...c,
            like_count: likeCounts[c.id] || 0,
            liked_by_me: likedByMe.has(c.id),
            media: mediaByComment[c.id] || [],
          }));

          return ok(req, env, request_id, { comments: enrichedComments });
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

          // Notify parent comment author on reply (skip self-notification)
          if (parent_comment_id) {
            try {
              const { data: parentComment } = await sb(env)
                .from("news_comments")
                .select("user_id")
                .eq("id", parent_comment_id)
                .single();
              if (parentComment) {
                await createNotification(env, {
                  recipient_user_id: parentComment.user_id,
                  actor_user_id: user_id,
                  actor_name: author_name,
                  actor_avatar: author_avatar,
                  type: "reply",
                  comment_id: data.id,
                  parent_comment_id,
                  news_id,
                  group_key: `rp:${parent_comment_id}`,
                }, request_id);
              }
            } catch (notifErr) {
              console.error("[NEWS COMMENT] reply notification failed", String(notifErr));
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

            // Notify comment author on like
            try {
              const { data: likedComment } = await sb(env)
                .from("news_comments")
                .select("user_id, news_id")
                .eq("id", comment_id)
                .single();
              if (likedComment) {
                // Fetch actor info
                const { data: actorProfile } = await sb(env)
                  .from("user_profiles")
                  .select("display_name, avatar_key")
                  .eq("user_id", user_id)
                  .single();
                await createNotification(env, {
                  recipient_user_id: likedComment.user_id,
                  actor_user_id: user_id,
                  actor_name: actorProfile?.display_name ?? null,
                  actor_avatar: actorProfile?.avatar_key ?? null,
                  type: "comment_like",
                  comment_id,
                  news_id: likedComment.news_id,
                  group_key: `cl:${comment_id}`,
                }, request_id);
              }
            } catch (notifErr) {
              console.error("[NEWS LIKE] notification failed", String(notifErr));
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

        // GET /api/rooms — list public rooms
        if (path === "/api/rooms" && req.method === "GET") {
          const { data, error } = await sb(env)
            .from("rooms")
            .select("id,room_key,name,description,emoji,icon_key,owner_id,visibility,read_policy,post_policy,created_at")
            .eq("visibility", "public")
            .order("created_at", { ascending: false })
            .limit(100);
          if (error) throw new Error(error.message);

          // Attach member_count per room
          const roomIds = (data || []).map((r: any) => r.id);
          let countMap: Record<string, number> = {};
          if (roomIds.length > 0) {
            const { data: counts } = await sb(env)
              .from("room_members")
              .select("room_id")
              .in("room_id", roomIds);
            if (counts) {
              for (const c of counts) {
                countMap[c.room_id] = (countMap[c.room_id] || 0) + 1;
              }
            }
          }

          const rooms = (data || []).map((r: any) => ({
            ...r,
            member_count: countMap[r.id] || 0,
          }));

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

        // GET /api/rooms/:id — room detail
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)$/);
          if (m && req.method === "GET") {
            const roomId = m[1];
            const { data: room, error } = await sb(env)
              .from("rooms")
              .select("*")
              .eq("id", roomId)
              .maybeSingle();
            if (error) throw new Error(error.message);
            if (!room) throw new HttpError(404, "NOT_FOUND", "Room not found");

            // Private rooms: only members can see details
            if ((room as any).visibility === "private_invite_only") {
              const callerId = await optionalAuth(req, env);
              if (!callerId) throw new HttpError(404, "NOT_FOUND", "Room not found");
              const role = await checkRoomMembership(env, roomId, callerId);
              if (!role) throw new HttpError(404, "NOT_FOUND", "Room not found");
            }

            // Attach member_count
            const { count } = await sb(env)
              .from("room_members")
              .select("*", { count: "exact", head: true })
              .eq("room_id", roomId);

            // Check caller membership
            const callerId = await optionalAuth(req, env);
            let my_role: string | null = null;
            if (callerId) {
              my_role = await checkRoomMembership(env, roomId, callerId);
            }

            return ok(req, env, request_id, {
              room: { ...(room as any), member_count: count ?? 0 },
              my_role,
            });
          }
        }

        // POST /api/rooms — create room
        if (path === "/api/rooms" && req.method === "POST") {
          const user_id = await requireAuth(req, env);
          const body = (await req.json().catch(() => null)) as any;

          const name = typeof body?.name === "string" ? body.name.trim() : "";
          if (!name) throw new HttpError(422, "VALIDATION_ERROR", "name is required");
          if (name.length > 80) throw new HttpError(422, "VALIDATION_ERROR", "name max 80 chars");

          const description = typeof body?.description === "string" ? body.description.trim().slice(0, 500) : null;
          const icon_key = typeof body?.icon_key === "string" ? body.icon_key.trim() : null;
          if (icon_key && icon_key.startsWith("data:")) {
            throw new HttpError(422, "VALIDATION_ERROR", "icon_key must not be a data URI");
          }

          // Generate random room_key (16 hex chars)
          const room_key = crypto.randomUUID().replace(/-/g, "").slice(0, 16);

          const { data: room, error } = await sb(env)
            .from("rooms")
            .insert({
              name, description, icon_key, room_key,
              owner_id: user_id,
              visibility: "public", read_policy: "public", post_policy: "public",
            })
            .select()
            .single();
          if (error) throw new Error(error.message);

          // Auto-add owner as member
          await sb(env)
            .from("room_members")
            .insert({ room_id: (room as any).id, user_id, role: "owner" });

          return ok(req, env, request_id, { room }, 201);
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

        // POST /api/rooms/:id/join — join public room
        {
          const m = path.match(/^\/api\/rooms\/([^/]+)\/join$/);
          if (m && req.method === "POST") {
            const roomId = m[1];
            const user_id = await requireAuth(req, env);

            const { data: room } = await sb(env).from("rooms").select("visibility").eq("id", roomId).maybeSingle();
            if (!room) throw new HttpError(404, "NOT_FOUND", "Room not found");
            if ((room as any).visibility === "private_invite_only") {
              throw new HttpError(403, "FORBIDDEN", "This room is invite-only. Use an invite link to join.");
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

    const res = await handleRequest();
    const ms = Date.now() - t0;
    console.log(`${req.method} ${label} -> ${res.status} ${ms}ms${ms >= 300 ? " SLOW" : ""}`);
    return res;
  },
};
