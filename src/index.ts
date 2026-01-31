// ~/Desktop/teran-api/src/index.ts
import { createClient } from "@supabase/supabase-js";

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_SECRET: string;
  CORS_ORIGIN?: string; // optional: "http://localhost:5173" etc
  R2_MEDIA: R2Bucket;    // R2 bucket for media uploads
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

// --------- Supabase client ----------
function sb(env: Env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    global: { fetch },
  });
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
    type: "comment_like" | "reply" | "post_comment";
    post_id?: number;
    comment_id?: number;
    parent_comment_id?: number;
    group_key: string;
  }
) {
  // Skip self-notification
  if (payload.recipient_user_id === payload.actor_user_id) return;

  await sb(env).from("notifications").insert({
    recipient_user_id: payload.recipient_user_id,
    actor_user_id: payload.actor_user_id,
    actor_name: payload.actor_name ?? null,
    actor_avatar: payload.actor_avatar ?? null,
    type: payload.type,
    post_id: payload.post_id ?? null,
    comment_id: payload.comment_id ?? null,
    parent_comment_id: payload.parent_comment_id ?? null,
    group_key: payload.group_key,
  });
}

// --------- routes ----------
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const request_id = getReqId();

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    }

    const url = new URL(req.url);
    const path = url.pathname;

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

      // /api/posts (GET) - filter by ?id=, ?user_id=, ?author_id=, ?room_id=, ?limit=
      if (path === "/api/posts" && req.method === "GET") {
        // Parse all query params
        const id_param = url.searchParams.get("id");
        const user_id_param = url.searchParams.get("user_id");
        const author_id_param = url.searchParams.get("author_id");
        const room_id_param = url.searchParams.get("room_id");
        const limit_param = url.searchParams.get("limit");

        // Build base query
        let q = sb(env)
          .from("posts")
          .select("*")
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

        const { data: posts, error } = await q;
        if (error) throw error;

        // Fetch media for all posts
        const postIds = (posts ?? []).map((p: any) => p.id);
        let mediaByPost: Record<number, any[]> = {};
        if (postIds.length > 0) {
          const { data: mediaRows } = await sb(env)
            .from("media")
            .select("*")
            .in("post_id", postIds);
          for (const m of mediaRows ?? []) {
            if (!mediaByPost[m.post_id]) mediaByPost[m.post_id] = [];
            mediaByPost[m.post_id].push(m);
          }
        }

        // Enrich posts with media
        const enrichedPosts = (posts ?? []).map((p: any) => ({
          ...p,
          media: mediaByPost[p.id] || [],
        }));

        return ok(req, env, request_id, { posts: enrichedPosts });
      }

      // /api/posts (POST)
      if (path === "/api/posts" && req.method === "POST") {
        const user_id = await requireAuth(req, env);

        const body = (await req.json().catch(() => null)) as any;
        const content = typeof body?.content === "string" ? body.content.trim() : "";
        if (!content) {
          throw new HttpError(422, "VALIDATION_ERROR", "content required");
        }

        // Parse optional author fields from request
        const title = typeof body?.title === "string" ? body.title.trim() : "";
        const author_id = typeof body?.author_id === "string" ? body.author_id : null;
        const author_name = typeof body?.author_name === "string" ? body.author_name : null;
        const author_avatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;
        const room_id = typeof body?.room_id === "string" ? body.room_id : null;

        // Parse optional media array
        const mediaInput = Array.isArray(body?.media) ? body.media : [];
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
          .insert({ user_id, content, title, author_id, author_name, author_avatar, room_id })
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

      // /api/comments (GET) ?post_id=123
      // Returns comments with like_count, liked_by_me, and media
      if (path === "/api/comments" && req.method === "GET") {
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

        const post_id_param = url.searchParams.get("post_id");
        let q = sb(env).from("comments").select("*").order("created_at", { ascending: false }).limit(200);
        if (post_id_param) q = q.eq("post_id", Number(post_id_param));
        const { data: comments, error } = await q;
        if (error) throw error;

        const commentList = comments ?? [];
        if (commentList.length === 0) {
          return ok(req, env, request_id, { comments: [] });
        }

        // Get like counts for all comments
        const commentIds = commentList.map((c: any) => c.id);
        const { data: likesData } = await sb(env)
          .from("comment_likes")
          .select("comment_id")
          .in("comment_id", commentIds);

        // Aggregate like counts
        const likeCounts: Record<number, number> = {};
        for (const like of likesData ?? []) {
          likeCounts[like.comment_id] = (likeCounts[like.comment_id] || 0) + 1;
        }

        // Get liked_by_me for current user
        const likedByMe: Set<number> = new Set();
        if (current_user_id) {
          const { data: userLikes } = await sb(env)
            .from("comment_likes")
            .select("comment_id")
            .in("comment_id", commentIds)
            .eq("user_id", current_user_id);
          for (const like of userLikes ?? []) {
            likedByMe.add(like.comment_id);
          }
        }

        // Fetch media for all comments
        let mediaByComment: Record<number, any[]> = {};
        const { data: mediaRows } = await sb(env)
          .from("media")
          .select("*")
          .in("comment_id", commentIds);
        for (const m of mediaRows ?? []) {
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
        const author_avatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;

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
            });
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
            });
          }
        }

        // Update post's last_activity_at timestamp (bump on new comment)
        await sb(env)
          .from("posts")
          .update({ last_activity_at: new Date().toISOString() })
          .eq("id", post_id);

        return ok(req, env, request_id, { comment: { ...data, media: mediaRows } }, 201);
      }

      // /api/comments/:id/like (POST = like, DELETE = unlike)
      {
        const m = path.match(/^\/api\/comments\/(\d+)\/like$/);
        if (m) {
          const comment_id = Number(m[1]);
          const user_id = await requireAuth(req, env);

          if (!Number.isFinite(comment_id)) {
            throw new HttpError(400, "BAD_REQUEST", "invalid comment_id");
          }

          if (req.method === "POST") {
            // Parse optional actor fields from request body
            const body = (await req.json().catch(() => ({}))) as any;
            const actor_name = typeof body?.actor_name === "string" ? body.actor_name : null;
            const actor_avatar = typeof body?.actor_avatar === "string" ? body.actor_avatar : null;

            // Toggle: try insert, if already exists then delete (unlike)
            const { error: insertError } = await sb(env)
              .from("comment_likes")
              .insert({ comment_id, user_id });

            // Postgres error 23505 = unique_violation (already liked)
            if (insertError && insertError.code === "23505") {
              // Already liked, so unlike (delete)
              const { error: deleteError } = await sb(env)
                .from("comment_likes")
                .delete()
                .eq("comment_id", comment_id)
                .eq("user_id", user_id);
              if (deleteError) throw deleteError;
              return ok(req, env, request_id, { liked: false });
            }

            if (insertError) throw insertError;

            // Create notification for like
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
              });
            }

            return ok(req, env, request_id, { liked: true }, 201);
          }

          if (req.method === "DELETE") {
            // Remove like (idempotent - no error if not exists)
            const { error } = await sb(env)
              .from("comment_likes")
              .delete()
              .eq("comment_id", comment_id)
              .eq("user_id", user_id);
            if (error) throw error;
            return ok(req, env, request_id, { ok: true });
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

        // Collect all comment IDs we need to fetch
        const commentIdSet = new Set<number>();
        for (const n of notifications) {
          if (n.comment_id) commentIdSet.add(n.comment_id);
          if (n.parent_comment_id) commentIdSet.add(n.parent_comment_id);
        }

        // Fetch all needed comments in one query
        let commentsMap: Record<number, string> = {};
        if (commentIdSet.size > 0) {
          const { data: commentsData } = await sb(env)
            .from("comments")
            .select("id, content")
            .in("id", Array.from(commentIdSet));
          for (const c of commentsData ?? []) {
            commentsMap[c.id] = c.content;
          }
        }

        // Enrich notifications with primary_text and secondary_text
        const enriched = notifications.map((n: any) => {
          let primary_text: string | null = null;
          let secondary_text: string | null = null;

          // primary_text = excerpt of n.comment_id content
          if (n.comment_id && commentsMap[n.comment_id]) {
            primary_text = excerpt(commentsMap[n.comment_id]);
          }

          // secondary_text = excerpt of n.parent_comment_id content (only for reply)
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

      // GET /api/notifications/unread_count
      if (path === "/api/notifications/unread_count" && req.method === "GET") {
        const user_id = await requireAuth(req, env);

        const { count, error } = await sb(env)
          .from("notifications")
          .select("id", { count: "exact", head: true })
          .eq("recipient_user_id", user_id)
          .eq("is_read", false);

        if (error) throw error;

        return ok(req, env, request_id, { unread_count: count ?? 0 });
      }

      // POST /api/upload-url -> presigned PUT URL for R2
      // Body: { kind: "image_original" | "image_thumb" | "video_original" | "video_thumb" | "video" | "thumb", content_type: string }
      if (path === "/api/upload-url" && req.method === "POST") {
        const user_id = await requireAuth(req, env);

        const body = (await req.json().catch(() => null)) as any;
        const kind = body?.kind as string | undefined;
        const content_type = typeof body?.content_type === "string" ? body.content_type : null;

        // Validate kind
        const validKinds = ["image_original", "image_thumb", "video_original", "video_thumb", "video", "thumb"] as const;
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
        if (isImage && !content_type.startsWith("image/")) {
          throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with image/ for image kinds");
        }
        if (isVideo && !content_type.startsWith("video/")) {
          throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with video/ for video kinds");
        }
        if (isThumb && !content_type.startsWith("image/")) {
          throw new HttpError(422, "VALIDATION_ERROR", "content_type must start with image/ for thumb kind");
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

        const ext = content_type.split("/")[1]?.split(";")[0] || (isImage || isThumb ? "jpg" : "mp4");
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
          const key = decodeURIComponent(mediaMatch[1]);

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
            return fail(req, env, request_id, 404, "NOT_FOUND", "Media not found");
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

      // POST /api/saves - Save a post (bookmark)
      if (path === "/api/saves" && req.method === "POST") {
        console.log("[POST /api/saves] Start");
        const user_id = await requireAuth(req, env);
        console.log("[POST /api/saves] user_id=", user_id);

        const body = (await req.json().catch(() => null)) as any;
        const post_id = Number(body?.post_id);
        console.log("[POST /api/saves] post_id=", post_id);

        if (!Number.isFinite(post_id) || post_id <= 0) {
          throw new HttpError(422, "VALIDATION_ERROR", "post_id must be a valid positive integer");
        }

        // Verify post exists
        const { data: post, error: postError } = await sb(env)
          .from("posts")
          .select("id")
          .eq("id", post_id)
          .single();
        if (postError) {
          console.log("[POST /api/saves] postError=", postError);
        }
        if (postError || !post) {
          throw new HttpError(404, "NOT_FOUND", "Post not found");
        }

        // Insert (idempotent - ignore duplicates)
        console.log("[POST /api/saves] Inserting save...");
        const { error: insertError } = await sb(env)
          .from("saves")
          .insert({ user_id, post_id });

        if (insertError) {
          console.log("[POST /api/saves] insertError=", insertError.code, insertError.message);
        }

        // Postgres error 23505 = unique_violation (already saved)
        if (insertError && insertError.code !== "23505") {
          throw insertError;
        }

        console.log("[POST /api/saves] Success");
        return ok(req, env, request_id, { ok: true }, 201);
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

      // GET /api/saves/counts?post_ids=1,2,3 - Get save counts for multiple posts (public)
      if (path === "/api/saves/counts" && req.method === "GET") {
        const postIdsParam = url.searchParams.get("post_ids") || "";
        const postIds = postIdsParam
          .split(",")
          .map(s => parseInt(s.trim(), 10))
          .filter(n => Number.isFinite(n) && n > 0)
          .slice(0, 200); // Limit to 200

        if (postIds.length === 0) {
          throw new HttpError(400, "BAD_REQUEST", "post_ids is required (comma-separated integers)");
        }

        // Aggregate count per post_id
        const { data: rows, error } = await sb(env)
          .from("saves")
          .select("post_id")
          .in("post_id", postIds);
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

        return ok(req, env, request_id, { counts });
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
        const blocker_user_id = await requireAuth(req, env);

        const { data: rows, error } = await sb(env)
          .from("blocks")
          .select("blocked_user_id, created_at")
          .eq("blocker_user_id", blocker_user_id)
          .order("created_at", { ascending: false });
        if (error) throw error;

        const blocked = (rows ?? []).map(r => ({
          user_id: r.blocked_user_id,
          created_at: r.created_at,
        }));

        return ok(req, env, request_id, { blocked });
      }

      // GET /api/blocks/relations?user_ids=a,b,c - Check mutual blocks for filtering
      if (path === "/api/blocks/relations" && req.method === "GET") {
        const my_user_id = await requireAuth(req, env);

        const userIdsParam = url.searchParams.get("user_ids") || "";
        const userIds = userIdsParam
          .split(",")
          .map(s => s.trim())
          .filter(s => s.length > 0)
          .slice(0, 200);

        if (userIds.length === 0) {
          return ok(req, env, request_id, { blocked_user_ids: [] });
        }

        // Users I blocked
        const { data: iBlocked, error: e1 } = await sb(env)
          .from("blocks")
          .select("blocked_user_id")
          .eq("blocker_user_id", my_user_id)
          .in("blocked_user_id", userIds);
        if (e1) throw e1;

        // Users who blocked me
        const { data: blockedMe, error: e2 } = await sb(env)
          .from("blocks")
          .select("blocker_user_id")
          .eq("blocked_user_id", my_user_id)
          .in("blocker_user_id", userIds);
        if (e2) throw e2;

        const blockedSet = new Set<string>();
        for (const row of iBlocked ?? []) blockedSet.add(row.blocked_user_id);
        for (const row of blockedMe ?? []) blockedSet.add(row.blocker_user_id);

        return ok(req, env, request_id, { blocked_user_ids: Array.from(blockedSet) });
      }

      // =====================================================
      // ECHOES API (Private follow-like, no counts/notifications)
      // =====================================================

      // Helper: check if mutual block exists
      async function isMutuallyBlocked(userId1: string, userId2: string): Promise<boolean> {
        const { data: rows } = await sb(env)
          .from("blocks")
          .select("id")
          .or(`and(blocker_user_id.eq.${userId1},blocked_user_id.eq.${userId2}),and(blocker_user_id.eq.${userId2},blocked_user_id.eq.${userId1})`)
          .limit(1);
        return (rows ?? []).length > 0;
      }

      // POST /api/echoes - Echo a user
      if (path === "/api/echoes" && req.method === "POST") {
        const user_id = await requireAuth(req, env);

        const body = (await req.json().catch(() => null)) as any;
        const echoed_user_id = body?.user_id;

        if (!echoed_user_id || typeof echoed_user_id !== "string") {
          throw new HttpError(400, "BAD_REQUEST", "user_id is required");
        }
        if (echoed_user_id === user_id) {
          throw new HttpError(400, "BAD_REQUEST", "Cannot echo yourself");
        }

        // Block enforcement: check mutual block
        if (await isMutuallyBlocked(user_id, echoed_user_id)) {
          throw new HttpError(403, "BLOCKED", "Cannot echo a blocked user");
        }

        // Insert (idempotent - ignore duplicates)
        const { error } = await sb(env)
          .from("echoes")
          .insert({ user_id, echoed_user_id });

        // Postgres 23505 = unique_violation (already echoing)
        if (error && error.code !== "23505") {
          throw error;
        }

        return ok(req, env, request_id, { ok: true });
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

      // GET /api/echoes - List users I echo (private, newest first)
      if (path === "/api/echoes" && req.method === "GET") {
        const user_id = await requireAuth(req, env);

        // Get echoed users
        const { data: rows, error } = await sb(env)
          .from("echoes")
          .select("echoed_user_id, created_at")
          .eq("user_id", user_id)
          .order("created_at", { ascending: false });
        if (error) throw error;

        // Filter out mutually blocked users (safety)
        const echoedIds = (rows ?? []).map(r => r.echoed_user_id);
        let blockedIds = new Set<string>();
        if (echoedIds.length > 0) {
          // Users I blocked among echoedIds
          const { data: iBlocked } = await sb(env)
            .from("blocks")
            .select("blocked_user_id")
            .eq("blocker_user_id", user_id)
            .in("blocked_user_id", echoedIds);
          // Users who blocked me among echoedIds
          const { data: blockedMe } = await sb(env)
            .from("blocks")
            .select("blocker_user_id")
            .eq("blocked_user_id", user_id)
            .in("blocker_user_id", echoedIds);
          for (const r of iBlocked ?? []) blockedIds.add(r.blocked_user_id);
          for (const r of blockedMe ?? []) blockedIds.add(r.blocker_user_id);
        }

        const echoed = (rows ?? [])
          .filter(r => !blockedIds.has(r.echoed_user_id))
          .map(r => ({
            user_id: r.echoed_user_id,
            created_at: r.created_at,
          }));

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
          .order("created_at", { ascending: true })
          .limit(limit);
        if (error) throw error;

        const commentList = comments ?? [];
        if (commentList.length === 0) {
          return ok(req, env, request_id, { comments: [] });
        }

        // Get like counts
        const commentIds = commentList.map((c: any) => c.id);
        const { data: likesData } = await sb(env)
          .from("news_comment_likes")
          .select("comment_id")
          .in("comment_id", commentIds);

        const likeCounts: Record<number, number> = {};
        for (const like of likesData ?? []) {
          likeCounts[like.comment_id] = (likeCounts[like.comment_id] || 0) + 1;
        }

        // Get liked_by_me
        const likedByMe: Set<number> = new Set();
        if (current_user_id) {
          const { data: userLikes } = await sb(env)
            .from("news_comment_likes")
            .select("comment_id")
            .in("comment_id", commentIds)
            .eq("user_id", current_user_id);
          for (const like of userLikes ?? []) {
            likedByMe.add(like.comment_id);
          }
        }

        // Enrich comments
        const enrichedComments = commentList.map((c: any) => ({
          ...c,
          like_count: likeCounts[c.id] || 0,
          liked_by_me: likedByMe.has(c.id),
        }));

        return ok(req, env, request_id, { comments: enrichedComments });
      }

      // POST /api/news/comments - create a news comment
      if (path === "/api/news/comments" && req.method === "POST") {
        console.log("[NEWS COMMENT CREATE] hit");
        const user_id = await requireAuth(req, env);
        console.log("[NEWS COMMENT CREATE] user_id:", user_id);

        const body = (await req.json().catch(() => null)) as any;
        console.log("[NEWS COMMENT CREATE] body:", JSON.stringify(body));

        const news_url = typeof body?.news_url === "string" ? body.news_url.trim() : "";
        const content = typeof body?.content === "string" ? body.content.trim() : "";
        const parent_comment_id =
          typeof body?.parent_comment_id === "number" ? body.parent_comment_id : null;
        const author_name = typeof body?.author_name === "string" ? body.author_name : null;
        const author_avatar = typeof body?.author_avatar === "string" ? body.author_avatar : null;

        if (!news_url) {
          throw new HttpError(400, "BAD_REQUEST", "news_url is required");
        }
        if (!content) {
          throw new HttpError(400, "BAD_REQUEST", "content is required");
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
          content,
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
        return ok(req, env, request_id, {
          comment: { ...data, like_count: 0, liked_by_me: false }
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

      // GET /api/news/comments/counts?news_ids=id1,id2,...
      if (path === "/api/news/comments/counts" && req.method === "GET") {
        const newsIdsParam = url.searchParams.get("news_ids") || "";
        const newsIds = newsIdsParam
          .split(",")
          .map(s => s.trim())
          .filter(s => s.length > 0)
          .slice(0, 200);

        if (newsIds.length === 0) {
          return ok(req, env, request_id, { counts: {} });
        }

        // Get counts grouped by news_id
        const { data: rows, error } = await sb(env)
          .from("news_comments")
          .select("news_id")
          .in("news_id", newsIds);
        if (error) throw error;

        const countMap: Record<string, number> = {};
        for (const row of rows ?? []) {
          countMap[row.news_id] = (countMap[row.news_id] || 0) + 1;
        }

        // Build response with 0 for ids that had no comments
        const counts: Record<string, number> = {};
        for (const id of newsIds) {
          counts[id] = countMap[id] || 0;
        }

        return ok(req, env, request_id, { counts });
      }

      // GET /api/news/comments/recent?news_ids=id1,id2,...&limit=10
      if (path === "/api/news/comments/recent" && req.method === "GET") {
        const newsIdsParam = url.searchParams.get("news_ids") || "";
        const newsIds = newsIdsParam
          .split(",")
          .map(s => s.trim())
          .filter(s => s.length > 0)
          .slice(0, 100);

        const limitParam = url.searchParams.get("limit");
        let limit = 10;
        if (limitParam) {
          const parsed = Number(limitParam);
          if (Number.isFinite(parsed) && parsed > 0) {
            limit = Math.min(parsed, 50);
          }
        }

        if (newsIds.length === 0) {
          return ok(req, env, request_id, { recent: {} });
        }

        // Fetch all comments for these news_ids, newest first
        const fetchLimit = newsIds.length * limit * 2;
        const { data: allComments, error } = await sb(env)
          .from("news_comments")
          .select("id, news_id, content, created_at")
          .in("news_id", newsIds)
          .order("created_at", { ascending: false })
          .limit(fetchLimit);
        if (error) throw error;

        // Group by news_id and take first N per group
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

        return ok(req, env, request_id, { recent });
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
  },
};
