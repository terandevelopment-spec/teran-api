// ~/Desktop/teran-api/src/index.ts
import { createClient } from "@supabase/supabase-js";

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_SECRET: string;
  CORS_ORIGIN?: string; // optional: "http://localhost:5173" etc
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
    "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
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

      // /api/posts (GET)
      if (path === "/api/posts" && req.method === "GET") {
        const { data, error } = await sb(env)
          .from("posts")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(50);
        if (error) throw error;
        return ok(req, env, request_id, { posts: data ?? [] });
      }

      // /api/posts (POST)
      if (path === "/api/posts" && req.method === "POST") {
        const user_id = await requireAuth(req, env);

        const body = (await req.json().catch(() => null)) as any;
        const content = typeof body?.content === "string" ? body.content.trim() : "";
        if (!content) {
          throw new HttpError(422, "VALIDATION_ERROR", "content required");
        }

        const { data, error } = await sb(env)
          .from("posts")
          .insert({ user_id, content })
          .select("*")
          .single();
        if (error) throw error;
        return ok(req, env, request_id, { post: data }, 201);
      }

      // /api/posts/:id (DELETE)
      {
        const m = path.match(/^\/api\/posts\/(\d+)$/);
        if (m && req.method === "DELETE") {
          const user_id = await requireAuth(req, env);

          const id = Number(m[1]);

          // First check if the post exists and belongs to the user
          const { data: existingPost, error: fetchError } = await sb(env)
            .from("posts")
            .select("id, user_id")
            .eq("id", id)
            .single();

          if (fetchError || !existingPost) {
            throw new HttpError(404, "NOT_FOUND", "Post not found");
          }

          if (existingPost.user_id !== user_id) {
            throw new HttpError(403, "FORBIDDEN", "You can only delete your own posts");
          }

          const { error } = await sb(env)
            .from("posts")
            .delete()
            .eq("id", id);
          if (error) throw error;
          return ok(req, env, request_id, { ok: true });
        }
      }

      // /api/comments (GET) ?post_id=123
      if (path === "/api/comments" && req.method === "GET") {
        const post_id_param = url.searchParams.get("post_id");
        let q = sb(env).from("comments").select("*").order("created_at", { ascending: true }).limit(200);
        if (post_id_param) q = q.eq("post_id", Number(post_id_param));
        const { data, error } = await q;
        if (error) throw error;
        return ok(req, env, request_id, { comments: data ?? [] });
      }

      // /api/comments (POST) -> { post_id, content }
      if (path === "/api/comments" && req.method === "POST") {
        const user_id = await requireAuth(req, env);

        const body = (await req.json().catch(() => null)) as any;
        const post_id = Number(body?.post_id);
        const content = typeof body?.content === "string" ? body.content.trim() : "";
        const parent_comment_id =
          typeof body?.parent_comment_id === "number" ? body.parent_comment_id : null;
        if (!post_id || !content) {
          throw new HttpError(422, "VALIDATION_ERROR", "post_id & content required");
        }

        const { data, error } = await sb(env)
          .from("comments")
          .insert({ post_id, user_id, content, parent_comment_id })
          .select("*")
          .single();
        if (error) throw error;
        return ok(req, env, request_id, { comment: data }, 201);
      }

      throw new HttpError(404, "NOT_FOUND", "Not found");
    } catch (e: any) {
      if (e instanceof HttpError) {
        return fail(req, env, request_id, e.status, e.code, e.message);
      }

      // Supabase errors: surface as 500 with safe message (no secrets)
      const msg = typeof e?.message === "string" ? e.message : "Internal error";
      return fail(req, env, request_id, 500, "INTERNAL_ERROR", msg);
    }
  },
};
