const te = new TextEncoder();

function b64urlToBytes(s: string) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  const b64 = s + "=".repeat(pad);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64url(bytes: ArrayBuffer) {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmacSha256(secret: string, data: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    te.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, te.encode(data));
  return bytesToB64url(sig);
}

export async function signToken(secret: string, payload: Record<string, unknown>) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = bytesToB64url(te.encode(JSON.stringify(header)).buffer);
  const p = bytesToB64url(te.encode(JSON.stringify(payload)).buffer);
  const body = `${h}.${p}`;
  const s = await hmacSha256(secret, body);
  return `${body}.${s}`;
}

export async function verifyToken(secret: string, token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const body = `${h}.${p}`;
  const expected = await hmacSha256(secret, body);
  if (expected !== s) return null;

  try {
    const payloadJson = new TextDecoder().decode(b64urlToBytes(p));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}
