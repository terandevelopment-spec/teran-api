// k6 MIX load test: 80% READ (GET /api/posts) + 20% WRITE (POST /api/posts)
// Default target: loadtest Worker (never production)
// Token: pass via -e TOKEN=... to skip /api/identity, or auto-fetch with retry.
// Run:
//   cd ~/Desktop/teran-api
//   k6 run -e TOKEN="eyJ..." -e BASE_URL=https://teran-api-loadtest.teran-development.workers.dev k6/mix_posts.js
//   k6 run -e BASE_URL=https://teran-api-loadtest.teran-development.workers.dev k6/mix_posts.js

import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "https://teran-api-loadtest.teran-development.workers.dev";
const SLEEP_S = parseFloat(__ENV.SLEEP || "0.5");

export const options = {
    stages: [
        { duration: "10s", target: 2 },
        { duration: "30s", target: 10 },
        { duration: "10s", target: 0 },
    ],
    thresholds: {
        http_req_failed: ["rate<0.05"],
        http_req_duration: ["p(95)<2000"],
    },
};

const readUrl = `${BASE_URL}/api/posts?limit=20&root_only=1&post_type=status,thread&room_scope=global`;
const writeUrl = `${BASE_URL}/api/posts`;

export function setup() {
    // Prefer pre-supplied token (skips /api/identity entirely)
    if (__ENV.TOKEN) {
        console.log("setup: using TOKEN from env (no /api/identity call)");
        return { token: __ENV.TOKEN };
    }

    // Auto-fetch with retry + exponential backoff
    const maxAttempts = 5;
    for (let i = 0; i < maxAttempts; i++) {
        const res = http.post(`${BASE_URL}/api/identity`, null, {
            headers: { "Content-Type": "application/json" },
        });

        if (res.status === 429) {
            const backoff = Math.pow(2, i) * 0.5 * (0.5 + Math.random());
            console.log(`setup: /api/identity 429, retry ${i + 1}/${maxAttempts} after ${backoff.toFixed(1)}s`);
            sleep(backoff);
            continue;
        }

        if (res.status < 200 || res.status >= 300) {
            throw new Error(`setup: /api/identity failed: ${res.status} ${res.body}`);
        }

        const body = JSON.parse(res.body);
        if (!body.token) {
            throw new Error(`setup: /api/identity returned no token: ${res.body}`);
        }
        console.log(`setup: got token for user_id=${body.user_id}`);
        return { token: body.token };
    }

    throw new Error("setup: /api/identity failed after 5 retries (429 rate-limited). Pass -e TOKEN=... to skip.");
}

function getRid(res) {
    const hdr = res.headers["X-Req-Id"] || res.headers["x-req-id"]
        || res.headers["X-Request-Id"] || res.headers["x-request-id"]
        || "";
    if (hdr) return hdr;
    try { return JSON.parse(res.body).request_id || ""; } catch (_) { return ""; }
}

export default function (data) {
    if (Math.random() < 0.8) {
        // ── GET (80%) ──
        const res = http.get(readUrl, {
            headers: { "Content-Type": "application/json" },
            tags: { op: "get" },
        });

        if (res.status === 429) {
            console.log(`GET 429 body=${res.body} rid=${getRid(res)}`);
            sleep(1 + Math.random());
            return;
        }

        const ok = check(res, { "GET status is 200": (r) => r.status === 200 });
        if (!ok) {
            console.log(`GET FAIL status=${res.status} body=${res.body} rid=${getRid(res)}`);
        }
    } else {
        // ── POST (20%) ── skip if no valid token
        if (!data.token) {
            return;
        }

        const payload = JSON.stringify({
            post_type: "status",
            room_id: "global",
            title: "",
            content: `loadtest-mix ${__VU}-${__ITER}-${Date.now()}`,
        });
        const res = http.post(writeUrl, payload, {
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${data.token}`,
            },
            tags: { op: "post" },
        });

        if (res.status === 429) {
            console.log(`POST 429 body=${res.body} rid=${getRid(res)}`);
            sleep(1 + Math.random());
            return;
        }

        const ok = check(res, { "POST status is 2xx": (r) => r.status >= 200 && r.status < 300 });
        if (!ok) {
            console.log(`POST FAIL status=${res.status} body=${res.body} rid=${getRid(res)}`);
        }
    }

    sleep(SLEEP_S);
}
