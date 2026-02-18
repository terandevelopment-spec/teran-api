import http from "k6/http";
import { check, sleep } from "k6";

// ── Env-configurable params ──
const BASE_URL = __ENV.BASE_URL || "https://teran-api-loadtest.teran-development.workers.dev";
const LIMIT = __ENV.LIMIT || "60";
const SLEEP_S = parseFloat(__ENV.SLEEP || "1");
const POST_TYPES = __ENV.POST_TYPES || "status,thread";

// ── k6 options ──
export const options = {
    stages: [
        { duration: "10s", target: 1 },   // warmup
        { duration: "20s", target: 5 },   // steady
        { duration: "10s", target: 0 },   // cooldown
    ],
    thresholds: {
        http_req_failed: ["rate<0.01"],        // <1% errors
        http_req_duration: ["p(95)<800"],         // p95 < 800ms
    },
};

// ── Build URL with properly encoded query params ──
const params = [
    `post_type=${encodeURIComponent(POST_TYPES)}`,
    `root_only=1`,
    `room_scope=global`,
    `limit=${encodeURIComponent(LIMIT)}`,
].join("&");

const url = `${BASE_URL}/api/posts?${params}`;

export default function () {
    const res = http.get(url, {
        headers: { accept: "application/json" },
    });

    check(res, {
        "status is 200": (r) => r.status === 200,
    });

    sleep(SLEEP_S);
}
