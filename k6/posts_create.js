// k6 WRITE load test: POST /api/posts (auto-fetches JWT via /api/identity)
// Default target: loadtest Worker (never production)
// Run:
//   cd ~/Desktop/teran-api
//   k6 run k6/posts_create.js
// Override base URL:
//   k6 run -e BASE_URL=https://... k6/posts_create.js

import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "https://teran-api-loadtest.teran-development.workers.dev";
const SLEEP_S = parseFloat(__ENV.SLEEP || "0.5");

export const options = {
    stages: [
        { duration: "10s", target: 1 },
        { duration: "20s", target: 5 },
        { duration: "10s", target: 0 },
    ],
    thresholds: {
        http_req_failed: ["rate<0.05"],
        http_req_duration: ["p(95)<2000"],
    },
};

export function setup() {
    const res = http.post(`${BASE_URL}/api/identity`, null, {
        headers: { "Content-Type": "application/json" },
    });
    if (res.status < 200 || res.status >= 300) {
        throw new Error(`/api/identity failed: ${res.status} ${res.body}`);
    }
    const body = JSON.parse(res.body);
    if (!body.token) {
        throw new Error(`/api/identity returned no token: ${res.body}`);
    }
    console.log(`setup: got token for user_id=${body.user_id}`);
    return { token: body.token };
}

const url = `${BASE_URL}/api/posts`;

export default function (data) {
    const payload = JSON.stringify({
        post_type: "status",
        room_id: "global",
        title: "",
        content: `k6 write ${__VU}-${__ITER}-${Date.now()}`,
    });

    const res = http.post(url, payload, {
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${data.token}`,
        },
    });

    const ok = check(res, {
        "status is 2xx": (r) => r.status >= 200 && r.status < 300,
    });

    if (!ok) {
        console.log(`FAIL ${res.status} ${res.body}`);
    }

    sleep(SLEEP_S);
}
