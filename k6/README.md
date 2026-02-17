# k6 Load Tests — Teran API

## Prerequisites

Install k6: <https://grafana.com/docs/k6/latest/set-up/install-k6/>

```bash
brew install k6
```

## Run (default)

```bash
k6 run k6/posts_global.js
```

## Run against dev explicitly

```bash
BASE_URL="https://teran-api.teran-development.workers.dev" k6 run k6/posts_global.js
```

## Increase load

```bash
k6 run --vus 20 --duration 30s k6/posts_global.js
```

## Override params

```bash
LIMIT=100 SLEEP=0.5 k6 run k6/posts_global.js
```

## Env vars

| Variable     | Default                                                    | Description            |
| ------------ | ---------------------------------------------------------- | ---------------------- |
| `BASE_URL`   | `https://teran-api.teran-development.workers.dev`          | API root URL           |
| `LIMIT`      | `60`                                                       | Posts per page          |
| `SLEEP`      | `1`                                                        | Sleep between requests  |
| `POST_TYPES` | `status,thread`                                            | Comma-separated types   |

## Notes

- Auth is **not** included yet. If auth is required later, add an `Authorization` header in the script.
- Thresholds: p95 < 800ms, error rate < 1%.
