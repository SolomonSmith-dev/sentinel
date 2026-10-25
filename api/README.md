# sentinel api

Cloudflare Worker (Hono + D1) behind `https://sentinel.solomonsmith.dev`. It serves `/api/*` and the dashboard's static assets (`../dashboard/dist`, SPA fallback). The contract lives in [`../docs/api.md`](../docs/api.md).

## Endpoints

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/ingest` | Bearer `SENTINEL_TOKEN`, gzip optional, `Idempotency-Key` = sha256 of the uncompressed body |
| GET | `/api/flows?minutes=60` | per-minute totals, minutes 5 to 1440 |
| GET | `/api/alerts?limit=50&since=<ts>` | newest first |
| GET | `/api/devices` | last 7 days, by `last_score` desc. Cache API 10 s |
| GET | `/api/top?minutes=60` | top 10 devices and countries. Cache API 10 s |
| GET | `/api/metrics` | ingest stats, sensor state, row counts |
| GET | `/api/health` | `{"ok":true}`, no D1 |

Crons: `*/5` seed top-up (only while no real window arrived in 15 min), `17 3 * * *` prune.

## Local dev

```sh
npm ci
echo 'SENTINEL_TOKEN=local-dev-token' > .dev.vars   # gitignored, throwaway
npm run migrate:local
npm run seed:local       # optional: 24 h of demo data in local D1
npm run dev              # wrangler dev on :8787
```

## Test

```sh
npm run typecheck
npm test                 # vitest inside workerd via @cloudflare/vitest-plugin
```

## Seed and deploy

```sh
npm run migrate:remote
npm run seed:remote      # backfill the last 24 h of is_seed=1 rows (about 11.6k rows)
wrangler secret put SENTINEL_TOKEN
wrangler deploy          # build ../dashboard first
```

The seed generator (`src/seed.ts`) is deterministic, so re-running the backfill is a no-op on existing minutes.
