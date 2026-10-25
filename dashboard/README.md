# Sentinel dashboard

Single-page dark dashboard for Sentinel. Vite + React + TypeScript + Recharts + Tailwind v4.
Builds to `dist/`, which the Worker serves as static assets; the API is same-origin under `/api/*`
(contract: [`../docs/api.md`](../docs/api.md)).

## Run

```sh
npm ci
npm run dev        # http://localhost:5173, /api/* served by a fixture mock (mock/plugin.ts)
npm run build      # tsc -b && vite build -> dist/
```

Against a local Worker instead of the mock:

```sh
VITE_API_PROXY=http://127.0.0.1:8787 npm run dev   # proxies /api to `wrangler dev`
```

Mock switches (dev only): `MOCK_FAIL=alerts,metrics` makes those endpoints return 503 to exercise
the stale/error states; `MOCK_LIVE=1` serves non-seed rows and a reporting sensor.

## Behavior

- Polls every endpoint every 10 s with `If-None-Match`; a 304 keeps the cached body. Polling pauses
  while the tab is hidden and fires immediately when it is visible again.
- Each panel shows "updated Ns ago", turns "stale" after 30 s without a good response or on error,
  and keeps showing its last good data. Skeletons only on first load.
- The demo badge appears when any visible row has `is_seed` or `/api/metrics` reports `seed_active`.

Layout: `src/lib/` (types, polling, formatting), `src/components/` (one file per panel).
