# Sentinel API contract

Every component codes to this file. Change it only through the orchestrator.

Origin: `https://sentinel.solomonsmith.dev`. One Worker serves the dashboard as static assets and everything under `/api/*`. Same origin, no CORS.

Conventions
- Timestamps are integer Unix seconds (UTC).
- `device_hash` is `dev-` + the first 6 hex chars of `sha256(mac_lowercase + salt)`. Example `dev-3fa91c`.
- No IPv4, IPv6 or MAC address ever appears in any request or response. The Worker rejects an ingest body that matches an IP or MAC pattern (see Privacy guard).
- Every row carries `is_seed` (0 or 1). Seed rows are synthetic demo data.
- Errors: `{"error": "<code>", "message": "<text>"}` with the matching HTTP status.

## POST /api/ingest

Auth: `Authorization: Bearer <SENTINEL_TOKEN>`. Missing or wrong → 401 `unauthorized`.

Headers
- `Content-Type: application/json`
- `Content-Encoding: gzip` (optional; the shipper always sends it)
- `Idempotency-Key: <sha256 hex of the uncompressed JSON body>`. Required. The Worker recomputes the hash; mismatch → 400 `checksum_mismatch`. A key already seen in the last 24h → 200 `{"status":"duplicate"}` and nothing is written.

Limits
- Raw (as sent) body over 256 KB → 413 `too_large`. Decompressed body over 1 MB → 413.
- At most 500 windows, 500 alerts, 200 devices per batch → 400 `too_many_items`.
- Rate limit: 60 requests per minute per client IP → 429 `rate_limited`.
- Worker var `INGEST_ENABLED="false"` → 503 `ingest_disabled` (kill switch).
- D1 write failure → 503 `storage_unavailable`. The sensor keeps the batch queued and retries.

Body
```json
{
  "sensor_id": "sensor-01",
  "sent_at": 1761370800,
  "queue_depth": 0,
  "devices": [
    {"device_hash": "dev-3fa91c", "vendor": "Apple", "first_seen": 1761370740}
  ],
  "windows": [
    {
      "device_hash": "dev-3fa91c",
      "ts": 1761370740,
      "duration_s": 60,
      "bytes_in": 120394,
      "bytes_out": 20311,
      "pkts": 412,
      "distinct_dests": 9,
      "distinct_ports": 4,
      "syn_ratio": 0.03,
      "score": 0.41,
      "countries": {"US": 130000, "DE": 10705}
    }
  ],
  "alerts": [
    {
      "id": "6f1c0f0e-2b8a-4a51-9a63-0f7c6d1e2a10",
      "type": "port_scan",
      "device_hash": "dev-3fa91c",
      "ts": 1761370752,
      "severity": "high",
      "detail": {"distinct_ports": 87, "window_s": 10}
    }
  ]
}
```

Field rules
- `windows[].ts` is the start of a 60 s bucket (`ts % 60 == 0`). The sensor scores 10 s windows locally and rolls them up to 60 s before shipping. `score` is the max 10 s score in the bucket, in [0,1], or `null` when no model is loaded.
- `countries` maps ISO 3166-1 alpha-2 codes (or `"??"` for unknown) to bytes exchanged. Keys must match `^[A-Z?]{2}$`.
- `alerts[].type` is one of `flood`, `port_scan`, `new_device`, `geo_anomaly`, `ml_anomaly`, `suricata`.
- `alerts[].severity` is one of `low`, `medium`, `high`, `critical`.
- `alerts[].detail` is a flat-ish JSON object, at most 2 KB serialized. For `suricata`: `{"signature": "...", "sid": 2010935, "category": "..."}`. For `geo_anomaly`: `{"country": "RU"}`.
- `devices[].vendor` is an OUI vendor name, `"Private MAC"` for locally administered addresses, or `"Unknown"`.
- Upserts: windows on `(device_hash, ts)`, alerts on `id`, devices on `device_hash` (keeps the earliest `first_seen`, updates `last_seen`).
- The server stamps `received_at` on every row. Reads order by `ts`, but the server clamps `ts` to `received_at + 300` to absorb clock skew.

Success: 200 `{"status":"ok","windows":N,"alerts":N,"devices":N,"request_id":"..."}`.

Privacy guard: the Worker scans both decompressed JSON text and decoded content for IPv4, MAC and IPv6-looking tokens, plus local DNS names under `.local`, `.lan`, `.home`, `.internal`, `.localhost`, and `.home.arpa` (case insensitive). Any match returns 400 `pii_rejected`. The sensor uses matching patterns and redacts Suricata text before sending. Arbitrary single-label hostnames and custom/public suffixes cannot reliably be identified from free text. Shared classification vectors live in `api/test/pii-vectors.json`.

## Read endpoints

All are public, `GET`, JSON, and send `ETag` and `Cache-Control: public, max-age=10`. `If-None-Match` matching → 304. Worker caches `/api/top` and `/api/devices` for 10 s with the Cache API.

### GET /api/flows?minutes=60
`minutes` in [5, 1440], default 60. Per-minute totals across all devices.
```json
{"minutes": 60, "points": [{"ts": 1761370740, "bytes_in": 1, "bytes_out": 2, "pkts": 3}], "is_seed": true}
```
`is_seed` is true when any contributing row is seed.

### GET /api/alerts?limit=50&since=<ts>
`limit` in [1, 200], default 50. Newest first.
```json
{"alerts": [{"id": "...", "type": "port_scan", "device_hash": "dev-3fa91c", "ts": 1, "severity": "high", "detail": {}, "is_seed": 1}]}
```

### GET /api/devices
```json
{"devices": [{"device_hash": "dev-3fa91c", "vendor": "Apple", "first_seen": 1, "last_seen": 2, "last_score": 0.41, "alerts_24h": 3, "bytes_24h": 1234, "is_seed": 1}]}
```
Devices seen in the last 7 days, sorted by `last_score` desc (nulls last).

### GET /api/top?minutes=60
```json
{"minutes": 60, "devices": [{"device_hash": "dev-3fa91c", "vendor": "Apple", "bytes": 1234, "is_seed": 1}], "countries": [{"country": "US", "bytes": 1234}]}
```
Top 10 of each by total bytes.

### GET /api/metrics
```json
{
  "ingest": {"count_24h": 2880, "failed_24h": {"401": 0, "413": 0, "429": 0, "503": 0}, "p50_ms": 12, "p95_ms": 40},
  "sensor": {"sensor_id": "sensor-01", "last_seen": 1761370800, "queue_depth": 0},
  "rows": {"devices": 12, "windows": 10000, "alerts": 40},
  "seed_active": true
}
```
The Worker records each ingest attempt (status, duration ms) in `ingest_log`. `sensor` is null until a real sensor has posted.

`rows` is a snapshot refreshed after each successful cron run (normally every five minutes),
not a live count. Public requests read one snapshot row instead of scanning telemetry tables.
Until the first snapshot exists, counts are zero. Unknown query parameters are ignored by
read-cache keys; supported numeric parameters are clamped and normalized before caching.

### GET /api/health
`{"ok": true}`. No D1 access.

## Storage (D1, `api/migrations/`)

Tables: `devices`, `windows`, `alerts`, `ingest_log`, `idempotency`, `seed_marker`. Every data table has `is_seed INTEGER NOT NULL DEFAULT 0` and `received_at INTEGER NOT NULL`.

Migration `0003_row_counts.sql` adds the singleton `row_counts` snapshot and initializes it
from existing data. Apply this migration before deploying the updated Worker. Cron refreshes
still scan the three telemetry tables; the scan frequency is bounded independently of traffic.

## Cron

- `*/5 * * * *` seed top-up: if no real (non-seed) window arrived in the last 15 minutes, insert seed windows for the minutes missing since the last seed write (8 synthetic devices, plausible diurnal traffic, an occasional seed alert). Keeps the URL live-looking without a sensor. Stops writing once real data flows.
- `17 3 * * *` prune: delete real rows older than 7 days, seed rows older than 24 h, `idempotency` and `ingest_log` rows older than 24 h.

Free-tier budget: D1 allows 100k rows written per day, and every index entry counts as a row written (measured: the 24 h seed backfill cost 57.8k row-writes for 11.6k rows). `windows` therefore carries a single secondary index. The sensor never ships a window with `pkts == 0` and sends a device in `devices` only when it is new or was last sent more than 10 minutes ago. A LAN with 20 devices active at once stays near 60k row-writes a day; seed top-up stops once real data flows.

Read protection: telemetry GETs allow 120 requests per minute per client IP. Cache misses additionally share a 120/minute budget per Cloudflare location (best effort, not a global billing cap). Alert cursors and limits filter a shared latest-200, seven-day snapshot without extra D1 reads. Rate-limited responses use 429, Retry-After: 60 and no-store.


## Private dashboard access

Telemetry is no longer public. Cloudflare Access protects the entire hostname
with an exact-email allow policy for the owner and one-time PIN login.
`/api/ingest` has a separate, exact-path Access exception because it authenticates
with the existing Worker bearer token. This exception does not grant read access.
The Worker independently verifies Access JWT signature, RS256 algorithm, issuer,
audience, expiry, required identity claims, token type and the owner's email
before any telemetry cache lookup. Missing configuration fails closed.
`TELEMETRY_READS_ENABLED=false` is an emergency read kill switch, not an auth bypass.
Telemetry browser responses are `private, no-store`; only the internal edge
snapshot is cached. Existing copies already retrieved before access was restricted
cannot be recalled. Ingest credentials never authenticate dashboard reads.
