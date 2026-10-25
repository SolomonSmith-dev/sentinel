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

Privacy guard: before parsing fields, the Worker scans the decompressed body for IPv4 (`\b(?:\d{1,3}\.){3}\d{1,3}\b`), MAC (`\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b`) and IPv6-looking tokens. Any match → 400 `pii_rejected`. The sensor runs the same check before sending.

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

### GET /api/health
`{"ok": true}`. No D1 access.

## Storage (D1, `api/migrations/`)

Tables: `devices`, `windows`, `alerts`, `ingest_log`, `idempotency`, `seed_marker`. Every data table has `is_seed INTEGER NOT NULL DEFAULT 0` and `received_at INTEGER NOT NULL`.

## Cron

- `*/5 * * * *` seed top-up: if no real (non-seed) window arrived in the last 15 minutes, insert seed windows for the minutes missing since the last seed write (8 synthetic devices, plausible diurnal traffic, an occasional seed alert). Keeps the URL live-looking without a sensor. Stops writing once real data flows.
- `17 3 * * *` prune: delete real rows older than 7 days, seed rows older than 24 h, `idempotency` and `ingest_log` rows older than 24 h.

Free-tier budget: D1 allows 100k rows written per day. Seed top-up writes about 8 rows a minute (11.5k a day). A 30-device LAN at 60 s rollups writes about 43k a day.
