# Sentinel

A home-network security monitor. A C++ libpcap sensor on a Debian home server aggregates flow metadata, Suricata adds IDS alerts, a Python service runs detection rules and an isolation-forest anomaly score, and anonymized one-minute rollups land in Cloudflare Workers + D1 behind a public dashboard.

**Live:** https://sentinel.solomonsmith.dev (shows labeled synthetic seed data until the home sensor reports)

Monitor only. No payloads are captured, and no IP address, MAC address or hostname ever leaves the house.

## Architecture

```
home server (Docker compose, host network)
  suricata ─────────── eve.json ─────────┐
  sentinel-capture (C++17, libpcap)      │
     10 s per-host windows (ndjson) ──> sentinel-shipper (Python 3.12)
                                          rules: flood, port scan, new device, geo anomaly
                                          isolation forest score per window
                                          anonymize: dev-<sha256(mac+salt)[:6]>, country codes only
                                          roll up to 60 s, gzip, durable queue
                                              │ HTTPS, bearer token, Idempotency-Key
Cloudflare                                    v
  Worker (Hono, TypeScript)  POST /api/ingest ──> D1 (devices, windows, alerts)
     │  GET /api/{flows,alerts,devices,top,metrics}     cron: seed top-up, 7-day prune
     └─ static assets: React dashboard (same origin, polls every 10 s with ETags)
```

The public URL never reaches into the LAN. The sensor pushes out; nothing on the home network accepts inbound connections for this.

## Repository

| Path | What | Tests |
|---|---|---|
| `sensor/capture/` | C++17 libpcap capture: Ethernet/VLAN/IPv4/IPv6/TCP/UDP parsing, per-host 10 s windows, bounded memory, atomic file output, pcap replay mode | ctest: parser unit tests plus exact-value replays of three pcap fixtures (port scan, SYN flood, benign) |
| `sensor/shipper/` | Python shipper: rules, Suricata eve.json tail, geo lookup, anonymizer, privacy guard, rollup, on-disk queue with backoff, nightly retraining | pytest |
| `ml/` | Offline isolation-forest trainer and evaluator, with the reasoning behind features and calibration | `ml/train.py` |
| `api/` | Cloudflare Worker: authenticated ingest with size caps, rate limit, idempotency, PII rejection; read endpoints with ETag and edge caching; D1 migrations; cron jobs | vitest on the Workers runtime |
| `dashboard/` | Vite + React + TypeScript + Recharts + Tailwind | build in CI |
| `docs/api.md` | The API contract every component codes to | |
| `docs/sensor-format.md` | The capture to shipper file format | |
| `deploy-sensor.sh` | One-command sensor deploy on the home server | shellcheck in CI |

## Detections

| Detection | Rule |
|---|---|
| Flood | More than 2000 packets/s to one destination, or more than 500 SYNs without ACK in 10 s |
| Port scan | One source touches more than 20 distinct destination ports in 10 s (either direction) |
| New device | Hashed MAC not seen before |
| Geo anomaly | Outbound traffic to a country this device has not contacted in the trailing 7 days (quiet during a device's first 24 h) |
| ML anomaly | Isolation-forest score above 0.8 on bytes in/out, packets, distinct destinations, distinct ports and SYN ratio |
| Suricata | ET Open rule hits from eve.json, mapped to the device hash |

See `ml/README.md` for why an isolation forest (no labels exist on a home LAN), how raw scores map to [0, 1], and the evaluation `ml/train.py` prints on synthetic injected anomalies.

## Privacy

- Devices are `dev-` plus the first 6 hex characters of `sha256(mac + salt)`. The salt is generated on the sensor host and never leaves it.
- Remote endpoints are reduced to ISO country codes on the sensor.
- The shipper refuses to send any batch containing an IP or MAC pattern, and the Worker independently rejects such batches (`400 pii_rejected`), checking both the raw body and the decoded JSON.
- No packet payloads are captured (128-byte snaplen, headers only) or stored anywhere.

## Run it

Cloud side (needs a Cloudflare account; free tier):

```sh
cd api && npm ci
npx wrangler d1 create sentinel        # put the id in wrangler.jsonc
npx wrangler d1 migrations apply sentinel --remote
openssl rand -hex 32 | npx wrangler secret put SENTINEL_TOKEN
cd ../dashboard && npm ci && npm run build
cd ../api && npx wrangler deploy
```

Sensor side (Debian with Docker, on a box that sees LAN traffic):

```sh
git clone https://github.com/SolomonSmith-dev/sentinel && cd sentinel
mkdir -p ~/.config/sentinel && (umask 077; echo '<token>' > ~/.config/sentinel/token)
./deploy-sensor.sh --dry-run && ./deploy-sensor.sh
```

Kill switches: `docker compose -f sensor/docker-compose.yml down` on the sensor, or set the Worker var `INGEST_ENABLED=false`.

## Free-tier limits

D1 allows 100k rows written per day and counts each index entry as a write. Sentinel ships 60 s rollups (not 10 s windows), skips idle devices, re-sends device metadata at most every 10 minutes and keeps one secondary index on `windows`. Data older than 7 days is pruned nightly.

## Roadmap

- R2 archive of windows beyond 7 days
- Cloudflare Queues between ingest and storage
- Push/email notifications on high-severity alerts
- Server-sent events instead of polling
- Sharding D1 by device hash if a larger network outgrows one database

## License

MIT
