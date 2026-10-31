# sentinel-shipper

Runs on the sensor host. Every 30 s it turns the capture's local 10 s windows
(`docs/sensor-format.md`) and Suricata's `eve.json` into anonymized, scored,
rule-checked 60 s batches. It then POSTs them to `/api/ingest`
(`docs/api.md`). Raw IPs and MACs never leave the process.

```
windows/*.ndjson ─┐                    ┌─ rules (flood, port_scan, new_device, geo_anomaly, ml_anomaly)
                  ├─ parse ─ anonymize ┼─ isolation forest score ─┐
eve.json (tail) ──┘   (dev-xxxxxx)     └─ feature store (sqlite)  ├─ 60 s rollup ─ batch ─ durable queue ─ privacy guard ─ gzip POST
                                                                  └─ suricata alerts ──────┘
```

## Modules (`src/sentinel_shipper/`)

| module | job |
|---|---|
| `config.py` | env settings; refuses to start without `SENTINEL_TOKEN` and `SENTINEL_SALT` |
| `windows.py` | ndjson parsing; only finished `*.ndjson`, only complete 60 s buckets |
| `anonymize.py` | `dev-` + sha256(mac + salt)[:6]; IEEE OUI vendor; "Private MAC" for locally administered |
| `geo.py` | binary search over iptoasn `ip2country-v4.tsv`; non-global addresses never looked up |
| `rules.py` | the deterministic rules and the 5 min per type+device debounce |
| `mlcore.py` | numpy-free constants, `raw_features`, `Scorer`; what rules and pipeline import |
| `mlmode.py` | `SENTINEL_ML` handling and the subprocess import probe |
| `model.py` | isolation forest, calibration to [0,1]; imports numpy/sklearn, loaded lazily; see `ml/README.md` |
| `training.py` | nightly retrain at 03:30 local; bootstrap once 2 h of rows exist |
| `rollup.py` | 10 s to 60 s windows (sums; distinct counts as max-of-window) |
| `eve.py` | eve.json tailing with rotation/truncation handling; alert events only |
| `state.py` | sqlite: devices, 7-day country history, debounce, IP-to-device map, features |
| `queue.py` | fsynced on-disk FIFO, capped at 24 h |
| `sender.py` | privacy guard, gzip, Idempotency-Key, backoff with jitter |
| `pipeline.py` | one tick, with commit order chosen so a crash replays instead of losing data |

## Write budget

- A 60 s window with `pkts == 0` is never shipped.
- A device goes into a batch's `devices` array only when it is new or was last
  sent more than 10 minutes ago. The timestamp is kept in `state.db`.

## Configuration

| variable | default |
|---|---|
| `SENTINEL_API` | `https://sentinel.solomonsmith.dev` |
| `SENTINEL_TOKEN`, `SENTINEL_SALT` | required |
| `SENTINEL_SENSOR_ID` | `sensor-01` |
| `SENTINEL_WINDOWS_DIR` | `/var/lib/sentinel/windows` |
| `SENTINEL_STATE_DIR` | `/var/lib/sentinel/state` |
| `SENTINEL_EVE` | `/var/log/suricata/eve.json` |
| `SENTINEL_WAN_IP` | unset; if set, a batch containing it is never sent |
| `SENTINEL_RETRAIN_AT` | `03:30` (local time, `TZ`) |
| `SENTINEL_ML` | `auto` (default), `on`, `off`; see below |

## Mounted credentials

For mounted credentials, use `SENTINEL_TOKEN_FILE` and `SENTINEL_SALT_FILE`
instead of placing values in the container environment. Each file is read at
startup; setting both a value and its `_FILE` counterpart is rejected. The
production overlay `sensor/compose.credentials.yml` mounts the two credential
files from `~/.config/sentinel/` read-only. Keep these files outside the checkout, readable only by the shipper UID (10001),
with mode `0400` and an owner-only parent directory. Do not commit them or copy
them into `.env`. Once provisioned, deploy or validate without reading `.env`:

```sh
./deploy-sensor.sh --credentials --dry-run
./deploy-sensor.sh --credentials
```

## SENTINEL_ML

The sensor is a 2009 Mac Mini (Core 2 Duo P8600: SSE4.1, no SSE4.2, no POPCNT,
no AVX). If a numpy/scipy/sklearn wheel uses an instruction that CPU lacks, the
interpreter dies with SIGILL at import, which cannot be caught in-process and
would take the rules engine and shipping down with it. So only `mlcore.py` and
`mlmode.py` (no numpy) are imported at startup; `model.py` is imported lazily.

- `auto` (default): at startup a child `python -c` imports numpy, scipy,
  sklearn and joblib and fits a tiny IsolationForest (60 s timeout). If it exits
  non-zero or is killed by a signal (logged by name, e.g. SIGILL), the shipper
  logs one warning and runs with ML disabled.
- `on`: skip the probe and use ML.
- `off`: never import numpy/sklearn. Every score is null; rules and shipping run.

With ML disabled, no model is loaded and bootstrap/nightly training is skipped.

## Develop

```
python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/pytest -q
```

Tests use small committed fixtures (`tests/fixtures/`) and fake secrets. The
Docker image downloads the full geo and OUI tables at build time.

numpy is pinned to 2.3.x on purpose. numpy 2.4 wheels require x86-64-v2
(SSE4.2), and the sensor host's Core 2 Duo does not have it.
