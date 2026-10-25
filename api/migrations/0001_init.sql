-- Sentinel schema v1. See docs/api.md.

CREATE TABLE devices (
  device_hash TEXT PRIMARY KEY,
  vendor      TEXT NOT NULL DEFAULT 'Unknown',
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  is_seed     INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
-- /api/devices (last 7 days)
CREATE INDEX idx_devices_last_seen ON devices(last_seen);
-- prune by class and age
CREATE INDEX idx_devices_seed_last_seen ON devices(is_seed, last_seen);

CREATE TABLE windows (
  device_hash    TEXT NOT NULL,
  ts             INTEGER NOT NULL,
  duration_s     INTEGER NOT NULL,
  bytes_in       INTEGER NOT NULL,
  bytes_out      INTEGER NOT NULL,
  pkts           INTEGER NOT NULL,
  distinct_dests INTEGER NOT NULL,
  distinct_ports INTEGER NOT NULL,
  syn_ratio      REAL NOT NULL,
  score          REAL,
  countries      TEXT NOT NULL DEFAULT '{}',
  sensor_id      TEXT,
  is_seed        INTEGER NOT NULL DEFAULT 0,
  received_at    INTEGER NOT NULL,
  PRIMARY KEY (device_hash, ts)
);
-- PK (device_hash, ts) serves last_score and bytes_24h per device.
-- /api/flows and /api/top range scans (covering for flows)
CREATE INDEX idx_windows_ts ON windows(ts, bytes_in, bytes_out, pkts, is_seed);
-- prune by class and age
CREATE INDEX idx_windows_seed_ts ON windows(is_seed, ts);
-- seed top-up check and metrics seed_active: real window received recently
CREATE INDEX idx_windows_seed_received ON windows(is_seed, received_at);

CREATE TABLE alerts (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  severity    TEXT NOT NULL,
  detail      TEXT NOT NULL DEFAULT '{}',
  is_seed     INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
-- /api/alerts newest first with since filter
CREATE INDEX idx_alerts_ts ON alerts(ts);
-- alerts_24h per device
CREATE INDEX idx_alerts_device_ts ON alerts(device_hash, ts);
-- prune by class and age
CREATE INDEX idx_alerts_seed_ts ON alerts(is_seed, ts);

CREATE TABLE ingest_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id  TEXT NOT NULL,
  status      INTEGER NOT NULL,
  ms          INTEGER NOT NULL,
  bytes       INTEGER NOT NULL DEFAULT 0,
  sensor_id   TEXT,
  queue_depth INTEGER,
  is_seed     INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
-- metrics: 24h window, percentiles over ms, prune by received_at
CREATE INDEX idx_ingest_log_received ON ingest_log(received_at, status, ms);
-- metrics: per-status counts and latest sensor
CREATE INDEX idx_ingest_log_status_received ON ingest_log(status, received_at);

CREATE TABLE idempotency (
  key         TEXT PRIMARY KEY,
  is_seed     INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
-- prune
CREATE INDEX idx_idempotency_received ON idempotency(received_at);

CREATE TABLE seed_marker (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  last_ts     INTEGER NOT NULL,
  is_seed     INTEGER NOT NULL DEFAULT 1,
  received_at INTEGER NOT NULL
);
