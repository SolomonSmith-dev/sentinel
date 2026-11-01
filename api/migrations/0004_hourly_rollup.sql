-- Hourly rollups for the 24 h panels (/api/top, /api/devices bytes_24h). Summing 24 h of
-- per-minute windows read about 14k rows per request and hit the D1 free read limit (5M/day) on
-- 2026-10-31. Panels now read complete hours from these tables and only the edges from windows.
-- Ingest and seed top-up mark touched hours in rollup_dirty; the 5-minute cron rebuilds any dirty
-- hour that has ended, so late or re-sent windows are corrected on the next run.
CREATE TABLE windows_hourly (
  hour        INTEGER NOT NULL,
  device_hash TEXT NOT NULL,
  bytes       INTEGER NOT NULL,
  is_seed     INTEGER NOT NULL,
  PRIMARY KEY (hour, device_hash)
) WITHOUT ROWID;

CREATE TABLE countries_hourly (
  hour    INTEGER NOT NULL,
  country TEXT NOT NULL,
  bytes   INTEGER NOT NULL,
  is_seed INTEGER NOT NULL,
  PRIMARY KEY (hour, country)
) WITHOUT ROWID;

CREATE TABLE rollup_dirty (
  hour INTEGER PRIMARY KEY
) WITHOUT ROWID;

-- Backfill from the windows already stored (one read of the table).
INSERT INTO windows_hourly (hour, device_hash, bytes, is_seed)
SELECT (ts / 3600) * 3600, device_hash, SUM(bytes_in + bytes_out), MAX(is_seed)
FROM windows GROUP BY 1, 2;

INSERT INTO countries_hourly (hour, country, bytes, is_seed)
SELECT (w.ts / 3600) * 3600, j.key, SUM(j.value), MAX(w.is_seed)
FROM windows w, json_each(w.countries) j GROUP BY 1, 2;
