// Backfill the last 24 h of deterministic seed data into D1.
// Usage: npm run seed:remote            (remote D1)
//        node scripts/seed-remote.ts --local
// Rows are upserts keyed like real data, so running twice is a no-op.
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateMinute, minutesBetween, SEED_DEVICES, type SeedAlert, type SeedWindow } from "../src/seed.ts";

const target = process.argv.includes("--local") ? "--local" : "--remote";
const HOURS = 24;
const CHUNK = 200;

const now = Math.floor(Date.now() / 1000);
const nowMin = Math.floor(now / 60) * 60;
const start = nowMin - (HOURS * 60 - 1) * 60;

const q = (v: string | number | null): string =>
  v === null ? "NULL" : typeof v === "number" ? String(v) : `'${v.replace(/'/g, "''")}'`;

const windows: SeedWindow[] = [];
const alerts: SeedAlert[] = [];
for (const m of minutesBetween(start, nowMin)) {
  const g = generateMinute(m);
  windows.push(...g.windows);
  alerts.push(...g.alerts.filter((a) => a.ts <= now));
}

const sql: string[] = [];
sql.push(
  `INSERT INTO devices (device_hash, vendor, first_seen, last_seen, is_seed, received_at) VALUES ${SEED_DEVICES.map(
    (d) => `(${q(d.device_hash)}, ${q(d.vendor)}, ${start}, ${nowMin}, 1, ${now})`,
  ).join(", ")} ON CONFLICT(device_hash) DO UPDATE SET first_seen = MIN(devices.first_seen, excluded.first_seen), last_seen = MAX(devices.last_seen, excluded.last_seen);`,
);
for (let i = 0; i < windows.length; i += CHUNK) {
  const rows = windows.slice(i, i + CHUNK).map(
    (w) =>
      `(${q(w.device_hash)}, ${w.ts}, ${w.duration_s}, ${w.bytes_in}, ${w.bytes_out}, ${w.pkts}, ${w.distinct_dests}, ${w.distinct_ports}, ${w.syn_ratio}, ${w.score}, ${q(JSON.stringify(w.countries))}, NULL, 1, ${now})`,
  );
  sql.push(
    `INSERT INTO windows (device_hash, ts, duration_s, bytes_in, bytes_out, pkts, distinct_dests, distinct_ports, syn_ratio, score, countries, sensor_id, is_seed, received_at) VALUES ${rows.join(", ")} ON CONFLICT(device_hash, ts) DO NOTHING;`,
  );
}
if (alerts.length) {
  sql.push(
    `INSERT INTO alerts (id, type, device_hash, ts, severity, detail, is_seed, received_at) VALUES ${alerts
      .map((a) => `(${q(a.id)}, ${q(a.type)}, ${q(a.device_hash)}, ${a.ts}, ${q(a.severity)}, ${q(JSON.stringify(a.detail))}, 1, ${now})`)
      .join(", ")} ON CONFLICT(id) DO NOTHING;`,
  );
}
sql.push(
  `INSERT INTO seed_marker (id, last_ts, is_seed, received_at) VALUES (1, ${nowMin}, 1, ${now}) ON CONFLICT(id) DO UPDATE SET last_ts = MAX(seed_marker.last_ts, excluded.last_ts), received_at = excluded.received_at;`,
);

const dir = mkdtempSync(join(tmpdir(), "sentinel-seed-"));
const file = join(dir, "seed.sql");
writeFileSync(file, sql.join("\n") + "\n");
const total = SEED_DEVICES.length + windows.length + alerts.length;
console.log(`seed: ${windows.length} windows, ${alerts.length} alerts, ${SEED_DEVICES.length} devices (${total} rows) → ${file}`);

execFileSync("npx", ["wrangler", "d1", "execute", "sentinel", target, "--file", file, "--yes"], { stdio: "inherit" });
