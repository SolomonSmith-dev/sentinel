import type { Env } from "./env";
import { buildRowStatements } from "./ingest";
import { seedActive } from "./reads";
import { generateMinute, minutesBetween, SEED_DEVICES, type SeedAlert, type SeedWindow } from "./seed";

const DAY = 86_400;
const HOUR = 3_600;
/** The cron never backfills more than this; `npm run seed:remote` covers the initial 24 h. */
export const TOPUP_MAX_MINUTES = 120;
/** With no marker yet, start this far back. */
const TOPUP_DEFAULT_MINUTES = 15;

export interface TopUpResult {
  skipped?: "real_data" | "up_to_date";
  minutes: number;
  windows: number;
  alerts: number;
}

export async function seedTopUp(env: Env, t: number): Promise<TopUpResult> {
  if (!(await seedActive(env.DB, t))) return { skipped: "real_data", minutes: 0, windows: 0, alerts: 0 };

  const nowMin = Math.floor(t / 60) * 60;
  const marker = await env.DB.prepare("SELECT last_ts FROM seed_marker WHERE id = 1").first<{ last_ts: number }>();
  let start = marker ? marker.last_ts + 60 : nowMin - (TOPUP_DEFAULT_MINUTES - 1) * 60;
  start = Math.max(start, nowMin - (TOPUP_MAX_MINUTES - 1) * 60);
  if (start > nowMin) return { skipped: "up_to_date", minutes: 0, windows: 0, alerts: 0 };

  const windows: SeedWindow[] = [];
  const alerts: SeedAlert[] = [];
  const minutes = minutesBetween(start, nowMin);
  for (const m of minutes) {
    const g = generateMinute(m);
    windows.push(...g.windows);
    alerts.push(...g.alerts.filter((a) => a.ts <= t));
  }
  const stmts = buildRowStatements(
    env.DB,
    {
      devices: SEED_DEVICES.map((d) => ({ device_hash: d.device_hash, vendor: d.vendor, first_seen: start })),
      windows,
      alerts,
      sensorId: null,
      isSeed: 1,
    },
    t,
  );
  stmts.push(
    env.DB.prepare(
      "INSERT INTO seed_marker (id, last_ts, is_seed, received_at) VALUES (1, ?1, 1, ?2) ON CONFLICT(id) DO UPDATE SET last_ts = excluded.last_ts, received_at = excluded.received_at",
    ).bind(nowMin, t),
  );
  await env.DB.batch(stmts);
  const res = { minutes: minutes.length, windows: windows.length, alerts: alerts.length };
  console.log(JSON.stringify({ event: "seed_topup", ...res }));
  return res;
}

export async function prune(env: Env, t: number): Promise<Record<string, number>> {
  const realCut = t - 7 * DAY;
  const seedCut = t - DAY;
  const db = env.DB;
  const res = await db.batch([
    db.prepare("DELETE FROM windows WHERE is_seed = 0 AND ts < ?").bind(realCut),
    db.prepare("DELETE FROM windows WHERE is_seed = 1 AND ts < ?").bind(seedCut),
    db.prepare("DELETE FROM alerts WHERE is_seed = 0 AND ts < ?").bind(realCut),
    db.prepare("DELETE FROM alerts WHERE is_seed = 1 AND ts < ?").bind(seedCut),
    db.prepare("DELETE FROM devices WHERE is_seed = 0 AND last_seen < ?").bind(realCut),
    db.prepare("DELETE FROM devices WHERE is_seed = 1 AND last_seen < ?").bind(seedCut),
    db.prepare("DELETE FROM idempotency WHERE received_at < ?").bind(seedCut),
    db.prepare("DELETE FROM ingest_log WHERE received_at < ?").bind(seedCut),
    // An hourly row goes once its whole hour is past the cut.
    db.prepare("DELETE FROM windows_hourly WHERE is_seed = 0 AND hour <= ?").bind(realCut - HOUR),
    db.prepare("DELETE FROM windows_hourly WHERE is_seed = 1 AND hour <= ?").bind(seedCut - HOUR),
    db.prepare("DELETE FROM countries_hourly WHERE is_seed = 0 AND hour <= ?").bind(realCut - HOUR),
    db.prepare("DELETE FROM countries_hourly WHERE is_seed = 1 AND hour <= ?").bind(seedCut - HOUR),
  ]);
  const names = [
    "windows_real", "windows_seed", "alerts_real", "alerts_seed", "devices_real", "devices_seed", "idempotency", "ingest_log",
    "hourly_real", "hourly_seed", "countries_hourly_real", "countries_hourly_seed",
  ];
  const out: Record<string, number> = {};
  res.forEach((r, i) => (out[names[i]!] = r.meta.changes ?? 0));
  console.log(JSON.stringify({ event: "prune", ...out }));
  return out;
}

/**
 * Rebuild every dirty hour that has ended (hour < current hour). Five statements however many hours
 * are dirty, so it stays inside the 50-queries-per-invocation free limit. Reads cost about one hour of
 * windows per rebuilt hour; reads.ts never uses an hour from the rollup until it is an hour old.
 */
export async function rebuildRollups(env: Env, t: number): Promise<number> {
  const cur = Math.floor(t / HOUR) * HOUR;
  const db = env.DB;
  const res = await db.batch([
    db.prepare("DELETE FROM windows_hourly WHERE hour IN (SELECT hour FROM rollup_dirty WHERE hour < ?1)").bind(cur),
    db.prepare(
      `INSERT INTO windows_hourly (hour, device_hash, bytes, is_seed)
       SELECT r.hour, w.device_hash, SUM(w.bytes_in + w.bytes_out), MAX(w.is_seed)
       FROM rollup_dirty r JOIN windows w ON w.ts >= r.hour AND w.ts < r.hour + 3600
       WHERE r.hour < ?1 GROUP BY r.hour, w.device_hash`,
    ).bind(cur),
    db.prepare("DELETE FROM countries_hourly WHERE hour IN (SELECT hour FROM rollup_dirty WHERE hour < ?1)").bind(cur),
    db.prepare(
      `INSERT INTO countries_hourly (hour, country, bytes, is_seed)
       SELECT r.hour, j.key, SUM(j.value), MAX(w.is_seed)
       FROM rollup_dirty r JOIN windows w ON w.ts >= r.hour AND w.ts < r.hour + 3600, json_each(w.countries) j
       WHERE r.hour < ?1 GROUP BY r.hour, j.key`,
    ).bind(cur),
    db.prepare("DELETE FROM rollup_dirty WHERE hour < ?1").bind(cur),
  ]);
  return res[4]!.meta.changes ?? 0;
}

export async function refreshRowCounts(env: Env, t: number): Promise<void> {
  await env.DB.prepare(`INSERT INTO row_counts (id, devices, windows, alerts, updated_at)
    SELECT 1, (SELECT COUNT(*) FROM devices), (SELECT COUNT(*) FROM windows),
      (SELECT COUNT(*) FROM alerts), ?
    ON CONFLICT(id) DO UPDATE SET devices = excluded.devices, windows = excluded.windows,
      alerts = excluded.alerts, updated_at = excluded.updated_at`).bind(t).run();
}

export async function scheduled(controller: ScheduledController, env: Env): Promise<void> {
  const t = Math.floor(controller.scheduledTime / 1000);
  if (controller.cron === "17 3 * * *") await prune(env, t);
  else {
    await seedTopUp(env, t);
    await rebuildRollups(env, t);
  }
  await refreshRowCounts(env, t);
}
