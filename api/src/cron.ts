import type { Env } from "./env";
import { buildRowStatements } from "./ingest";
import { seedActive } from "./reads";
import { generateMinute, minutesBetween, SEED_DEVICES, type SeedAlert, type SeedWindow } from "./seed";

const DAY = 86_400;
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
  ]);
  const names = ["windows_real", "windows_seed", "alerts_real", "alerts_seed", "devices_real", "devices_seed", "idempotency", "ingest_log"];
  const out: Record<string, number> = {};
  res.forEach((r, i) => (out[names[i]!] = r.meta.changes ?? 0));
  console.log(JSON.stringify({ event: "prune", ...out }));
  return out;
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
  else await seedTopUp(env, t);
  await refreshRowCounts(env, t);
}
