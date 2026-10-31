import type { Context } from "hono";
import type { AppEnv } from "./env";
import { now } from "./env";
import { conditional, intParam, jsonWithEtag } from "./http";

type C = Context<AppEnv>;

const DAY = 86_400;
export const SEED_IDLE_S = 15 * 60;

/** Serve from the Cache API (10 s) when possible; ETag/304 still applies to hits. */
async function cachedJson(c: C, compute: () => Promise<unknown>): Promise<Response> {
  const url = new URL(c.req.url);
  // Canonicalize the values actually used by each handler. Unknown parameters,
  // duplicate parameters and alternate spellings must not create new cache entries.
  const params = new URLSearchParams();
  if (url.pathname === "/api/flows" || url.pathname === "/api/top") {
    params.set("minutes", String(intParam(c.req.query("minutes"), 60, 5, 1440)));
  } else if (url.pathname === "/api/alerts") {
    params.set("limit", String(intParam(c.req.query("limit"), 50, 1, 200)));
    params.set("since", String(intParam(c.req.query("since"), 0, 0, Number.MAX_SAFE_INTEGER)));
  }
  url.search = params.toString();
  const key = new Request(url.toString(), { method: "GET" });
  const cache = (caches as unknown as { default: Cache }).default;
  const hit = await cache.match(key);
  if (hit) return conditional(c.req.raw, hit);
  const fresh = await jsonWithEtag(key, await compute());
  c.executionCtx.waitUntil(cache.put(key, fresh.clone()).catch(() => undefined));
  return conditional(c.req.raw, fresh);
}

export async function flows(c: C): Promise<Response> {
  return cachedJson(c, () => flowsBody(c));
}

async function flowsBody(c: C): Promise<unknown> {
  const minutes = intParam(c.req.query("minutes"), 60, 5, 1440);
  const since = Math.floor(now() / 60) * 60 - (minutes - 1) * 60;
  const { results } = await c.env.DB.prepare(
    `SELECT ts, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(pkts) AS pkts, MAX(is_seed) AS is_seed
     FROM windows WHERE ts >= ? GROUP BY ts ORDER BY ts`,
  )
    .bind(since)
    .all<{ ts: number; bytes_in: number; bytes_out: number; pkts: number; is_seed: number }>();
  return {
    minutes,
    points: results.map(({ ts, bytes_in, bytes_out, pkts }) => ({ ts, bytes_in, bytes_out, pkts })),
    is_seed: results.some((r) => r.is_seed === 1),
  };
}

export async function alerts(c: C): Promise<Response> {
  return cachedJson(c, () => alertsBody(c));
}

async function alertsBody(c: C): Promise<unknown> {
  const limit = intParam(c.req.query("limit"), 50, 1, 200);
  const since = intParam(c.req.query("since"), 0, 0, Number.MAX_SAFE_INTEGER);
  const { results } = await c.env.DB.prepare(
    `SELECT id, type, device_hash, ts, severity, detail, is_seed FROM alerts
     WHERE ts > ? ORDER BY ts DESC, id DESC LIMIT ?`,
  )
    .bind(since, limit)
    .all<{ id: string; type: string; device_hash: string; ts: number; severity: string; detail: string; is_seed: number }>();
  return {
    alerts: results.map((r) => ({ ...r, detail: safeJson(r.detail) })),
  };
}

export async function devices(c: C): Promise<Response> {
  return cachedJson(c, async () => {
    const t = now();
    const { results } = await c.env.DB.prepare(
      `SELECT d.device_hash, d.vendor, d.first_seen, d.last_seen,
         (SELECT w.score FROM windows w WHERE w.device_hash = d.device_hash ORDER BY w.ts DESC LIMIT 1) AS last_score,
         (SELECT COUNT(*) FROM alerts a WHERE a.device_hash = d.device_hash AND a.ts >= ?1) AS alerts_24h,
         (SELECT COALESCE(SUM(w.bytes_in + w.bytes_out), 0) FROM windows w WHERE w.device_hash = d.device_hash AND w.ts >= ?1) AS bytes_24h,
         d.is_seed
       FROM devices d WHERE d.last_seen >= ?2
       ORDER BY last_score IS NULL, last_score DESC, d.device_hash
       LIMIT 500`,
    )
      .bind(t - DAY, t - 7 * DAY)
      .all();
    return { devices: results };
  });
}

export async function top(c: C): Promise<Response> {
  return cachedJson(c, async () => {
    const minutes = intParam(c.req.query("minutes"), 60, 5, 1440);
    const since = Math.floor(now() / 60) * 60 - (minutes - 1) * 60;
    const [devs, countries] = await c.env.DB.batch<Record<string, unknown>>([
      c.env.DB.prepare(
        `SELECT w.device_hash, COALESCE(d.vendor, 'Unknown') AS vendor, SUM(w.bytes_in + w.bytes_out) AS bytes, MAX(w.is_seed) AS is_seed
         FROM windows w LEFT JOIN devices d ON d.device_hash = w.device_hash
         WHERE w.ts >= ? GROUP BY w.device_hash ORDER BY bytes DESC LIMIT 10`,
      ).bind(since),
      c.env.DB.prepare(
        `SELECT j.key AS country, SUM(j.value) AS bytes
         FROM windows w, json_each(w.countries) j
         WHERE w.ts >= ? GROUP BY j.key ORDER BY bytes DESC LIMIT 10`,
      ).bind(since),
    ]);
    return { minutes, devices: devs!.results, countries: countries!.results };
  });
}

export async function seedActive(db: D1Database, t: number): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS hit FROM windows WHERE ts > ? AND is_seed = 0 LIMIT 1")
    .bind(t - SEED_IDLE_S)
    .first();
  return !row;
}

export async function metrics(c: C): Promise<Response> {
  return cachedJson(c, () => metricsBody(c));
}

// failed_24h counts for 401, 429 and 503 (kill switch) are SAMPLED: unauthenticated failures write
// at most one ingest_log row per status per minute (see unauthLogAllowed in ingest.ts), so these
// are a lower bound, not exact counts. Authenticated outcomes (200/400/413/503 storage) are exact.
async function metricsBody(c: C): Promise<unknown> {
  const t = now();
  const since = t - DAY;
  const db = c.env.DB;
  const [count, failed, sensor, rows, recentReal] = await db.batch<Record<string, number | string | null>>([
    db.prepare("SELECT COUNT(*) AS n FROM ingest_log WHERE status = 200 AND received_at > ?").bind(since),
    db.prepare("SELECT status, COUNT(*) AS n FROM ingest_log WHERE status <> 200 AND received_at > ? GROUP BY status").bind(since),
    db.prepare(
      `SELECT sensor_id, received_at AS last_seen, queue_depth FROM ingest_log
       WHERE status = 200 AND sensor_id IS NOT NULL ORDER BY received_at DESC, id DESC LIMIT 1`,
    ),
    db.prepare(
      "SELECT devices, windows, alerts FROM row_counts WHERE id = 1",
    ),
    db.prepare("SELECT 1 AS hit FROM windows WHERE ts > ? AND is_seed = 0 LIMIT 1").bind(t - SEED_IDLE_S),
  ]);
  const n = Number(count!.results[0]?.n ?? 0);
  let p50: number | null = null;
  let p95: number | null = null;
  if (n > 0) {
    const pct = db.prepare("SELECT ms FROM ingest_log WHERE status = 200 AND received_at > ? ORDER BY ms LIMIT 1 OFFSET ?");
    const [a, b] = await db.batch<{ ms: number }>([
      pct.bind(since, Math.floor(0.5 * (n - 1))),
      pct.bind(since, Math.floor(0.95 * (n - 1))),
    ]);
    p50 = a!.results[0]?.ms ?? null;
    p95 = b!.results[0]?.ms ?? null;
  }
  const failed_24h: Record<string, number> = { "401": 0, "413": 0, "429": 0, "503": 0 };
  for (const r of failed!.results) failed_24h[String(r.status)] = Number(r.n);
  const s = sensor!.results[0];
  const r = rows!.results[0] ?? {};
  return {
    ingest: { count_24h: n, failed_24h, p50_ms: p50, p95_ms: p95 },
    sensor: s ? { sensor_id: s.sensor_id, last_seen: s.last_seen, queue_depth: s.queue_depth } : null,
    rows: { devices: Number(r.devices ?? 0), windows: Number(r.windows ?? 0), alerts: Number(r.alerts ?? 0) },
    seed_active: recentReal!.results.length === 0,
  };
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}
