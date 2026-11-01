import { describe, expect, it } from "vitest";
import { prune, rebuildRollups } from "../src/cron";
import { buildRowStatements, type RowSet } from "../src/ingest";
import { BYTES_BY_DEVICE, rollupBounds } from "../src/reads";
import { env, fetchWorker, nowS } from "./helpers";

const DAY = 86_400;
const DEVS = ["dev-a00001", "dev-a00002", "dev-a00003"];

// The pre-rollup queries, kept here as the reference the new reads must match.
const RAW_TOP = `SELECT w.device_hash, COALESCE(d.vendor, 'Unknown') AS vendor, SUM(w.bytes_in + w.bytes_out) AS bytes, MAX(w.is_seed) AS is_seed
  FROM windows w LEFT JOIN devices d ON d.device_hash = w.device_hash
  WHERE w.ts >= ? GROUP BY w.device_hash ORDER BY bytes DESC LIMIT 10`;
const RAW_COUNTRIES = `SELECT j.key AS country, SUM(j.value) AS bytes FROM windows w, json_each(w.countries) j
  WHERE w.ts >= ? GROUP BY j.key ORDER BY bytes DESC LIMIT 10`;
const RAW_DEVICE_BYTES = `SELECT d.device_hash, (SELECT COALESCE(SUM(w.bytes_in + w.bytes_out), 0) FROM windows w
  WHERE w.device_hash = d.device_hash AND w.ts >= ?) AS bytes_24h FROM devices d ORDER BY d.device_hash`;

function win(device_hash: string, ts: number, k: number) {
  return {
    device_hash, ts, duration_s: 60, bytes_in: 1000 + k, bytes_out: 100 + (k % 7), pkts: 10,
    distinct_dests: 1, distinct_ports: 1, syn_ratio: 0, score: 0.2, countries: { US: 900 + k, DE: 200 + (k % 5) },
  };
}

/** 26 h of windows every 5 minutes for three devices, written the way ingest writes them. */
async function load(t: number, every = 300) {
  const start = Math.floor((t - 26 * 3600) / 60) * 60;
  const windows = [];
  let k = 0;
  for (let ts = start; ts <= t - 60; ts += every) for (const h of DEVS) windows.push(win(h, ts, k++));
  const rows: RowSet = {
    devices: DEVS.map((h) => ({ device_hash: h, vendor: "Apple", first_seen: start })),
    windows, alerts: [], sensorId: "s1", isSeed: 0,
  };
  await env.DB.batch(buildRowStatements(env.DB, rows, t));
}

async function json(path: string) {
  const res = await fetchWorker(path);
  expect(res.status).toBe(200);
  return res.json<any>();
}

describe("hourly rollup", () => {
  it("rollupBounds splits into raw edges and whole rollup hours", () => {
    const t = 1_761_400_000; // 13:46:40 into an hour
    const b = Math.floor(t / 3600) * 3600 - 3600;
    const [since, lead, bb, tail] = rollupBounds(t - DAY, t);
    expect([since, bb, tail]).toEqual([t - DAY, b, b]);
    expect(lead % 3600).toBe(0);
    expect(lead - since).toBeGreaterThanOrEqual(0);
    expect(lead - since).toBeLessThan(3600);
    // a short range never touches the rollup: [lead, b) is empty and raw covers [since, now)
    const short = rollupBounds(t - 300, t);
    expect(short[1]).toBe(short[2]);
    expect(short[3]).toBe(t - 300);
  });

  it("marks touched hours dirty on ingest and rebuilds only ended hours", async () => {
    const t = nowS();
    await load(t);
    // load() stops at t - 60, so in the first five minutes of an hour it writes nothing into the
    // current hour. Write one current-hour window explicitly so the assertion below never depends
    // on the wall clock.
    const cur = Math.floor(t / 3600) * 3600;
    await env.DB.batch(buildRowStatements(env.DB, { devices: [], windows: [win(DEVS[0]!, cur, 0)], alerts: [], sensorId: "s1", isSeed: 0 }, t));
    const dirty = await env.DB.prepare("SELECT COUNT(*) AS n FROM rollup_dirty").first<{ n: number }>();
    expect(dirty!.n).toBeGreaterThanOrEqual(26);
    await rebuildRollups(env, t);
    const left = await env.DB.prepare("SELECT hour FROM rollup_dirty").all<{ hour: number }>();
    expect(left.results).toEqual([{ hour: Math.floor(t / 3600) * 3600 }]);
  });

  it("/api/top and /api/devices match the raw queries after a rebuild", async () => {
    const t = nowS();
    await load(t);
    await rebuildRollups(env, t);
    const since = Math.floor(t / 60) * 60 - 1439 * 60;
    const top = await json("/api/top?minutes=1440");
    expect(top.devices).toEqual((await env.DB.prepare(RAW_TOP).bind(since).all()).results);
    expect(top.countries).toEqual((await env.DB.prepare(RAW_COUNTRIES).bind(since).all()).results);
    const devs = await json("/api/devices");
    const got = devs.devices.map((d: any) => ({ device_hash: d.device_hash, bytes_24h: d.bytes_24h }));
    got.sort((a: any, b: any) => a.device_hash.localeCompare(b.device_hash));
    // /api/devices computes its 24 h cut from now() at request time; allow the same second.
    expect(got).toEqual((await env.DB.prepare(RAW_DEVICE_BYTES).bind(nowS() - DAY).all()).results);
  });

  it("a re-sent window replaces, not adds, after the next rebuild", async () => {
    const t = nowS();
    await load(t);
    await rebuildRollups(env, t);
    const old = Math.floor((t - 10 * 3600) / 3600) * 3600 + 120;
    const resent = { ...win(DEVS[0]!, old, 0), bytes_in: 5_000_000, countries: { FR: 5_000_000 } };
    await env.DB.batch(buildRowStatements(env.DB, { devices: [], windows: [resent], alerts: [], sensorId: "s1", isSeed: 0 }, t));
    await rebuildRollups(env, t);
    const hour = Math.floor(old / 3600) * 3600;
    const raw = await env.DB.prepare("SELECT SUM(bytes_in + bytes_out) AS b FROM windows WHERE device_hash = ? AND ts >= ? AND ts < ?")
      .bind(DEVS[0], hour, hour + 3600).first<{ b: number }>();
    const rolled = await env.DB.prepare("SELECT bytes FROM windows_hourly WHERE device_hash = ? AND hour = ?").bind(DEVS[0], hour).first<{ bytes: number }>();
    expect(rolled!.bytes).toBe(raw!.b);
    const fr = await env.DB.prepare("SELECT bytes FROM countries_hourly WHERE country = 'FR' AND hour = ?").bind(hour).first<{ bytes: number }>();
    expect(fr!.bytes).toBe(5_000_000);
  });

  it("reads far fewer rows than the raw 24 h queries", async () => {
    const t = nowS();
    await load(t, 60); // per-minute, like a real sensor
    await rebuildRollups(env, t);
    const since = Math.floor(t / 60) * 60 - 1439 * 60;
    const rawRead = (await env.DB.prepare(RAW_TOP).bind(since).all()).meta.rows_read;
    const newRead = (await env.DB.prepare(BYTES_BY_DEVICE).bind(...rollupBounds(since, t)).all()).meta.rows_read;
    console.log(JSON.stringify({ rows_read_raw: rawRead, rows_read_rollup: newRead }));
    expect(rawRead).toBeGreaterThan(4000);
    expect(newRead * 4).toBeLessThan(rawRead);
  });

  it("prune drops hourly rows once their hour is past the cut", async () => {
    const t = nowS();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO windows_hourly VALUES (?, 'x', 1, 0), (?, 'x', 1, 0), (?, 'y', 1, 1), (?, 'y', 1, 1)")
        .bind(Math.floor((t - 8 * DAY) / 3600) * 3600, Math.floor((t - 2 * DAY) / 3600) * 3600,
          Math.floor((t - 2 * DAY) / 3600) * 3600, Math.floor((t - 3600) / 3600) * 3600),
    ]);
    const out = await prune(env, t);
    expect(out.hourly_real).toBe(1);
    expect(out.hourly_seed).toBe(1);
    const left = await env.DB.prepare("SELECT device_hash, is_seed FROM windows_hourly ORDER BY device_hash").all();
    expect(left.results).toEqual([{ device_hash: "x", is_seed: 0 }, { device_hash: "y", is_seed: 1 }]);
  });
});
