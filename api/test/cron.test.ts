import { createScheduledController } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { prune, seedTopUp, TOPUP_MAX_MINUTES } from "../src/cron";
import worker from "../src/index";
import { generateMinute, SEED_DEVICES } from "../src/seed";
import { env, nowS, postIngest, sampleBatch } from "./helpers";

const n = async (sql: string, ...binds: unknown[]) =>
  (await env.DB.prepare(sql).bind(...binds).first<{ n: number }>())!.n;

describe("seed generator", () => {
  it("is deterministic and in range", () => {
    const t = 1761370800;
    expect(generateMinute(t)).toEqual(generateMinute(t + 30));
    const scores: number[] = [];
    let alerts = 0;
    const types = new Set<string>();
    for (let i = 0; i < 1440; i++) {
      const g = generateMinute(t + i * 60);
      expect(g.windows).toHaveLength(8);
      for (const w of g.windows) {
        expect(w.ts % 60).toBe(0);
        expect(w.device_hash).toMatch(/^dev-[0-9a-f]{6}$/);
        for (const k of Object.keys(w.countries)) expect(k).toMatch(/^[A-Z?]{2}$/);
        scores.push(w.score);
      }
      alerts += g.alerts.length;
      g.alerts.forEach((a) => types.add(a.type));
    }
    const mid = scores.filter((s) => s >= 0.1 && s <= 0.5).length / scores.length;
    expect(mid).toBeGreaterThan(0.95);
    expect(scores.some((s) => s > 0.8)).toBe(true);
    expect(alerts).toBeGreaterThan(10);
    expect(alerts).toBeLessThan(150);
    // 24 h of seed rows stays under the 15k budget
    expect(1440 * SEED_DEVICES.length + alerts + SEED_DEVICES.length).toBeLessThan(15_000);
    expect(types.size).toBeGreaterThanOrEqual(5);
  });

  it("covers every alert type within a week", () => {
    const types = new Set<string>();
    for (let i = 0; i < 7 * 1440; i++) generateMinute(1761370800 + i * 60).alerts.forEach((a) => types.add(a.type));
    expect([...types].sort()).toEqual(["flood", "geo_anomaly", "ml_anomaly", "new_device", "port_scan", "suricata"]);
  });
});

describe("seed top-up cron", () => {
  it("writes seed rows when no real data, then fills only missing minutes", async () => {
    const t = nowS();
    const r1 = await seedTopUp(env, t);
    expect(r1.minutes).toBe(15);
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 1")).toBe(15 * 8);
    expect(await n("SELECT COUNT(*) AS n FROM devices WHERE is_seed = 1")).toBe(8);
    const r2 = await seedTopUp(env, t + 300);
    expect(r2.minutes).toBe(5);
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 1")).toBe(20 * 8);
    expect((await seedTopUp(env, t + 300)).skipped).toBe("up_to_date");
  });

  it("caps backfill at TOPUP_MAX_MINUTES", async () => {
    const t = nowS();
    await env.DB.prepare("INSERT INTO seed_marker (id, last_ts, is_seed, received_at) VALUES (1, ?, 1, ?)").bind(t - 10 * 86400, t).run();
    expect((await seedTopUp(env, t)).minutes).toBe(TOPUP_MAX_MINUTES);
  });

  it("stops when real data is recent", async () => {
    expect((await postIngest(JSON.stringify(sampleBatch()))).status).toBe(200);
    const r = await seedTopUp(env, nowS());
    expect(r.skipped).toBe("real_data");
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 1")).toBe(0);
  });

  it("resumes once real data is older than 15 minutes", async () => {
    expect((await postIngest(JSON.stringify(sampleBatch()))).status).toBe(200);
    const r = await seedTopUp(env, nowS() + 16 * 60);
    expect(r.skipped).toBeUndefined();
    expect(r.windows).toBeGreaterThan(0);
  });

  it("runs from the */5 scheduled handler", async () => {
    const ctrl = createScheduledController({ scheduledTime: Date.now(), cron: "*/5 * * * *" });
    await worker.scheduled(ctrl, env);
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 1")).toBeGreaterThan(0);
  });
});

describe("prune cron", () => {
  it("deletes old rows per class and keeps fresh ones", async () => {
    const t = nowS();
    const day = 86400;
    const insW = env.DB.prepare(
      "INSERT INTO windows (device_hash, ts, duration_s, bytes_in, bytes_out, pkts, distinct_dests, distinct_ports, syn_ratio, score, countries, is_seed, received_at) VALUES (?, ?, 60, 1, 1, 1, 1, 1, 0, 0.1, '{}', ?, ?)",
    );
    const insA = env.DB.prepare("INSERT INTO alerts (id, type, device_hash, ts, severity, detail, is_seed, received_at) VALUES (?, 'flood', 'dev-000000', ?, 'low', '{}', ?, ?)");
    const insD = env.DB.prepare("INSERT INTO devices (device_hash, vendor, first_seen, last_seen, is_seed, received_at) VALUES (?, 'Apple', ?, ?, ?, ?)");
    const m = (x: number) => Math.floor(x / 60) * 60;
    await env.DB.batch([
      insW.bind("dev-000001", m(t - 8 * day), 0, t - 8 * day), // real, old → gone
      insW.bind("dev-000001", m(t - 2 * day), 0, t - 2 * day), // real, 2 days → kept
      insW.bind("dev-000002", m(t - 2 * day), 1, t - 2 * day), // seed, 2 days → gone
      insW.bind("dev-000002", m(t - 3600), 1, t - 3600), // seed, fresh → kept
      insA.bind("a1", t - 8 * day, 0, t),
      insA.bind("a2", t - 2 * day, 0, t),
      insA.bind("a3", t - 2 * day, 1, t),
      insD.bind("dev-000001", t - 9 * day, t - 8 * day, 0, t),
      insD.bind("dev-000002", t - 2 * day, t - 2 * day, 1, t),
      insD.bind("dev-000003", t - 2 * day, t - 2 * day, 0, t),
      env.DB.prepare("INSERT INTO idempotency (key, received_at) VALUES ('old', ?), ('new', ?)").bind(t - 2 * day, t),
      env.DB.prepare("INSERT INTO ingest_log (request_id, status, ms, received_at) VALUES ('o', 200, 1, ?), ('n', 200, 1, ?)").bind(t - 2 * day, t),
    ]);
    const ctrl = createScheduledController({ scheduledTime: t * 1000, cron: "17 3 * * *" });
    await worker.scheduled(ctrl, env);
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 0")).toBe(1);
    expect(await n("SELECT COUNT(*) AS n FROM windows WHERE is_seed = 1")).toBe(1);
    expect((await env.DB.prepare("SELECT id FROM alerts ORDER BY id").all()).results).toEqual([{ id: "a2" }]);
    expect((await env.DB.prepare("SELECT device_hash FROM devices").all()).results).toEqual([{ device_hash: "dev-000003" }]);
    expect((await env.DB.prepare("SELECT key FROM idempotency").all()).results).toEqual([{ key: "new" }]);
    expect((await env.DB.prepare("SELECT request_id FROM ingest_log").all()).results).toEqual([{ request_id: "n" }]);
    const again = await prune(env, t);
    expect(Object.values(again).every((v) => v === 0)).toBe(true);
  });
});
