import { describe, expect, it } from "vitest";
import { env, fetchWorker, nowS, postIngest, sampleBatch } from "./helpers";

async function getJson(path: string) {
  const res = await fetchWorker(path);
  expect(res.status).toBe(200);
  expect(res.headers.get("etag")).toMatch(/^"[0-9a-f]+"$/);
  expect(res.headers.get("cache-control")).toBe("public, max-age=10");
  return { res, body: await res.json<any>() };
}

describe("read endpoints", () => {
  it("GET /api/health", async () => {
    const { body } = await getJson("/api/health");
    expect(body).toEqual({ ok: true });
  });

  it("GET /api/flows shape and is_seed", async () => {
    await postIngest(JSON.stringify(sampleBatch()));
    const { body } = await getJson("/api/flows?minutes=30");
    expect(body.minutes).toBe(30);
    expect(body.is_seed).toBe(false);
    expect(body.points).toHaveLength(1);
    expect(body.points[0]).toEqual({ ts: expect.any(Number), bytes_in: 120394, bytes_out: 20311, pkts: 412 });
    // clamping of minutes
    expect((await getJson("/api/flows?minutes=1")).body.minutes).toBe(5);
    expect((await getJson("/api/flows?minutes=99999")).body.minutes).toBe(1440);
    expect((await getJson("/api/flows")).body.minutes).toBe(60);
  });

  it("GET /api/alerts shape, newest first, limit and since", async () => {
    const b = sampleBatch();
    const a0 = b.alerts[0]!;
    b.alerts.push({ ...a0, id: crypto.randomUUID(), ts: a0.ts + 5, type: "geo_anomaly", detail: { country: "RU" } as any });
    await postIngest(JSON.stringify(b));
    const { body } = await getJson("/api/alerts");
    expect(body.alerts).toHaveLength(2);
    expect(body.alerts[0]).toEqual({
      id: expect.any(String),
      type: "geo_anomaly",
      device_hash: "dev-3fa91c",
      ts: a0.ts + 5,
      severity: "high",
      detail: { country: "RU" },
      is_seed: 0,
    });
    expect((await getJson("/api/alerts?limit=1")).body.alerts).toHaveLength(1);
    expect((await getJson(`/api/alerts?since=${a0.ts}`)).body.alerts).toHaveLength(1);
  });

  it("GET /api/devices shape", async () => {
    await postIngest(JSON.stringify(sampleBatch()));
    const { body } = await getJson("/api/devices?t=shape");
    expect(body.devices).toEqual([
      {
        device_hash: "dev-3fa91c",
        vendor: "Apple",
        first_seen: expect.any(Number),
        last_seen: expect.any(Number),
        last_score: 0.41,
        alerts_24h: 1,
        bytes_24h: 140705,
        is_seed: 0,
      },
    ]);
  });

  it("GET /api/devices sorts by last_score desc, nulls last", async () => {
    const b = sampleBatch();
    const w = b.windows[0]!;
    b.devices = [];
    b.windows = [
      { ...w, device_hash: "dev-aaaaaa", score: null as any },
      { ...w, device_hash: "dev-bbbbbb", score: 0.9 },
      { ...w, device_hash: "dev-cccccc", score: 0.2 },
    ];
    b.alerts = [];
    await postIngest(JSON.stringify(b));
    const { body } = await getJson("/api/devices?t=sort");
    expect(body.devices.map((d: any) => d.device_hash)).toEqual(["dev-bbbbbb", "dev-cccccc", "dev-aaaaaa"]);
    expect(body.devices[0].vendor).toBe("Unknown");
  });

  it("GET /api/top shape", async () => {
    await postIngest(JSON.stringify(sampleBatch()));
    const { body } = await getJson("/api/top?minutes=60&t=shape");
    expect(body).toEqual({
      minutes: 60,
      devices: [{ device_hash: "dev-3fa91c", vendor: "Apple", bytes: 140705, is_seed: 0 }],
      countries: [
        { country: "US", bytes: 130000 },
        { country: "DE", bytes: 10705 },
      ],
    });
  });

  it("GET /api/metrics shape", async () => {
    const empty = (await getJson("/api/metrics")).body;
    expect(empty.sensor).toBeNull();
    expect(empty.seed_active).toBe(true);
    await postIngest("{}", { token: "bad" });
    await postIngest(JSON.stringify(sampleBatch()));
    const { body } = await getJson("/api/metrics");
    expect(body).toEqual({
      ingest: {
        count_24h: 1,
        failed_24h: { "401": 1, "413": 0, "429": 0, "503": 0 },
        p50_ms: expect.any(Number),
        p95_ms: expect.any(Number),
      },
      sensor: { sensor_id: "sensor-01", last_seen: expect.any(Number), queue_depth: 2 },
      rows: { devices: 1, windows: 1, alerts: 1 },
      seed_active: false,
    });
    expect(Math.abs(body.sensor.last_seen - nowS())).toBeLessThan(5);
  });

  it("304 on matching If-None-Match, for each endpoint", async () => {
    await postIngest(JSON.stringify(sampleBatch()));
    for (const p of ["/api/health", "/api/flows", "/api/alerts", "/api/devices?t=304", "/api/top?t=304", "/api/metrics"]) {
      const first = await fetchWorker(p);
      const etag = first.headers.get("etag")!;
      await first.arrayBuffer();
      const second = await fetchWorker(p, { headers: { "if-none-match": etag } });
      expect(second.status, p).toBe(304);
      expect(second.headers.get("etag")).toBe(etag);
      expect(await second.text()).toBe("");
      const third = await fetchWorker(p, { headers: { "if-none-match": '"stale"' } });
      expect(third.status, p).toBe(200);
      await third.arrayBuffer();
    }
  });

  it("/api/top is served from the Cache API for 10 s", async () => {
    const p = "/api/top?t=cache";
    const first = await (await fetchWorker(p)).json<any>();
    expect(first.devices).toHaveLength(0);
    await postIngest(JSON.stringify(sampleBatch()));
    // give waitUntil(cache.put) a tick
    await new Promise((r) => setTimeout(r, 50));
    const second = await (await fetchWorker(p)).json<any>();
    expect(second.devices).toHaveLength(0);
    const uncached = await (await fetchWorker("/api/top?t=cache2")).json<any>();
    expect(uncached.devices).toHaveLength(1);
  });

  it("row counts in D1 match ingest", async () => {
    await postIngest(JSON.stringify(sampleBatch()));
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM idempotency").first<{ n: number }>();
    expect(r!.n).toBe(1);
  });
});
