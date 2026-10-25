import { describe, expect, it } from "vitest";
import { containsPii } from "../src/ingest";
import vectors from "./pii-vectors.json";
import { env, fetchWorker, gzip, nowS, postIngest, sampleBatch, sha256Hex } from "./helpers";

async function count(table: string): Promise<number> {
  const r = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
  return r!.n;
}

// Same vectors as sensor/shipper/tests/test_geo_anon_privacy.py: shipper and Worker must agree.
describe("privacy vectors shared with the shipper", () => {
  it.each(vectors.map((v) => [v.text, v.pii] as const))("containsPii(%j) = %s", (text, pii) => {
    expect(containsPii(text)).toBe(pii);
  });

  it("rejects a JSON-escaped IPv4 (\\u0031...) that the raw-text scan cannot see", async () => {
    const body = JSON.stringify(sampleBatch()).replace('"vendor":"Apple"', '"vendor":"\\u0031\\u0030.0.0.1"');
    expect(body).toContain("\\u0031");
    const res = await postIngest(body);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "pii_rejected" });
  });
});

describe("POST /api/ingest", () => {
  it("401 without a token", async () => {
    const res = await postIngest(JSON.stringify(sampleBatch()), { token: null });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "unauthorized" });
  });

  it("401 with a wrong token", async () => {
    const res = await postIngest(JSON.stringify(sampleBatch()), { token: "nope" });
    expect(res.status).toBe(401);
  });

  it("200 with a good token and writes rows + ingest_log", async () => {
    const res = await postIngest(JSON.stringify(sampleBatch()));
    expect(res.status).toBe(200);
    const body = await res.json<Record<string, unknown>>();
    expect(body).toMatchObject({ status: "ok", windows: 1, alerts: 1, devices: 1 });
    expect(typeof body.request_id).toBe("string");
    expect(await count("windows")).toBe(1);
    expect(await count("alerts")).toBe(1);
    const dev = await env.DB.prepare("SELECT vendor, is_seed FROM devices WHERE device_hash = 'dev-3fa91c'").first();
    expect(dev).toEqual({ vendor: "Apple", is_seed: 0 });
  });

  it("duplicate idempotency key is a no-op", async () => {
    const text = JSON.stringify(sampleBatch());
    expect((await postIngest(text)).status).toBe(200);
    const before = await env.DB.prepare("SELECT received_at FROM windows").first();
    const res = await postIngest(text);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "duplicate" });
    expect(await count("windows")).toBe(1);
    expect(await env.DB.prepare("SELECT received_at FROM windows").first()).toEqual(before);
  });

  it("checksum mismatch → 400", async () => {
    const res = await postIngest(JSON.stringify(sampleBatch()), { key: "0".repeat(64) });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "checksum_mismatch" });
  });

  it("oversize raw body → 413", async () => {
    const big = JSON.stringify(sampleBatch({ pad: "x".repeat(300 * 1024) }));
    const res = await postIngest(big);
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ error: "too_large" });
  });

  it("decompressed body over 1 MB → 413", async () => {
    const big = JSON.stringify(sampleBatch({ pad: "x".repeat(1100 * 1024) }));
    const res = await postIngest(big, { gzip: true });
    expect(res.status).toBe(413);
  });

  it("pii_rejected for an IPv4 and a MAC", async () => {
    for (const leak of ["192.168.1.20", "a4:83:e7:12:34:56"]) {
      const text = JSON.stringify(sampleBatch({ devices: [{ device_hash: "dev-3fa91c", vendor: leak, first_seen: 1 }] }));
      const res = await postIngest(text);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: "pii_rejected" });
    }
    expect(await count("windows")).toBe(0);
  });

  it("privacy guard catches IPv6 and leaves normal bodies alone", () => {
    expect(containsPii('{"x":"fe80::1"}')).toBe(true);
    expect(containsPii('{"x":"2001:db8:85a3:0:0:8a2e:370:7334"}')).toBe(true);
    expect(containsPii(JSON.stringify(sampleBatch()))).toBe(false);
  });

  it("pii_rejected for JSON-escaped addresses", async () => {
    const base = JSON.stringify(sampleBatch({ devices: [{ device_hash: "dev-3fa91c", vendor: "VENDOR", first_seen: 1 }] }));
    for (const leak of ["\\u0031\\u0039\\u0032.168.1.20", "a4\\u003a83:e7:12:34:56"]) {
      const res = await postIngest(base.replace("VENDOR", leak));
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: "pii_rejected" });
    }
  });

  it("privacy guard catches letter-adjacent addresses, spares uuids and signatures", () => {
    expect(containsPii('{"x":"x10.0.0.1y"}')).toBe(true);
    expect(containsPii('{"x":"zza4:83:e7:12:34:56q"}')).toBe(true);
    expect(containsPii('{"x":"xfe80::1y"}')).toBe(true);
    expect(containsPii('{"id":"123e4567-e89b-42d3-a456-426614174000","score":0.03,"cc":"US","d":"dev-5e0a11"}')).toBe(false);
    expect(containsPii('{"signature":"ET SCAN Possible Nmap User-Agent Observed","sid":2024364}')).toBe(false);
  });

  it("too_many_items", async () => {
    const w = sampleBatch().windows[0]!;
    const windows = Array.from({ length: 501 }, (_, i) => ({ ...w, ts: w.ts - i * 60 }));
    const res = await postIngest(JSON.stringify(sampleBatch({ windows })));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "too_many_items" });
  });

  it("accepts 500 windows in one batch", async () => {
    const w = sampleBatch().windows[0]!;
    const windows = Array.from({ length: 500 }, (_, i) => ({ ...w, ts: w.ts - i * 60 }));
    const res = await postIngest(JSON.stringify(sampleBatch({ windows })), { gzip: true });
    expect(res.status).toBe(200);
    expect(await count("windows")).toBe(500);
  });

  it("INGEST_ENABLED=false → 503", async () => {
    const { default: worker } = await import("../src/index");
    const { createExecutionContext, waitOnExecutionContext } = await import("cloudflare:test");
    const text = JSON.stringify(sampleBatch());
    const req = new Request("https://sentinel.test/api/ingest", {
      method: "POST",
      headers: { authorization: "Bearer test-token", "idempotency-key": await sha256Hex(text) },
      body: text,
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, { ...env, INGEST_ENABLED: "false" }, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "ingest_disabled" });
  });

  it("D1 failure → 503 storage_unavailable", async () => {
    const { default: worker } = await import("../src/index");
    const { createExecutionContext, waitOnExecutionContext } = await import("cloudflare:test");
    const text = JSON.stringify(sampleBatch());
    const broken = new Proxy(env.DB, {
      get(target, prop) {
        if (prop === "batch") return () => Promise.reject(new Error("D1_ERROR: boom"));
        const v = Reflect.get(target, prop);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(
      new Request("https://sentinel.test/api/ingest", {
        method: "POST",
        headers: { authorization: "Bearer test-token", "idempotency-key": await sha256Hex(text) },
        body: text,
      }),
      { ...env, DB: broken },
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "storage_unavailable" });
  });

  it("gzip body accepted", async () => {
    const res = await postIngest(JSON.stringify(sampleBatch()), { gzip: true });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok", windows: 1 });
  });

  it("clamps future ts to received_at + 300", async () => {
    const t = Math.floor(Date.now() / 1000);
    const future = Math.floor((t + 3600) / 60) * 60;
    const b = sampleBatch();
    b.windows[0]!.ts = future;
    b.alerts[0]!.ts = t + 3600;
    expect((await postIngest(JSON.stringify(b))).status).toBe(200);
    const w = await env.DB.prepare("SELECT ts, received_at FROM windows").first<{ ts: number; received_at: number }>();
    expect(w!.ts).toBeLessThanOrEqual(w!.received_at + 300);
    expect(w!.ts % 60).toBe(0);
    const a = await env.DB.prepare("SELECT ts, received_at FROM alerts").first<{ ts: number; received_at: number }>();
    expect(a!.ts).toBe(a!.received_at + 300);
  });

  it("rejects invalid fields", async () => {
    const b = sampleBatch();
    b.windows[0]!.ts += 7;
    const res = await postIngest(JSON.stringify(b));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_body" });
  });

  it("429 after 60 requests per minute from one IP", async () => {
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await postIngest("{}", { ip: "198.51.100.7", token: "bad" })).status;
    expect(last).toBe(429);
  });

  it("logs every attempt in ingest_log", async () => {
    await postIngest("{}", { token: null });
    await postIngest(JSON.stringify(sampleBatch()));
    const { results } = await env.DB.prepare("SELECT status, sensor_id, queue_depth FROM ingest_log ORDER BY id").all();
    expect(results).toEqual([
      { status: 401, sensor_id: null, queue_depth: null },
      { status: 200, sensor_id: "sensor-01", queue_depth: 2 },
    ]);
  });

  it("100 bad-token POSTs write at most one 401 row, and 429s at most one row", async () => {
    for (let i = 0; i < 100; i++) expect((await postIngest("{}", { token: "bad" })).status).toBe(401);
    for (let i = 0; i < 70; i++) await postIngest("{}", { token: "bad", ip: "198.51.100.9" });
    await new Promise((r) => setTimeout(r, 50));
    const { results } = await env.DB.prepare("SELECT status, COUNT(*) AS n FROM ingest_log GROUP BY status ORDER BY status").all();
    // The same-IP burst hits 401 (already throttled this minute) and then 429 (one row).
    expect(results).toEqual([
      { status: 401, n: 1 },
      { status: 429, n: 1 },
    ]);
  });

  it("authenticated failures still log a row each", async () => {
    for (let i = 0; i < 3; i++) expect((await postIngest("not json")).status).toBe(400);
    await postIngest(JSON.stringify(sampleBatch()));
    const { results } = await env.DB.prepare("SELECT status, COUNT(*) AS n FROM ingest_log GROUP BY status ORDER BY status").all();
    expect(results).toEqual([
      { status: 200, n: 1 },
      { status: 400, n: 3 },
    ]);
  });

  it("rejects window and alert ts older than 8 days, accepts just inside", async () => {
    const t = nowS();
    const old = Math.floor((t - 8 * 86_400) / 60) * 60 - 60;
    const b = sampleBatch();
    b.windows[0]!.ts = old;
    let res = await postIngest(JSON.stringify(b));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_body" });

    const c = sampleBatch();
    c.alerts[0]!.ts = t - 8 * 86_400 - 5;
    res = await postIngest(JSON.stringify(c));
    expect(res.status).toBe(400);

    const ok = sampleBatch();
    ok.windows[0]!.ts = Math.floor((t - 7 * 86_400) / 60) * 60;
    ok.alerts[0]!.ts = t - 7 * 86_400;
    expect((await postIngest(JSON.stringify(ok))).status).toBe(200);
  });

  it("gzip helper round trip sanity", async () => {
    const z = await gzip("hello");
    expect(z[0]).toBe(0x1f);
  });

  it("unknown /api route → 404 JSON", async () => {
    const res = await fetchWorker("/api/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found" });
  });
});
