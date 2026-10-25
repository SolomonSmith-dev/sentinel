// Dev-only mock of the Sentinel read API (docs/api.md). Serves contract-shaped
// JSON generated from the current clock, so the page looks live. Responses are
// deterministic per minute, so ETag / If-None-Match -> 304 behaves like the Worker.
//
// MOCK_FAIL=alerts,metrics   make those endpoints return 503 (to test stale states)
// MOCK_LIVE=1                pretend a real sensor is reporting (no seed rows)
import { createHash } from "node:crypto";
import type { Plugin } from "vite";

type Json = Record<string, unknown>;

const DEVICES = [
  { device_hash: "dev-3fa91c", vendor: "Apple", score: 0.86, weight: 1.6 },
  { device_hash: "dev-a07e52", vendor: "Raspberry Pi Trading", score: 0.64, weight: 0.5 },
  { device_hash: "dev-91bd0f", vendor: "Samsung Electronics", score: 0.41, weight: 1.1 },
  { device_hash: "dev-5c2e88", vendor: "Private MAC", score: 0.33, weight: 0.9 },
  { device_hash: "dev-e4410a", vendor: "Sonos", score: 0.22, weight: 0.7 },
  { device_hash: "dev-0b7d3e", vendor: "Espressif", score: 0.12, weight: 0.15 },
  { device_hash: "dev-c88a14", vendor: "Intel Corporate", score: 0.07, weight: 1.3 },
  { device_hash: "dev-7f19d2", vendor: "Unknown", score: null, weight: 0.2 },
];

const COUNTRIES: [string, number][] = [
  ["US", 0.71], ["DE", 0.08], ["NL", 0.06], ["IE", 0.05], ["JP", 0.03],
  ["GB", 0.025], ["SG", 0.02], ["CA", 0.01], ["RU", 0.003], ["??", 0.002],
];

function rng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    return s / 4294967296;
  };
}

const nowS = () => Math.floor(Date.now() / 1000);
const minuteFloor = (t: number) => t - (t % 60);

function diurnal(ts: number) {
  const hour = (ts / 3600) % 24; // UTC; peak around 03:00 UTC (evening PT)
  return 0.55 + 0.45 * Math.cos(((hour - 3) / 24) * 2 * Math.PI);
}

function minuteTotals(ts: number) {
  const r = rng(ts);
  const base = 2_400_000 * diurnal(ts);
  const burst = r() > 0.97 ? 4 + r() * 6 : 1;
  const bytes_in = Math.round(base * (0.75 + r() * 0.5) * burst);
  const bytes_out = Math.round(bytes_in * (0.12 + r() * 0.1));
  return { ts, bytes_in, bytes_out, pkts: Math.round((bytes_in + bytes_out) / 900) };
}

const live = () => process.env.MOCK_LIVE === "1";
const seedInt = () => (live() ? 0 : 1);

function flows(q: URLSearchParams): Json {
  const minutes = clamp(Number(q.get("minutes") ?? 60), 5, 1440);
  const end = minuteFloor(nowS()) - 60;
  const points = [];
  for (let ts = end - (minutes - 1) * 60; ts <= end; ts += 60) points.push(minuteTotals(ts));
  return { minutes, points, is_seed: !live() };
}

function alerts(q: URLSearchParams): Json {
  const limit = clamp(Number(q.get("limit") ?? 50), 1, 200);
  const now = minuteFloor(nowS());
  const templates: [string, string, string, Json][] = [
    ["port_scan", "high", "dev-3fa91c", { distinct_ports: 87, window_s: 10 }],
    ["ml_anomaly", "medium", "dev-3fa91c", { score: 0.86, threshold: 0.8 }],
    ["suricata", "high", "dev-a07e52", { signature: "ET SCAN Potential SSH Scan OUTBOUND", sid: 2003068, category: "Attempted Information Leak" }],
    ["geo_anomaly", "medium", "dev-91bd0f", { country: "RU" }],
    ["new_device", "low", "dev-7f19d2", { vendor: "Unknown" }],
    ["flood", "critical", "dev-c88a14", { pps: 18400, window_s: 10, syn_ratio: 0.94 }],
    ["suricata", "low", "dev-e4410a", { signature: "ET POLICY Spotify P2P Client", sid: 2027397, category: "Potential Corporate Privacy Violation" }],
    ["ml_anomaly", "high", "dev-a07e52", { score: 0.91, threshold: 0.8 }],
    ["new_device", "low", "dev-5c2e88", { vendor: "Private MAC" }],
    ["geo_anomaly", "high", "dev-0b7d3e", { country: "CN" }],
  ];
  const offsets = [2, 7, 19, 41, 66, 130, 210, 380, 600, 990, 1300, 1400];
  const out = offsets.map((m, i) => {
    const [type, severity, device_hash, detail] = templates[i % templates.length];
    const ts = now - m * 60 + ((i * 17) % 60);
    return {
      id: `00000000-0000-4000-8000-${String(ts).padStart(12, "0")}`,
      type, device_hash, ts, severity, detail, is_seed: seedInt(),
    };
  });
  return { alerts: out.slice(0, limit) };
}

function devices(): Json {
  const now = minuteFloor(nowS());
  const r = rng(minuteFloor(now));
  const list = DEVICES.map((d, i) => ({
    device_hash: d.device_hash,
    vendor: d.vendor,
    first_seen: now - 86400 * (6 - (i % 5)) - 3600 * i,
    last_seen: i === 7 ? now - 3 * 3600 : now - Math.floor(r() * 90),
    last_score: d.score,
    alerts_24h: [4, 3, 1, 1, 1, 1, 1, 1][i],
    bytes_24h: Math.round(2_400_000 * 1440 * 0.7 * (d.weight / 6.45)),
    is_seed: seedInt(),
  }));
  return { devices: list };
}

function top(q: URLSearchParams): Json {
  const minutes = clamp(Number(q.get("minutes") ?? 60), 5, 1440);
  const total = (flows(new URLSearchParams({ minutes: String(minutes) })).points as { bytes_in: number; bytes_out: number }[])
    .reduce((a, p) => a + p.bytes_in + p.bytes_out, 0);
  const wsum = DEVICES.reduce((a, d) => a + d.weight, 0);
  return {
    minutes,
    devices: DEVICES.map((d) => ({ device_hash: d.device_hash, vendor: d.vendor, bytes: Math.round((total * d.weight) / wsum), is_seed: seedInt() }))
      .sort((a, b) => b.bytes - a.bytes),
    countries: COUNTRIES.map(([country, f]) => ({ country, bytes: Math.round(total * f) })),
  };
}

function metrics(): Json {
  const now = minuteFloor(nowS());
  return {
    ingest: { count_24h: live() ? 1438 : 0, failed_24h: { "401": 0, "413": 0, "429": 2, "503": 1 }, p50_ms: 12, p95_ms: 41 },
    sensor: live() ? { sensor_id: "sensor-01", last_seen: minuteFloor(now) - 4, queue_depth: 0 } : null,
    rows: { devices: 8, windows: 11_312, alerts: 37 },
    seed_active: !live(),
  };
}

function clamp(n: number, lo: number, hi: number) {
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.floor(n))) : lo;
}

const routes: Record<string, (q: URLSearchParams) => Json> = {
  "/api/flows": flows,
  "/api/alerts": alerts,
  "/api/devices": devices,
  "/api/top": top,
  "/api/metrics": metrics,
  "/api/health": () => ({ ok: true }),
};

export function mockApi(): Plugin {
  return {
    name: "sentinel-mock-api",
    apply: "serve",
    configureServer(server) {
      server.config.logger.info("  sentinel: /api/* served by dev mock (set VITE_API_PROXY to use wrangler dev)");
      server.middlewares.use((req, res, next) => {
        if (!req.url?.startsWith("/api/")) return next();
        const url = new URL(req.url, "http://mock");
        const handler = routes[url.pathname];
        res.setHeader("Content-Type", "application/json");
        const send = (status: number, body: Json) => { res.statusCode = status; res.end(JSON.stringify(body)); };
        if (!handler) return send(404, { error: "not_found", message: "No such endpoint" });
        if (req.method !== "GET") return send(405, { error: "method_not_allowed", message: "Mock serves GET only" });
        const name = url.pathname.slice(5);
        if ((process.env.MOCK_FAIL ?? "").split(",").includes(name)) {
          return send(503, { error: "storage_unavailable", message: "Mock failure (MOCK_FAIL)" });
        }
        const body = JSON.stringify(handler(url.searchParams));
        const etag = `"${createHash("sha1").update(body).digest("hex").slice(0, 16)}"`;
        res.setHeader("ETag", etag);
        res.setHeader("Cache-Control", "public, max-age=10");
        if (req.headers["if-none-match"] === etag) { res.statusCode = 304; return res.end(); }
        res.statusCode = 200;
        res.end(body);
      });
    },
  };
}
