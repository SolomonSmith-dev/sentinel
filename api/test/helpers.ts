import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";

export const TOKEN = "test-token";
export const BASE = "https://sentinel.test";

let ipCounter = 0;
/** Unique client IP per request keeps tests clear of the 60/min limiter unless a test wants it. */
export function freshIp(): string {
  ipCounter++;
  return `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;
}

export function fetchWorker(path: string, init?: RequestInit): Promise<Response> {
  return (exports as unknown as { default: Fetcher }).default.fetch(new Request(BASE + path, init));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function nowS(): number {
  return Math.floor(Date.now() / 1000);
}

export function sampleBatch(overrides: Record<string, unknown> = {}, t = nowS()) {
  const ts = Math.floor(t / 60) * 60 - 60;
  return {
    sensor_id: "sensor-01",
    sent_at: t,
    queue_depth: 2,
    devices: [{ device_hash: "dev-3fa91c", vendor: "Apple", first_seen: ts }],
    windows: [
      {
        device_hash: "dev-3fa91c",
        ts,
        duration_s: 60,
        bytes_in: 120394,
        bytes_out: 20311,
        pkts: 412,
        distinct_dests: 9,
        distinct_ports: 4,
        syn_ratio: 0.03,
        score: 0.41,
        countries: { US: 130000, DE: 10705 },
      },
    ],
    alerts: [
      {
        id: crypto.randomUUID(),
        type: "port_scan",
        device_hash: "dev-3fa91c",
        ts: ts + 12,
        severity: "high",
        detail: { distinct_ports: 87, window_s: 10 },
      },
    ],
    ...overrides,
  };
}

export async function postIngest(
  body: string | Uint8Array,
  opts: { token?: string | null; key?: string; gzip?: boolean; ip?: string; headers?: Record<string, string> } = {},
): Promise<Response> {
  const text = typeof body === "string" ? body : new TextDecoder().decode(body);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "cf-connecting-ip": opts.ip ?? freshIp(),
    "idempotency-key": opts.key ?? (await sha256Hex(text)),
    ...opts.headers,
  };
  if (opts.token !== null) headers.authorization = `Bearer ${opts.token ?? TOKEN}`;
  let payload: BodyInit = typeof body === "string" ? body : body;
  if (opts.gzip) {
    headers["content-encoding"] = "gzip";
    payload = await gzip(text);
  }
  return fetchWorker("/api/ingest", { method: "POST", headers, body: payload });
}

export { env };
