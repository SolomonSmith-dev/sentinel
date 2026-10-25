import { z } from "zod";
import type { Env } from "./env";
import { now } from "./env";
import { errorResponse, readCapped, sha256Hex, timingSafeEqualStr, TooLargeError } from "./http";

export const RAW_MAX = 256 * 1024;
export const DECODED_MAX = 1024 * 1024;
export const MAX_WINDOWS = 500;
export const MAX_ALERTS = 500;
export const MAX_DEVICES = 200;
const CLOCK_SKEW_S = 300;
const IDEMPOTENCY_TTL_S = 86_400;

// Privacy guard (docs/api.md). IPv4 and MAC patterns are verbatim from the contract.
const IPV4_RE = /(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)/;
const MAC_RE = /(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}(?![0-9a-fA-F])/;
// IPv6-looking tokens: 3+ colon-separated hex groups, or any token using "::" compression.
const IPV6_RE = new RegExp(
  [
    String.raw`(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])`,
    String.raw`(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?(?![0-9a-fA-F])`,
    String.raw`(?<![0-9a-fA-F:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-fA-F])`,
  ].join("|"),
);

export function containsPii(text: string): boolean {
  return IPV4_RE.test(text) || MAC_RE.test(text) || IPV6_RE.test(text);
}

const deviceHash = z.string().regex(/^dev-[0-9a-f]{6}$/);
const unixTs = z.number().int().nonnegative();

const WindowSchema = z.object({
  device_hash: deviceHash,
  ts: unixTs.refine((t) => t % 60 === 0, "ts must be a 60 s bucket start"),
  duration_s: z.number().int().positive().max(3600),
  bytes_in: z.number().int().nonnegative(),
  bytes_out: z.number().int().nonnegative(),
  pkts: z.number().int().nonnegative(),
  distinct_dests: z.number().int().nonnegative(),
  distinct_ports: z.number().int().nonnegative(),
  syn_ratio: z.number().min(0).max(1),
  score: z.number().min(0).max(1).nullable(),
  countries: z.record(z.string().regex(/^[A-Z?]{2}$/), z.number().int().nonnegative()),
});

const AlertSchema = z.object({
  id: z.string().min(1).max(64),
  type: z.enum(["flood", "port_scan", "new_device", "geo_anomaly", "ml_anomaly", "suricata"]),
  device_hash: deviceHash,
  ts: unixTs,
  severity: z.enum(["low", "medium", "high", "critical"]),
  detail: z
    .record(z.string(), z.unknown())
    .refine((d) => JSON.stringify(d).length <= 2048, "detail over 2 KB"),
});

const DeviceSchema = z.object({
  device_hash: deviceHash,
  vendor: z.string().min(1).max(128),
  first_seen: unixTs,
});

export const BatchSchema = z.object({
  sensor_id: z.string().min(1).max(64),
  sent_at: unixTs,
  queue_depth: z.number().int().nonnegative(),
  devices: z.array(DeviceSchema).max(MAX_DEVICES),
  windows: z.array(WindowSchema).max(MAX_WINDOWS),
  alerts: z.array(AlertSchema).max(MAX_ALERTS),
});
export type Batch = z.infer<typeof BatchSchema>;

interface Attempt {
  requestId: string;
  started: number;
  receivedAt: number;
  rawBytes: number;
  decodedBytes: number;
  sensorId: string | null;
  queueDepth: number | null;
  counts: { windows: number; alerts: number; devices: number };
}

function logAttempt(env: Env, ctx: ExecutionContext, a: Attempt, status: number, error?: string): void {
  const ms = Date.now() - a.started;
  console.log(
    JSON.stringify({
      event: "ingest",
      request_id: a.requestId,
      status,
      error,
      sensor_id: a.sensorId,
      queue_depth: a.queueDepth,
      ...a.counts,
      bytes_raw: a.rawBytes,
      bytes_decoded: a.decodedBytes,
      ms,
    }),
  );
  ctx.waitUntil(
    env.DB.prepare(
      "INSERT INTO ingest_log (request_id, status, ms, bytes, sensor_id, queue_depth, is_seed, received_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
    )
      .bind(a.requestId, status, ms, a.rawBytes, a.sensorId, a.queueDepth, a.receivedAt)
      .run()
      .then(() => undefined)
      .catch((e: unknown) => console.error(JSON.stringify({ event: "ingest_log_failed", request_id: a.requestId, err: String(e) }))),
  );
}

function looksGzip(b: Uint8Array): boolean {
  return b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
}

async function gunzipCapped(raw: Uint8Array, max: number): Promise<Uint8Array> {
  const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream("gzip"));
  return readCapped(stream, max);
}

export async function handleIngest(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const a: Attempt = {
    requestId: req.headers.get("cf-ray") ?? crypto.randomUUID(),
    started: Date.now(),
    receivedAt: now(),
    rawBytes: 0,
    decodedBytes: 0,
    sensorId: null,
    queueDepth: null,
    counts: { windows: 0, alerts: 0, devices: 0 },
  };
  const fail = (status: number, code: string, message: string, headers?: Record<string, string>) => {
    logAttempt(env, ctx, a, status, code);
    return errorResponse(status, code, message, { "x-request-id": a.requestId, ...headers });
  };

  // 1. Rate limit per client IP.
  const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
  const { success } = await env.INGEST_LIMITER.limit({ key: `ingest:${ip}` });
  if (!success) return fail(429, "rate_limited", "Too many requests; limit is 60 per minute", { "retry-after": "60" });

  // 2. Kill switch.
  if (env.INGEST_ENABLED !== "true") return fail(503, "ingest_disabled", "Ingest is disabled");

  // 3. Auth, constant time.
  const auth = req.headers.get("authorization") ?? "";
  const presented = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const expected = env.SENTINEL_TOKEN ?? "";
  if (!expected || !presented || !(await timingSafeEqualStr(presented, expected))) {
    return fail(401, "unauthorized", "Missing or invalid bearer token");
  }

  // 4. Raw size cap, before reading the body.
  const declared = Number(req.headers.get("content-length") ?? "NaN");
  if (Number.isFinite(declared) && declared > RAW_MAX) {
    a.rawBytes = declared;
    return fail(413, "too_large", `Body over ${RAW_MAX} bytes`);
  }
  if (!req.body) return fail(400, "invalid_body", "Empty body");
  let raw: Uint8Array;
  try {
    raw = await readCapped(req.body, RAW_MAX);
  } catch (e) {
    if (e instanceof TooLargeError) return fail(413, "too_large", `Body over ${RAW_MAX} bytes`);
    return fail(400, "invalid_body", "Could not read body");
  }
  a.rawBytes = raw.byteLength;

  // 5. Decode (gzip optional). If the platform already decoded it, the magic bytes are gone.
  let decoded: Uint8Array = raw;
  const encoding = (req.headers.get("content-encoding") ?? "").toLowerCase();
  if (encoding.includes("gzip") && looksGzip(raw)) {
    try {
      decoded = await gunzipCapped(raw, DECODED_MAX);
    } catch (e) {
      if (e instanceof TooLargeError) return fail(413, "too_large", `Decompressed body over ${DECODED_MAX} bytes`);
      return fail(400, "invalid_body", "Invalid gzip stream");
    }
  } else if (decoded.byteLength > DECODED_MAX) {
    return fail(413, "too_large", `Decompressed body over ${DECODED_MAX} bytes`);
  }
  a.decodedBytes = decoded.byteLength;

  // 6. Idempotency key = sha256 of the uncompressed body.
  const key = (req.headers.get("idempotency-key") ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(key)) return fail(400, "missing_idempotency_key", "Idempotency-Key must be a sha256 hex digest");
  const digest = await sha256Hex(decoded);
  if (digest !== key) return fail(400, "checksum_mismatch", "Idempotency-Key does not match sha256 of the body");

  // 7. Privacy guard on the raw decoded text, before parsing fields.
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(decoded);
  } catch {
    return fail(400, "invalid_body", "Body is not UTF-8");
  }
  if (containsPii(text)) return fail(400, "pii_rejected", "Body contains an IP or MAC address");

  // 8. Parse, cap item counts, validate.
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return fail(400, "invalid_body", "Body is not valid JSON");
  }
  if (json && typeof json === "object") {
    const o = json as Record<string, unknown>;
    if (typeof o.sensor_id === "string") a.sensorId = o.sensor_id.slice(0, 64);
    const len = (k: string) => (Array.isArray(o[k]) ? (o[k] as unknown[]).length : 0);
    if (len("windows") > MAX_WINDOWS || len("alerts") > MAX_ALERTS || len("devices") > MAX_DEVICES) {
      return fail(400, "too_many_items", `At most ${MAX_WINDOWS} windows, ${MAX_ALERTS} alerts, ${MAX_DEVICES} devices per batch`);
    }
  }
  // JSON escapes (\u0031...) hide addresses from the raw-text check; re-check decoded text.
  if (containsPii(JSON.stringify(json))) {
    return fail(400, "pii_rejected", "Body contains an IP or MAC address");
  }
  const parsed = BatchSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return fail(400, "invalid_body", issue ? `${issue.path.join(".")}: ${issue.message}` : "Invalid body");
  }
  const batch = parsed.data;
  a.sensorId = batch.sensor_id;
  a.queueDepth = batch.queue_depth;
  a.counts = { windows: batch.windows.length, alerts: batch.alerts.length, devices: batch.devices.length };

  // 9. Duplicate check, then write everything in one atomic batch.
  try {
    const seen = await env.DB.prepare("SELECT 1 AS hit FROM idempotency WHERE key = ? AND received_at > ?")
      .bind(key, a.receivedAt - IDEMPOTENCY_TTL_S)
      .first<{ hit: number }>();
    if (seen) {
      logAttempt(env, ctx, a, 200, "duplicate");
      return Response.json({ status: "duplicate", request_id: a.requestId }, { headers: { "x-request-id": a.requestId } });
    }
    await env.DB.batch(buildWrites(env.DB, batch, key, a.receivedAt));
  } catch (e) {
    console.error(JSON.stringify({ event: "ingest_storage_error", request_id: a.requestId, err: String(e) }));
    return fail(503, "storage_unavailable", "Storage write failed; retry later", { "retry-after": "30" });
  }

  logAttempt(env, ctx, a, 200);
  return Response.json(
    { status: "ok", ...a.counts, request_id: a.requestId },
    { headers: { "x-request-id": a.requestId } },
  );
}

// Each upsert takes one JSON array parameter (?1) plus is_seed (?2) and received_at (?3), so a
// batch is a fixed 3-4 statements regardless of item count (D1 free plan: 50 queries/invocation,
// 100 bound params/statement). "WHERE true" disambiguates INSERT ... SELECT ... ON CONFLICT.
const J = (k: string) => `json_extract(j.value, '$.${k}')`;

const DEVICE_UPSERT = `INSERT INTO devices (device_hash, vendor, first_seen, last_seen, is_seed, received_at)
SELECT ${J("h")}, ${J("v")}, ${J("f")}, ${J("l")}, ?2, ?3 FROM json_each(?1) j WHERE true
ON CONFLICT(device_hash) DO UPDATE SET
  vendor = CASE WHEN excluded.vendor <> 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
  first_seen = MIN(devices.first_seen, excluded.first_seen),
  last_seen = MAX(devices.last_seen, excluded.last_seen),
  is_seed = excluded.is_seed,
  received_at = excluded.received_at`;

const WINDOW_UPSERT = `INSERT INTO windows (device_hash, ts, duration_s, bytes_in, bytes_out, pkts, distinct_dests, distinct_ports, syn_ratio, score, countries, sensor_id, is_seed, received_at)
SELECT ${J("device_hash")}, ${J("ts")}, ${J("duration_s")}, ${J("bytes_in")}, ${J("bytes_out")}, ${J("pkts")},
  ${J("distinct_dests")}, ${J("distinct_ports")}, ${J("syn_ratio")}, ${J("score")}, ${J("countries")}, ?4, ?2, ?3
FROM json_each(?1) j WHERE true
ON CONFLICT(device_hash, ts) DO UPDATE SET
  duration_s = excluded.duration_s, bytes_in = excluded.bytes_in, bytes_out = excluded.bytes_out,
  pkts = excluded.pkts, distinct_dests = excluded.distinct_dests, distinct_ports = excluded.distinct_ports,
  syn_ratio = excluded.syn_ratio, score = excluded.score, countries = excluded.countries,
  sensor_id = excluded.sensor_id, is_seed = excluded.is_seed, received_at = excluded.received_at`;

const ALERT_UPSERT = `INSERT INTO alerts (id, type, device_hash, ts, severity, detail, is_seed, received_at)
SELECT ${J("id")}, ${J("type")}, ${J("device_hash")}, ${J("ts")}, ${J("severity")}, ${J("detail")}, ?2, ?3
FROM json_each(?1) j WHERE true
ON CONFLICT(id) DO UPDATE SET
  type = excluded.type, device_hash = excluded.device_hash, ts = excluded.ts, severity = excluded.severity,
  detail = excluded.detail, is_seed = excluded.is_seed, received_at = excluded.received_at`;

export interface RowSet {
  devices: { device_hash: string; vendor: string; first_seen: number }[];
  windows: Batch["windows"];
  alerts: { id: string; type: string; device_hash: string; ts: number; severity: string; detail: Record<string, unknown> }[];
  sensorId: string | null;
  isSeed: 0 | 1;
}

/** Upsert statements for a set of rows. Clamps ts to received_at + 300. Shared by ingest and seed top-up. */
export function buildRowStatements(db: D1Database, rows: RowSet, receivedAt: number): D1PreparedStatement[] {
  const maxTs = receivedAt + CLOCK_SKEW_S;
  const maxBucket = Math.floor(maxTs / 60) * 60;
  const clampBucket = (t: number) => Math.min(t, maxBucket);
  const clamp = (t: number) => Math.min(t, maxTs);

  // Device span seen in this batch: listed devices plus any device that only appears in windows/alerts.
  const span = new Map<string, { vendor: string; first: number; last: number }>();
  const touch = (h: string, ts: number, vendor = "Unknown") => {
    const cur = span.get(h);
    if (!cur) span.set(h, { vendor, first: ts, last: ts });
    else {
      cur.first = Math.min(cur.first, ts);
      cur.last = Math.max(cur.last, ts);
      if (vendor !== "Unknown") cur.vendor = vendor;
    }
  };
  for (const d of rows.devices) touch(d.device_hash, clamp(d.first_seen), d.vendor);
  for (const w of rows.windows) touch(w.device_hash, clampBucket(w.ts));
  for (const al of rows.alerts) touch(al.device_hash, clamp(al.ts));

  const stmts: D1PreparedStatement[] = [];
  if (span.size > 0) {
    const devs = [...span].map(([h, s]) => ({ h, v: s.vendor, f: s.first, l: s.last }));
    stmts.push(db.prepare(DEVICE_UPSERT).bind(JSON.stringify(devs), rows.isSeed, receivedAt));
  }
  if (rows.windows.length > 0) {
    // countries and detail are stored as JSON text, so pre-serialize them as strings.
    const wins = rows.windows.map((w) => ({ ...w, ts: clampBucket(w.ts), countries: JSON.stringify(w.countries) }));
    stmts.push(db.prepare(WINDOW_UPSERT).bind(JSON.stringify(wins), rows.isSeed, receivedAt, rows.sensorId));
  }
  if (rows.alerts.length > 0) {
    const als = rows.alerts.map((x) => ({ ...x, ts: clamp(x.ts), detail: JSON.stringify(x.detail) }));
    stmts.push(db.prepare(ALERT_UPSERT).bind(JSON.stringify(als), rows.isSeed, receivedAt));
  }
  return stmts;
}

function buildWrites(db: D1Database, batch: Batch, key: string, receivedAt: number): D1PreparedStatement[] {
  const stmts = buildRowStatements(
    db,
    { devices: batch.devices, windows: batch.windows, alerts: batch.alerts, sensorId: batch.sensor_id, isSeed: 0 },
    receivedAt,
  );
  stmts.push(
    db
      .prepare("INSERT INTO idempotency (key, is_seed, received_at) VALUES (?, 0, ?) ON CONFLICT(key) DO UPDATE SET received_at = excluded.received_at")
      .bind(key, receivedAt),
  );
  return stmts;
}
