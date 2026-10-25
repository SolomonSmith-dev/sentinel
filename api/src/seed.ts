// Deterministic synthetic demo data. Pure functions, no imports, so the Node
// seed script (scripts/seed-remote.ts) can load this file directly.
// The same (minute ts) always yields the same rows, so re-running is an upsert no-op.

export interface SeedDevice {
  device_hash: string;
  vendor: string;
  /** relative traffic weight */
  weight: number;
  countries: string[];
}

export interface SeedWindow {
  device_hash: string;
  ts: number;
  duration_s: number;
  bytes_in: number;
  bytes_out: number;
  pkts: number;
  distinct_dests: number;
  distinct_ports: number;
  syn_ratio: number;
  score: number;
  countries: Record<string, number>;
}

export interface SeedAlert {
  id: string;
  type: string;
  device_hash: string;
  ts: number;
  severity: string;
  detail: Record<string, string | number>;
}

// device_hash = first 6 hex chars of sha256("sentinel-seed-device-<n>"), n = 1..8.
export const SEED_DEVICES: SeedDevice[] = [
  { device_hash: "dev-4bd03b", vendor: "Apple", weight: 1.0, countries: ["US", "IE", "NL"] },
  { device_hash: "dev-f3157b", vendor: "Apple", weight: 0.6, countries: ["US", "JP"] },
  { device_hash: "dev-a05e38", vendor: "Google", weight: 1.6, countries: ["US", "NL"] },
  { device_hash: "dev-d35248", vendor: "Samsung", weight: 2.2, countries: ["US", "KR", "DE"] },
  { device_hash: "dev-cfe5ea", vendor: "Raspberry Pi Foundation", weight: 0.3, countries: ["US", "GB", "??"] },
  { device_hash: "dev-577369", vendor: "Private MAC", weight: 0.8, countries: ["US", "CA"] },
  { device_hash: "dev-2fd239", vendor: "Private MAC", weight: 0.5, countries: ["US", "FR"] },
  { device_hash: "dev-2f7eb3", vendor: "Google", weight: 0.4, countries: ["US"] },
];

export const SEED_DEVICE_COUNT = SEED_DEVICES.length;

/** 32-bit integer hash (lowbias32 over a combined key). */
function hash32(a: number, b: number): number {
  let x = (Math.imul(a | 0, 0x9e3779b1) ^ Math.imul(b | 0, 0x85ebca77)) >>> 0;
  x ^= x >>> 16;
  x = Math.imul(x, 0x7feb352d) >>> 0;
  x ^= x >>> 15;
  x = Math.imul(x, 0x846ca68b) >>> 0;
  x ^= x >>> 16;
  return x >>> 0;
}

/** Deterministic uniform [0,1) for (minute, stream). */
function rand(minute: number, stream: number): number {
  return hash32(minute, stream) / 4294967296;
}

/** Diurnal multiplier in [0.15, 1.0], low at ~04:00 and peak at ~20:00 Pacific (UTC-7). */
export function diurnal(ts: number): number {
  const hour = (((ts / 3600 - 7) % 24) + 24) % 24;
  const phase = ((hour - 20) / 24) * 2 * Math.PI;
  return 0.15 + 0.85 * ((Math.cos(phase) + 1) / 2) ** 1.5;
}

const ALERT_TYPES = ["flood", "port_scan", "new_device", "geo_anomaly", "ml_anomaly", "suricata"];
const SURICATA = [
  { signature: "ET POLICY Possible Kali Linux hostname in DHCP Request Packet", sid: 2022973, category: "Potential Corporate Privacy Violation" },
  { signature: "ET SCAN Possible Nmap User-Agent Observed", sid: 2024364, category: "Web Application Attack" },
  { signature: "ET INFO Observed DNS Query to .onion TLD", sid: 2014939, category: "Potentially Bad Traffic" },
];
const GEO = ["RU", "CN", "KP", "IR", "BR"];
const SEVERITIES = ["low", "medium", "high", "critical"];

function hex(n: number, len: number): string {
  return (n >>> 0).toString(16).padStart(8, "0").slice(-len);
}

function uuidFor(minute: number): string {
  const a = hash32(minute, 101);
  const b = hash32(minute, 102);
  const c = hash32(minute, 103);
  const d = hash32(minute, 104);
  return `${hex(a, 8)}-${hex(b, 4)}-4${hex(b >>> 16, 3)}-${hex((c & 0x3fff) | 0x8000, 4)}-${hex(c >>> 16, 4)}${hex(d, 8)}`;
}

/** Windows for all 8 seed devices for one minute bucket, plus maybe one alert. */
export function generateMinute(ts: number): { windows: SeedWindow[]; alerts: SeedAlert[] } {
  const minuteTs = Math.floor(ts / 60) * 60;
  const m = minuteTs / 60;
  const day = diurnal(minuteTs);
  const windows: SeedWindow[] = [];
  let spikeDevice = -1;

  SEED_DEVICES.forEach((dev, i) => {
    const s = i * 16;
    const jitter = 0.6 + 0.8 * rand(m, s + 1);
    const burst = rand(m, s + 2) < 0.03 ? 4 + 6 * rand(m, s + 3) : 1;
    const base = 180_000 * dev.weight * day * jitter * burst;
    const bytes_in = Math.round(base);
    const bytes_out = Math.round(base * (0.08 + 0.2 * rand(m, s + 4)));
    const pkts = Math.max(1, Math.round((bytes_in + bytes_out) / (700 + 500 * rand(m, s + 5))));
    const spike = rand(m, s + 6) < 0.0015;
    if (spike) spikeDevice = i;
    const score = spike
      ? 0.81 + 0.18 * rand(m, s + 7)
      : 0.1 + 0.4 * rand(m, s + 7) ** 1.3;
    const countries: Record<string, number> = {};
    const total = bytes_in + bytes_out;
    let left = total;
    dev.countries.forEach((cc, k) => {
      const share = k === dev.countries.length - 1 ? left : Math.round(left * (k === 0 ? 0.75 + 0.2 * rand(m, s + 8) : 0.6));
      if (share > 0) countries[cc] = share;
      left -= share;
    });
    windows.push({
      device_hash: dev.device_hash,
      ts: minuteTs,
      duration_s: 60,
      bytes_in,
      bytes_out,
      pkts,
      distinct_dests: 1 + Math.floor(12 * day * rand(m, s + 9)) + (burst > 1 ? 6 : 0),
      distinct_ports: 1 + Math.floor(5 * rand(m, s + 10)),
      syn_ratio: Math.round((0.01 + 0.06 * rand(m, s + 11)) * 1000) / 1000,
      score: Math.round(score * 1000) / 1000,
      countries,
    });
  });

  const alerts: SeedAlert[] = [];
  // About one alert per ~45 min, plus one for every score spike.
  if (spikeDevice >= 0 || rand(m, 900) < 1 / 45) {
    const devIdx = spikeDevice >= 0 ? spikeDevice : Math.floor(rand(m, 901) * SEED_DEVICES.length);
    const type = spikeDevice >= 0 ? "ml_anomaly" : ALERT_TYPES[Math.floor(rand(m, 902) * ALERT_TYPES.length)]!;
    const severity = type === "ml_anomaly" ? "high" : SEVERITIES[Math.floor(rand(m, 903) * SEVERITIES.length)]!;
    let detail: Record<string, string | number>;
    switch (type) {
      case "flood":
        detail = { syn_per_s: 400 + Math.floor(rand(m, 904) * 2000), window_s: 10 };
        break;
      case "port_scan":
        detail = { distinct_ports: 40 + Math.floor(rand(m, 904) * 200), window_s: 10 };
        break;
      case "new_device":
        detail = { vendor: SEED_DEVICES[devIdx]!.vendor };
        break;
      case "geo_anomaly":
        detail = { country: GEO[Math.floor(rand(m, 904) * GEO.length)]! };
        break;
      case "ml_anomaly":
        detail = { score: windows[devIdx]!.score, model: "iforest-v1" };
        break;
      default: {
        const sig = SURICATA[Math.floor(rand(m, 904) * SURICATA.length)]!;
        detail = { signature: sig.signature, sid: sig.sid, category: sig.category };
      }
    }
    alerts.push({
      id: uuidFor(m),
      type,
      device_hash: SEED_DEVICES[devIdx]!.device_hash,
      ts: minuteTs + Math.floor(rand(m, 905) * 60),
      severity,
      detail,
    });
  }
  return { windows, alerts };
}

/** All minute buckets in [fromTs, toTs], both floored to the minute. */
export function minutesBetween(fromTs: number, toTs: number): number[] {
  const out: number[] = [];
  for (let t = Math.floor(fromTs / 60) * 60; t <= toTs; t += 60) out.push(t);
  return out;
}
