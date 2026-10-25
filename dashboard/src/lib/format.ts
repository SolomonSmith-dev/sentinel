const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

/** 1536 -> "1.5 KB". Decimal (1000) units, as network tools report. */
export function formatBytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n)) return "–";
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1000 && i < UNITS.length - 1) { v /= 1000; i++; }
  const d = i === 0 || v >= 100 ? 0 : digits;
  return `${n < 0 ? "-" : ""}${v.toFixed(d)} ${UNITS[i]}`;
}

/** Compact axis tick: "2.4M" style, bytes implied by the axis title. */
export function formatBytesTick(n: number): string {
  if (n === 0) return "0";
  return formatBytes(n, 0).replace(" ", "");
}

export function formatCount(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "–";
  return new Intl.NumberFormat("en-US", { notation: n >= 10_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(n);
}

/** Seconds-ago -> "just now", "42s ago", "5m ago", "3h ago", "2d ago". */
export function formatAgo(tsSec: number, nowMs = Date.now()): string {
  const s = Math.max(0, Math.round(nowMs / 1000 - tsSec));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

export const formatClock = (tsSec: number) => timeFmt.format(tsSec * 1000);
export const formatDateTime = (tsSec: number) => dateTimeFmt.format(tsSec * 1000);

let regionNames: Intl.DisplayNames | null = null;
try { regionNames = new Intl.DisplayNames(["en"], { type: "region" }); } catch { regionNames = null; }

export function countryName(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return "Unknown";
  try { return regionNames?.of(code) ?? code; } catch { return code; }
}

export const ALERT_LABEL: Record<string, string> = {
  flood: "Flood",
  port_scan: "Port scan",
  new_device: "New device",
  geo_anomaly: "Geo anomaly",
  ml_anomaly: "ML anomaly",
  suricata: "Suricata IDS",
};

/** One-line human summary of an alert's detail object. */
export function summarizeDetail(type: string, d: Record<string, unknown> | null): string {
  if (!d || typeof d !== "object") return "";
  const num = (k: string) => (typeof d[k] === "number" ? (d[k] as number) : undefined);
  const str = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : undefined);
  switch (type) {
    case "port_scan": {
      const p = num("distinct_ports"), w = num("window_s");
      if (p != null) return `${p} distinct ports${w != null ? ` in ${w}s` : ""}`;
      break;
    }
    case "flood": {
      const pps = num("pps"), w = num("window_s"), syn = num("syn_ratio");
      const parts = [pps != null ? `${formatCount(pps)} pkt/s` : "", w != null ? `over ${w}s` : "", syn != null ? `SYN ${Math.round(syn * 100)}%` : ""].filter(Boolean);
      if (parts.length) return parts.join(" · ");
      break;
    }
    case "geo_anomaly": {
      const c = str("country");
      if (c) return `Unusual outbound to ${countryName(c)} (${c})`;
      break;
    }
    case "ml_anomaly": {
      const s = num("score");
      if (s != null) return `Anomaly score ${s.toFixed(2)}${num("threshold") != null ? ` (threshold ${num("threshold")})` : ""}`;
      break;
    }
    case "suricata": {
      const sig = str("signature"), cat = str("category"), sid = num("sid");
      if (sig) return `${sig}${sid != null ? ` · sid ${sid}` : ""}${cat ? ` · ${cat}` : ""}`;
      break;
    }
    case "new_device": {
      const v = str("vendor");
      return v ? `First seen on LAN · vendor ${v}` : "First seen on LAN";
    }
  }
  return Object.entries(d)
    .filter(([, v]) => v == null || typeof v !== "object")
    .slice(0, 4)
    .map(([k, v]) => `${k.replace(/_/g, " ")} ${String(v)}`)
    .join(" · ");
}
