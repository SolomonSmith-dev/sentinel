// Shapes from docs/api.md (read endpoints). is_seed arrives as boolean on /api/flows
// and as 0|1 on row-level fields; treat both as truthy flags.
export type SeedFlag = boolean | 0 | 1;

export type AlertType = "flood" | "port_scan" | "new_device" | "geo_anomaly" | "ml_anomaly" | "suricata";
export type Severity = "low" | "medium" | "high" | "critical";

export interface FlowPoint { ts: number; bytes_in: number; bytes_out: number; pkts: number }
export interface FlowsResponse { minutes: number; points: FlowPoint[]; is_seed: SeedFlag }

export interface Alert {
  id: string;
  type: AlertType | string;
  device_hash: string;
  ts: number;
  severity: Severity | string;
  detail: Record<string, unknown> | null;
  is_seed: SeedFlag;
}
export interface AlertsResponse { alerts: Alert[] }

export interface Device {
  device_hash: string;
  vendor: string;
  first_seen: number;
  last_seen: number;
  last_score: number | null;
  alerts_24h: number;
  bytes_24h: number;
  is_seed: SeedFlag;
}
export interface DevicesResponse { devices: Device[] }

export interface TopDevice { device_hash: string; vendor: string; bytes: number; is_seed: SeedFlag }
export interface TopCountry { country: string; bytes: number }
export interface TopResponse { minutes: number; devices: TopDevice[]; countries: TopCountry[] }

export interface MetricsResponse {
  ingest: { count_24h: number; failed_24h: Record<string, number>; p50_ms: number | null; p95_ms: number | null };
  sensor: { sensor_id: string; last_seen: number; queue_depth: number } | null;
  rows: Record<string, number>;
  seed_active: boolean;
}

export const isSeed = (f: SeedFlag | undefined) => f === true || f === 1;
