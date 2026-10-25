import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts";
import type { FlowsResponse } from "../lib/types";
import type { PollState } from "../lib/poll";
import { formatBytes, formatBytesTick, formatClock, formatDateTime } from "../lib/format";
import { Panel, Skeleton, Empty } from "./Panel";

export const RANGES = [
  { label: "1h", minutes: 60 },
  { label: "6h", minutes: 360 },
  { label: "24h", minutes: 1440 },
] as const;
export type RangeMinutes = (typeof RANGES)[number]["minutes"];

const IN = "var(--color-series-in)";
const OUT = "var(--color-series-out)";

interface Row { ts: number; bytes_in: number | null; bytes_out: number | null }

function fillGaps(points: FlowsResponse["points"]): Row[] {
  if (!points.length) return [];
  const sorted = [...points].sort((a, b) => a.ts - b.ts);
  const byTs = new Map(sorted.map((p) => [p.ts, p]));
  const rows: Row[] = [];
  const first = sorted[0].ts, last = sorted[sorted.length - 1].ts;
  // Guard against a malformed series producing a huge loop.
  if ((last - first) / 60 > 2000) return sorted.map((p) => ({ ts: p.ts, bytes_in: p.bytes_in, bytes_out: p.bytes_out }));
  for (let t = first; t <= last; t += 60) {
    const p = byTs.get(t);
    rows.push({ ts: t, bytes_in: p ? p.bytes_in : null, bytes_out: p ? p.bytes_out : null });
  }
  return rows;
}

function ChartTooltip({ active, payload }: TooltipContentProps) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as Row;
  return (
    <div className="rounded-lg border border-line-strong bg-raised/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      <div className="mb-1 font-mono text-ink-3">{formatDateTime(row.ts)}</div>
      <TipLine color={IN} label="In" value={row.bytes_in} />
      <TipLine color={OUT} label="Out" value={row.bytes_out} />
    </div>
  );
}

function TipLine({ color, label, value }: { color: string; label: string; value: number | null }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-0.5 w-3 rounded-full" style={{ background: color }} aria-hidden="true" />
      <span className="w-8 text-ink-2">{label}</span>
      <span className="ml-auto font-mono text-ink tnum">{value == null ? "no data" : formatBytes(value)}</span>
    </div>
  );
}

function Stat({ label, value, swatch }: { label: string; value: string; swatch?: string }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-[0.08em] text-ink-3">
        {swatch && <span className="h-0.5 w-3 rounded-full" style={{ background: swatch }} aria-hidden="true" />}
        {label}
      </div>
      <div className="mt-0.5 font-mono text-lg text-ink tnum">{value}</div>
    </div>
  );
}

interface Props {
  poll: PollState<FlowsResponse>;
  minutes: RangeMinutes;
  onMinutes: (m: RangeMinutes) => void;
}

export function TrafficChart({ poll, minutes, onMinutes }: Props) {
  const rows = useMemo(() => fillGaps(poll.data?.points ?? []), [poll.data]);
  const totals = useMemo(() => {
    let tin = 0, tout = 0, peak = 0, peakTs = 0;
    for (const r of rows) {
      tin += r.bytes_in ?? 0;
      tout += r.bytes_out ?? 0;
      const t = (r.bytes_in ?? 0) + (r.bytes_out ?? 0);
      if (t > peak) { peak = t; peakTs = r.ts; }
    }
    return { tin, tout, peak, peakTs };
  }, [rows]);

  const label = RANGES.find((r) => r.minutes === minutes)?.label ?? `${minutes}m`;
  const summary = rows.length
    ? `Network traffic over the last ${label}: ${formatBytes(totals.tin)} in, ${formatBytes(totals.tout)} out. Peak minute ${formatBytes(totals.peak)} at ${formatClock(totals.peakTs)}.`
    : "No traffic data yet.";

  const actions = (
    <div role="group" aria-label="Time range" className="inline-flex rounded-lg border border-line bg-bg/60 p-0.5">
      {RANGES.map((r) => (
        <button
          key={r.minutes}
          type="button"
          aria-pressed={minutes === r.minutes}
          onClick={() => onMinutes(r.minutes)}
          className={`rounded-md px-2.5 py-1 font-mono text-xs transition-colors ${
            minutes === r.minutes ? "bg-raised text-ink shadow-[0_0_0_1px_var(--color-line-strong)]" : "text-ink-3 hover:text-ink-2"
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );

  const first = poll.data == null;

  return (
    <Panel id="traffic" title="Live traffic" subtitle="Bytes per minute across all devices" poll={poll} actions={actions} delay={60}>
      <div className="mb-4 grid grid-cols-3 gap-3">
        {first ? (
          <>
            <Skeleton className="h-10" /><Skeleton className="h-10" /><Skeleton className="h-10" />
          </>
        ) : (
          <>
            <Stat label={`In · ${label}`} value={formatBytes(totals.tin)} swatch={IN} />
            <Stat label={`Out · ${label}`} value={formatBytes(totals.tout)} swatch={OUT} />
            <Stat label="Peak / min" value={formatBytes(totals.peak)} />
          </>
        )}
      </div>

      {first ? (
        <Skeleton className="h-[240px]" />
      ) : rows.length === 0 ? (
        <Empty>No flow windows in this range yet.</Empty>
      ) : (
        <figure className={`m-0 transition-opacity ${poll.pending ? "opacity-50" : ""}`} aria-busy={poll.pending}>
          <figcaption className="sr-only">{summary}</figcaption>
          <AreaChart
            responsive
            style={{ width: "100%", height: 240 }}
            data={rows}
            margin={{ top: 6, right: 6, bottom: 0, left: 0 }}
            title={summary}
          >
            <defs>
              <linearGradient id="fill-in" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3987e5" stopOpacity={0.22} />
                <stop offset="100%" stopColor="#3987e5" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="fill-out" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#d95926" stopOpacity={0.18} />
                <stop offset="100%" stopColor="#d95926" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1e232a" vertical={false} />
            <XAxis
              dataKey="ts"
              type="number"
              scale="time"
              domain={["dataMin", "dataMax"]}
              tickFormatter={(t: number) => formatClock(t)}
              tick={{ fill: "#8a919c", fontSize: 11, fontFamily: "IBM Plex Mono" }}
              tickLine={false}
              axisLine={{ stroke: "#2f3540" }}
              minTickGap={48}
            />
            <YAxis
              tickFormatter={formatBytesTick}
              tick={{ fill: "#8a919c", fontSize: 11, fontFamily: "IBM Plex Mono" }}
              tickLine={false}
              axisLine={false}
              width={52}
            />
            <Tooltip
              content={ChartTooltip}
              cursor={{ stroke: "#5b6370", strokeWidth: 1 }}
              isAnimationActive={false}
            />
            <Area
              type="monotoneX"
              dataKey="bytes_in"
              name="In"
              stroke={IN}
              strokeWidth={2}
              fill="url(#fill-in)"
              connectNulls={false}
              isAnimationActive={false}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 2, stroke: "#12151a", fill: "#3987e5" }}
            />
            <Area
              type="monotoneX"
              dataKey="bytes_out"
              name="Out"
              stroke={OUT}
              strokeWidth={2}
              fill="url(#fill-out)"
              connectNulls={false}
              isAnimationActive={false}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 2, stroke: "#12151a", fill: "#d95926" }}
            />
          </AreaChart>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2" aria-hidden="true">
            <span className="inline-flex items-center gap-1.5"><span className="h-0.5 w-4 rounded-full" style={{ background: IN }} />In (download)</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-0.5 w-4 rounded-full" style={{ background: OUT }} />Out (upload)</span>
          </div>
        </figure>
      )}
    </Panel>
  );
}
