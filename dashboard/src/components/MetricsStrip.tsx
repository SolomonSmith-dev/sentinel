import type { ReactNode } from "react";
import type { MetricsResponse } from "../lib/types";
import { useNow, type PollState } from "../lib/poll";
import { formatAgo, formatCount, formatDateTime } from "../lib/format";
import { Freshness, Skeleton } from "./Panel";

function Cell({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="min-w-0 px-4 py-3" title={hint}>
      <dt className="text-[11px] uppercase tracking-[0.08em] text-ink-3">{label}</dt>
      <dd className="mt-1 font-mono text-sm text-ink tnum">{children}</dd>
    </div>
  );
}

export function MetricsStrip({ poll }: { poll: PollState<MetricsResponse> }) {
  const now = useNow();
  const m = poll.data;
  const failed = m ? Object.entries(m.ingest.failed_24h ?? {}) : [];
  const failedTotal = failed.reduce((a, [, n]) => a + n, 0);
  const sensorAge = m?.sensor ? now / 1000 - m.sensor.last_seen : undefined;

  return (
    <section aria-labelledby="metrics-title" className="rise rounded-xl border border-line bg-panel/80" style={{ animationDelay: "300ms" }}>
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
        <h2 id="metrics-title" className="font-display text-[13px] font-medium text-ink-2">Pipeline health</h2>
        <Freshness poll={poll} />
      </header>
      {m == null && poll.error ? null : m == null ? (
        <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-3 lg:grid-cols-6" aria-hidden="true">
          {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-10" />)}
        </div>
      ) : (
        <dl className="grid grid-cols-2 divide-line sm:grid-cols-3 lg:grid-cols-[repeat(5,minmax(0,1fr))_minmax(0,1.6fr)] [&>div]:border-line [&>div]:border-b lg:[&>div]:border-b-0 lg:[&>div:not(:last-child)]:border-r">
          <Cell label="Ingests 24h">{formatCount(m.ingest.count_24h)}</Cell>
          <Cell label="Failed 24h" hint="Rejected ingest attempts by HTTP status">
            <span className={failedTotal ? "text-ink" : "text-ink-3"}>{failedTotal}</span>
            {failed.length > 0 && (
              <span className="ml-2 text-[11px] text-ink-3">
                {failed.map(([code, n]) => `${code}:${n}`).join(" ")}
              </span>
            )}
          </Cell>
          <Cell label="Ingest p50 / p95">
            {m.ingest.p50_ms ?? "–"}<span className="text-ink-3"> / </span>{m.ingest.p95_ms ?? "–"}<span className="text-ink-3"> ms</span>
          </Cell>
          <Cell label="Sensor queue">{m.sensor ? formatCount(m.sensor.queue_depth) : <span className="text-ink-3">–</span>}</Cell>
          <Cell label="Sensor last seen" hint={m.sensor ? `${m.sensor.sensor_id} · ${formatDateTime(m.sensor.last_seen)}` : "No real sensor has posted yet"}>
            {m.sensor ? (
              <span className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${sensorAge != null && sensorAge < 180 ? "bg-good" : "bg-sev-medium"}`}
                />
                {formatAgo(m.sensor.last_seen, now)}
                <span className="sr-only">{sensorAge != null && sensorAge < 180 ? "(reporting)" : "(late)"}</span>
              </span>
            ) : (
              <span className="text-ink-3">not reporting yet</span>
            )}
          </Cell>
          <Cell label="D1 rows" hint={Object.entries(m.rows ?? {}).map(([k, v]) => `${k}: ${v}`).join(", ")}>
            <span className="text-[12px]">
              {Object.entries(m.rows ?? {}).map(([k, v], i) => (
                <span key={k}>{i > 0 && <span className="text-ink-3"> · </span>}{formatCount(v)}<span className="text-ink-3"> {k}</span></span>
              ))}
            </span>
          </Cell>
        </dl>
      )}
      {poll.data == null && poll.error && (
        <p role="alert" className="px-4 pb-3 font-mono text-xs text-ink-3">Metrics unavailable: {poll.error}</p>
      )}
    </section>
  );
}
