import type { AlertsResponse } from "../lib/types";
import { useNow, type PollState } from "../lib/poll";
import { ALERT_LABEL, formatAgo, formatDateTime, summarizeDetail } from "../lib/format";
import { Panel, Skeleton, Empty } from "./Panel";

const SEV: Record<string, { color: string; label: string; rank: number }> = {
  low: { color: "var(--color-sev-low)", label: "Low", rank: 0 },
  medium: { color: "var(--color-sev-medium)", label: "Medium", rank: 1 },
  high: { color: "var(--color-sev-high)", label: "High", rank: 2 },
  critical: { color: "var(--color-sev-critical)", label: "Critical", rank: 3 },
};

/** Severity = color + label + bar count, so it never relies on color alone. */
export function SeverityTag({ severity }: { severity: string }) {
  const s = SEV[severity] ?? SEV.low;
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-bg/50 px-1.5 py-0.5 text-[11px] font-medium text-ink-2">
      <span aria-hidden="true" className="flex items-end gap-[2px]">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className="w-[3px] rounded-[1px]"
            style={{ height: 4 + i * 2, background: i <= s.rank ? s.color : "var(--color-line-strong)" }}
          />
        ))}
      </span>
      {s.label}
    </span>
  );
}

export function AlertFeed({ poll }: { poll: PollState<AlertsResponse> }) {
  const now = useNow();
  const alerts = poll.data?.alerts ?? [];

  return (
    <Panel id="alerts" title="Alert feed" subtitle="Rules, Suricata IDS and ML detections, newest first" poll={poll} delay={120} className="lg:h-full">
      {poll.data == null ? (
        <ul className="space-y-3" aria-hidden="true">
          {Array.from({ length: 5 }, (_, i) => <li key={i}><Skeleton className="h-12" /></li>)}
        </ul>
      ) : alerts.length === 0 ? (
        <Empty>No alerts. Quiet network.</Empty>
      ) : (
        <ol className="-mx-4 -my-4 max-h-[420px] overflow-y-auto overscroll-contain lg:absolute lg:inset-0 lg:m-0 lg:max-h-none" aria-label="Recent alerts">
          {alerts.map((a) => {
            const sev = SEV[a.severity] ?? SEV.low;
            const detail = summarizeDetail(a.type, a.detail);
            return (
              <li key={a.id} className="relative border-b border-line/70 px-4 py-2.5 last:border-b-0">
                <span aria-hidden="true" className="absolute inset-y-2 left-0 w-[2px] rounded-full" style={{ background: sev.color }} />
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <SeverityTag severity={a.severity} />
                  <span className="text-sm font-medium text-ink">{ALERT_LABEL[a.type] ?? a.type}</span>
                  <span className="font-mono text-xs text-ink-3">{a.device_hash}</span>
                  <time
                    dateTime={new Date(a.ts * 1000).toISOString()}
                    title={formatDateTime(a.ts)}
                    className="ml-auto font-mono text-[11px] text-ink-3 tnum"
                  >
                    {formatAgo(a.ts, now)}
                  </time>
                </div>
                {detail && <p className="mt-1 break-words text-xs leading-relaxed text-ink-2">{detail}</p>}
              </li>
            );
          })}
        </ol>
      )}
    </Panel>
  );
}
