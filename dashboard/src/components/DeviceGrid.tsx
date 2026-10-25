import type { DevicesResponse } from "../lib/types";
import { useNow, type PollState } from "../lib/poll";
import { formatAgo, formatBytes, formatDateTime } from "../lib/format";
import { Panel, Skeleton, Empty } from "./Panel";

export const ALERT_THRESHOLD = 0.8;

function band(score: number) {
  if (score >= ALERT_THRESHOLD) return { color: "var(--color-sev-critical)", word: "above threshold" };
  if (score >= 0.5) return { color: "var(--color-sev-medium)", word: "elevated" };
  return { color: "var(--color-series-in)", word: "normal" };
}

/** 0 to 1 anomaly meter with the 0.8 alert threshold marked. */
export function ScoreMeter({ score, device }: { score: number | null; device: string }) {
  if (score == null) {
    return (
      <div className="flex items-center gap-2" aria-label={`${device} anomaly score: no model loaded`} role="img">
        <div className="relative h-1.5 flex-1 rounded-full border border-dashed border-line-strong" />
        <span className="font-mono text-xs text-ink-3">no model</span>
      </div>
    );
  }
  const v = Math.min(1, Math.max(0, score));
  const b = band(v);
  return (
    <div className="flex items-center gap-2">
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={Number(v.toFixed(2))}
        aria-valuetext={`${v.toFixed(2)}, ${b.word} (alert threshold ${ALERT_THRESHOLD})`}
        aria-label={`${device} anomaly score`}
        className="relative h-1.5 flex-1 rounded-full bg-line"
      >
        <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${v * 100}%`, background: b.color }} />
        <div
          aria-hidden="true"
          className="absolute -top-1 -bottom-1 w-[2px] rounded-full bg-ink-2 shadow-[0_0_0_2px_var(--color-panel)]"
          style={{ left: `calc(${ALERT_THRESHOLD * 100}% - 1px)` }}
          title={`Alert threshold ${ALERT_THRESHOLD}`}
        />
      </div>
      <span className="w-9 text-right font-mono text-sm text-ink tnum">{v.toFixed(2)}</span>
    </div>
  );
}

export function DeviceGrid({ poll }: { poll: PollState<DevicesResponse> }) {
  const now = useNow();
  const devices = poll.data?.devices ?? [];

  const subtitle = (
    <>
      Seen in the last 7 days, highest anomaly score first. Marker
      <span aria-hidden="true" className="mx-1 inline-block h-2.5 w-[2px] translate-y-[1px] rounded-full bg-ink-2" />
      = alert threshold {ALERT_THRESHOLD}.
    </>
  );

  return (
    <Panel id="devices" title="Devices" subtitle={subtitle} poll={poll} delay={180}>
      {poll.data == null ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-hidden="true">
          {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[118px]" />)}
        </div>
      ) : devices.length === 0 ? (
        <Empty>No devices reported yet.</Empty>
      ) : (
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label="Devices">
          {devices.map((d) => {
            const hot = d.last_score != null && d.last_score >= ALERT_THRESHOLD;
            return (
              <li
                key={d.device_hash}
                className={`min-w-0 rounded-lg border bg-raised/60 p-3 ${hot ? "border-sev-critical/45" : "border-line"}`}
              >
                <div className="flex items-baseline justify-between gap-2">
                  <span className="font-mono text-sm text-ink">{d.device_hash}</span>
                  <span className="truncate text-xs text-ink-3" title={d.vendor}>{d.vendor}</span>
                </div>
                <div className="mt-1 text-[11px] uppercase tracking-[0.08em] text-ink-3">Anomaly score</div>
                <div className="mt-1.5"><ScoreMeter score={d.last_score} device={d.device_hash} /></div>
                <dl className="mt-3 grid grid-cols-3 gap-2 text-xs">
                  <div className="min-w-0">
                    <dt className="text-ink-3">Alerts 24h</dt>
                    <dd className={`font-mono tnum ${d.alerts_24h > 0 ? "text-ink" : "text-ink-3"}`}>{d.alerts_24h}</dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="text-ink-3">Bytes 24h</dt>
                    <dd className="font-mono text-ink-2 tnum">{formatBytes(d.bytes_24h)}</dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="text-ink-3">Last seen</dt>
                    <dd className="font-mono text-ink-2 tnum" title={formatDateTime(d.last_seen)}>{formatAgo(d.last_seen, now)}</dd>
                  </div>
                </dl>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
