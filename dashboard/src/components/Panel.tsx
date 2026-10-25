import type { ReactNode } from "react";
import { STALE_MS, useNow, type PollState } from "../lib/poll";

function ago(ms: number) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ago` : `${Math.floor(m / 60)}h ago`;
}

/** "updated 4s ago" / "stale · 2m ago" / "error" chip shown in every panel header. */
export function Freshness({ poll }: { poll: PollState<unknown> }) {
  const now = useNow();
  const age = poll.updatedAt != null ? now - poll.updatedAt : undefined;
  const stale = !!poll.error || (age != null && age > STALE_MS);

  if (poll.updatedAt == null && !poll.error) {
    return <span className="font-mono text-[11px] text-ink-3">loading…</span>;
  }
  if (!stale) {
    return (
      <span className="font-mono text-[11px] text-ink-3 tnum" aria-live="off">
        updated {ago(age ?? 0)}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-sev-medium/40 bg-sev-medium/10 px-2 py-0.5 font-mono text-[11px] text-ink-2"
      title={poll.error}
      role="status"
    >
      <svg aria-hidden="true" viewBox="0 0 12 12" className="h-3 w-3 fill-sev-medium"><path d="M6 0.8 11.4 10.6H0.6z" /><rect x="5.4" y="4.2" width="1.2" height="3.4" fill="#12151a" /><rect x="5.4" y="8.4" width="1.2" height="1.2" fill="#12151a" /></svg>
      {poll.data == null ? "unavailable" : "stale"}
      {age != null && <span className="text-ink-3">· {ago(age)}</span>}
    </span>
  );
}

interface PanelProps {
  id: string;
  title: string;
  subtitle?: ReactNode;
  poll: PollState<unknown>;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
  delay?: number;
}

export function Panel({ id, title, subtitle, poll, actions, className = "", children, delay = 0 }: PanelProps) {
  return (
    <section
      aria-labelledby={`${id}-title`}
      className={`rise flex min-w-0 flex-col rounded-xl border border-line bg-panel/90 shadow-[0_1px_0_0_rgb(255_255_255/0.03)_inset] backdrop-blur-sm ${className}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <header className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <h2 id={`${id}-title`} className="font-display text-[15px] font-medium tracking-tight text-ink">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-ink-3">{subtitle}</p>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {actions}
          <Freshness poll={poll} />
        </div>
      </header>
      <div className="relative min-h-0 flex-1 p-4">
        {poll.data == null && poll.error ? <ErrorState message={poll.error} /> : children}
      </div>
    </section>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div role="alert" className="flex h-full min-h-32 flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-line-strong px-4 py-8 text-center">
      <p className="text-sm text-ink-2">Could not reach the API.</p>
      <p className="font-mono text-xs text-ink-3">{message} · retrying every 10 s</p>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-32 items-center justify-center rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm text-ink-3">
      {children}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`skeleton ${className}`} />;
}
